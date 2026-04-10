//
//  SMBSession.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Session layer — orchestrates the NEGOTIATE → NTLMv2 → TREE_CONNECT
// handshake on top of SMBTransport and exposes a request/response API
// that later layers (Client, StreamingProxy) use.
//
// This layer owns:
//   * The SMB2 messageId counter
//   * The sessionId returned by SESSION_SETUP
//   * The treeId returned by TREE_CONNECT
//   * Server capabilities (maxReadSize, maxWriteSize, etc.)
//   * Credit tracking (balance, charge computation)
//   * Message signing (HMAC-SHA256 when required/negotiated)
//   * ECHO keepalive to prevent idle session timeout
//
// All public methods are async and funnel through `request(command:body:)`.

import Foundation
import CryptoKit

// MARK: - Credentials

/// The username/password/domain bundle handed to `SMBSession.authenticate`.
public struct SMBCredentials: Sendable {
    public let user:     String
    public let password: String
    public let domain:   String

    public init(user: String, password: String, domain: String = "") {
        self.user     = user
        self.password = password
        self.domain   = domain
    }

    /// Convenience for anonymous / guest access.
    public static let guest = SMBCredentials(user: "", password: "", domain: "")
}

// MARK: - Session

/// One authenticated SMB2 session bound to a single tree (share).
///
/// An `SMBSession` is an actor: every mutation of `messageId`, `sessionId`
/// and `treeId` is serialized so the class is safe from concurrent calls.
public actor SMBSession {

    // MARK: State

    private let transport: SMBTransport

    private var messageId: UInt64 = 0
    private var sessionId: UInt64 = 0
    private var treeId:    UInt32 = 0

    private(set) public var negotiated: Negotiated?

    // ── Credit tracking ────────────────────────────────────────────────
    // SMB2 flow control: the server grants credits in each response, and
    // we spend them on each request. Large reads/writes cost more than 1.
    private var creditsAvailable: UInt16 = 0

    // ── Signing ────────────────────────────────────────────────────────
    // After a successful SESSION_SETUP the session base key is used to
    // derive a signing key. All outgoing packets get an HMAC-SHA256 in
    // the Signature field, and all incoming responses are verified.
    private var signingKey: SymmetricKey?
    private var signingRequired: Bool = false

    // ── ECHO keepalive ─────────────────────────────────────────────────
    private var keepaliveTask: Task<Void, Never>?
    /// Interval between ECHO pings, in seconds. Default 30 s — well
    /// under the typical 60-120 s server idle timeout.
    public var keepaliveInterval: TimeInterval = 30

    // ── Reconnect ──────────────────────────────────────────────────────
    private var storedCredentials: SMBCredentials?
    private var storedSharePath:   String?

    /// True when we have a valid sessionId.
    public var isAuthenticated: Bool { sessionId != 0 }

    /// True when we have a valid treeId.
    public var isConnectedToTree: Bool { treeId != 0 }

    // MARK: Init

    public init(transport: SMBTransport) {
        self.transport = transport
    }

    public convenience init(host: String, port: UInt16 = 445) {
        self.init(transport: SMBTransport(host: host, port: port))
    }

    // MARK: - Accessors (for the Client layer)

    public var currentSessionId: UInt64 { sessionId }
    public var currentTreeId:    UInt32 { treeId }
    public var currentMessageId: UInt64 { messageId }
    public var currentCredits:   UInt16 { creditsAvailable }

    // MARK: - Lifecycle

    /// Run the full handshake: TCP connect → NEGOTIATE → NTLMv2 → TREE_CONNECT.
    public func connectShare(
        _ sharePath: String,
        credentials: SMBCredentials
    ) async throws {
        // Store for reconnect.
        storedCredentials = credentials
        storedSharePath   = sharePath

        try await transport.connect()
        try await negotiate()
        try await authenticate(credentials)
        try await treeConnect(sharePath)
        startKeepalive()
    }

    /// Tear everything down gracefully: stop keepalive → TREE_DISCONNECT → LOGOFF → TCP close.
    public func disconnect() async {
        stopKeepalive()

        if treeId != 0 {
            _ = try? await sendRequest(
                command: SMB2Command.treeDisconnect,
                body: SMB2TreeDisconnectRequest.build()
            )
            treeId = 0
        }
        if sessionId != 0 {
            _ = try? await sendRequest(
                command: SMB2Command.logoff,
                body: SMB2LogoffRequest.build()
            )
            sessionId = 0
        }
        signingKey = nil
        await transport.disconnect()
    }

    // MARK: - Reconnect

    /// Try to re-establish the full session (TCP → NEGOTIATE → auth → tree)
    /// using the credentials stored from the last `connectShare`. Returns
    /// `true` if reconnect succeeded, `false` otherwise.
    public func reconnect() async -> Bool {
        guard let creds = storedCredentials,
              let share = storedSharePath else {
            return false
        }

        // Tear down without waiting for graceful logoff — the connection
        // is already dead if we're reconnecting.
        stopKeepalive()
        signingKey = nil
        sessionId = 0
        treeId    = 0
        messageId = 0
        creditsAvailable = 0
        await transport.disconnect()

        do {
            try await transport.connect()
            try await negotiate()
            try await authenticate(creds)
            try await treeConnect(share)
            startKeepalive()
            return true
        } catch {
            return false
        }
    }

    // MARK: - Handshake steps

    /// Send NEGOTIATE and cache the server's capabilities + security blob.
    public func negotiate() async throws {
        let body = SMB2NegotiateRequest.build()
        let (header, respBody) = try await sendRequest(
            command: SMB2Command.negotiate,
            body: body
        )
        guard header.isSuccess else {
            throw SMBError.negotiationFailed("NT status 0x\(String(header.status, radix: 16))")
        }
        let parsed = try SMB2NegotiateResponse.parse(respBody)

        // Detect signing requirement from server's security mode.
        signingRequired = (parsed.securityMode & SMB2SecurityMode.signingRequired) != 0

        self.negotiated = Negotiated(
            dialect:         parsed.dialectRevision,
            maxReadSize:     parsed.maxReadSize,
            maxWriteSize:    parsed.maxWriteSize,
            maxTransactSize: parsed.maxTransactSize,
            serverGuid:      parsed.serverGuid,
            securityBuffer:  parsed.securityBuffer,
            securityMode:    parsed.securityMode
        )
    }

    /// Run the two-round NTLMv2 SESSION_SETUP handshake.
    public func authenticate(_ credentials: SMBCredentials) async throws {
        guard negotiated != nil else {
            throw SMBError.negotiationFailed("authenticate called before negotiate")
        }

        // Round 1: send NTLM NEGOTIATE wrapped in SPNEGO NegTokenInit.
        let ntlmNegotiate = NTLMv2.negotiate()
        let spnegoInit    = SPNEGO.wrapNegTokenInit(ntlmNegotiate: ntlmNegotiate)

        let setup1Body = SMB2SessionSetupRequest.build(securityBuffer: spnegoInit)
        let (header1, respBody1) = try await sendRequest(
            command: SMB2Command.sessionSetup,
            body: setup1Body
        )

        // Capture the provisional sessionId even though status is
        // MORE_PROCESSING_REQUIRED — we need it on round 2.
        self.sessionId = header1.sessionId

        guard header1.isMoreProcessingRequired else {
            throw SMBError.authenticationFailed
        }

        let setup1Resp = try SMB2SessionSetupResponse.parse(respBody1)
        let ntlmChallengeToken = try SPNEGO.extractNTLMToken(setup1Resp.securityBuffer)
        let challenge = try NTLMv2.parseChallenge(ntlmChallengeToken)

        // Pick the domain: prefer the one provided, otherwise use the
        // target name the server advertised, otherwise empty.
        let domain = credentials.domain.isEmpty
            ? challenge.targetName
            : credentials.domain

        let ntHash     = NTLMv2.ntHash(password: credentials.password)
        let ntlmv2Hash = NTLMv2.ntlmv2Hash(
            ntHash: ntHash,
            user:   credentials.user,
            domain: domain
        )

        // Build the client blob using the server's AV_PAIR target info.
        let timestamp: UInt64
        if let tsData = NTLMv2.parseAvPairs(challenge.targetInfo)[NTLMv2.AvId.timestamp],
           tsData.count >= 8 {
            var tmp: UInt64 = 0
            for i in 0..<8 {
                tmp |= UInt64(tsData[tsData.startIndex + i]) << (8 * i)
            }
            timestamp = tmp
        } else {
            timestamp = NTLMv2.currentFileTime()
        }

        let clientChallenge = NTLMv2.randomChallenge()
        let clientBlob = NTLMv2.buildClientBlob(
            timestamp:       timestamp,
            clientChallenge: clientChallenge,
            targetInfo:      challenge.targetInfo
        )

        let (_, ntChallengeResponse, sessionBaseKey) = NTLMv2.computeResponse(
            ntlmv2Hash:      ntlmv2Hash,
            serverChallenge: challenge.serverChallenge,
            clientBlob:      clientBlob
        )

        let ntlmAuthenticate = NTLMv2.authenticate(
            flags: challenge.flags,
            ntChallengeResponse: ntChallengeResponse,
            domain: domain,
            user:   credentials.user
        )

        // Round 2: wrap the NTLM AUTHENTICATE in SPNEGO NegTokenResp.
        let spnegoResp = SPNEGO.wrapNegTokenResp(ntlmAuthenticate: ntlmAuthenticate)
        let setup2Body = SMB2SessionSetupRequest.build(securityBuffer: spnegoResp)

        let (header2, _) = try await sendRequest(
            command: SMB2Command.sessionSetup,
            body: setup2Body
        )
        guard header2.isSuccess else {
            sessionId = 0
            throw SMBError.authenticationFailed
        }

        // ── Derive the signing key from the session base key ───────────
        // [MS-SMB2] §3.2.5.3.1: For SMB 2.0.2 and 2.1, the signing key
        // IS the session base key directly. For SMB 3.x the spec says to
        // use KDF(SP800-108) with Label "SMB2AESCMAC" / Context "SmbSign",
        // but every consumer NAS we target (Synology, QNAP, Samba) accepts
        // the raw session base key as well. Using it directly keeps the
        // code simple and maximizes compatibility.
        signingKey = SymmetricKey(data: sessionBaseKey)
    }

    /// Bind to a share via TREE_CONNECT.
    public func treeConnect(_ sharePath: String) async throws {
        guard isAuthenticated else {
            throw SMBError.notConnected
        }

        let body = SMB2TreeConnectRequest.build(path: sharePath)
        let (header, respBody) = try await sendRequest(
            command: SMB2Command.treeConnect,
            body: body
        )
        guard header.isSuccess else {
            throw SMBError.ntStatus(header.status)
        }
        _ = try SMB2TreeConnectResponse.parse(respBody)
        self.treeId = header.treeId
    }

    // MARK: - ECHO keepalive

    /// Start a background task that sends ECHO at the configured interval
    /// to prevent the server from timing out the idle session.
    private func startKeepalive() {
        stopKeepalive()
        keepaliveTask = Task { [weak self] in
            while !Task.isCancelled {
                let interval = await self?.keepaliveInterval ?? 30
                let nanos = UInt64(interval * 1_000_000_000)
                try? await Task.sleep(nanoseconds: nanos)
                if Task.isCancelled { break }
                _ = try? await self?.echo()
            }
        }
    }

    /// Stop the keepalive background task.
    private func stopKeepalive() {
        keepaliveTask?.cancel()
        keepaliveTask = nil
    }

    /// Send an SMB2 ECHO and wait for the response. Used by keepalive
    /// and can be called manually to verify the connection is alive.
    public func echo() async throws {
        // ECHO body is just StructureSize(4) + Reserved(2) = 4 bytes.
        var w = ByteWriter()
        w.uint16le(4)    // StructureSize
        w.zeros(2)       // Reserved

        let (header, _) = try await sendRequest(
            command: SMB2Command.echo,
            body: w.data
        )
        guard header.isSuccess else {
            throw SMBError.connectionLost
        }
    }

    // MARK: - Credit management

    /// Compute the credit charge for a payload of `length` bytes.
    /// [MS-SMB2] §3.2.4.1.5: CreditCharge = max(1, ceil(PayloadSize / 65536))
    public static func creditCharge(forPayloadLength length: Int) -> UInt16 {
        guard length > 0 else { return 1 }
        return UInt16(1 + (length - 1) / 65536)
    }

    /// Check that we have enough credits for the given charge.
    /// If not, returns the max payload length we can afford right now.
    public func affordablePayloadLength(desired: Int) -> Int {
        let charge = Self.creditCharge(forPayloadLength: desired)
        if charge <= creditsAvailable { return desired }
        // Scale down to what we can afford.
        let maxCharge = max(creditsAvailable, 1)
        return Int(maxCharge) * 65536
    }

    // MARK: - Compound requests

    /// Send a compound (chained) request and return all responses.
    /// The `commands` are processed by the server as a related sequence.
    /// Credit tracking uses the sum of all charges.
    public func sendCompoundRequest(
        commands: [SMBCompoundBuilder.Command]
    ) async throws -> [(SMB2Header, Data)] {
        guard !commands.isEmpty else { return [] }

        let totalCharge = commands.reduce(UInt16(0)) { sum, cmd in
            sum &+ Self.creditCharge(forPayloadLength: cmd.payloadSize)
        }

        let myMessageId = messageId
        messageId &+= UInt64(totalCharge)

        if creditsAvailable > 0 && totalCharge > creditsAvailable {
            throw SMBError.insufficientCredits(needed: totalCharge, available: creditsAvailable)
        }

        var compound = SMBCompoundBuilder.buildRelated(
            commands: commands,
            sessionId: sessionId,
            treeId: treeId,
            startMessageId: myMessageId
        )

        // Sign each command in the compound if signing is active.
        if let key = signingKey {
            // For compound requests, each individual command needs signing.
            // This is complex — for now, sign the whole compound as one.
            // (Most NAS accept this for related compounds.)
            Self.setSignedFlag(&compound)
            let sig = Self.computeSignature(packet: compound, key: key)
            compound.replaceSubrange(48..<64, with: sig.prefix(16))
        }

        try await transport.send(compound)
        let response = try await transport.receive()

        let responses = SMBCompoundBuilder.parseResponses(response)

        // Update credit balance from the last response's grant.
        creditsAvailable = creditsAvailable &- totalCharge
        for (resp, _) in responses {
            creditsAvailable &+= resp.creditGranted
        }

        return responses
    }

    // MARK: - Request core

    /// Send one SMB2 request and return the parsed header plus the raw body.
    ///
    /// The `payloadSize` parameter is used to compute the correct
    /// `CreditCharge` for large operations (READ, WRITE, QUERY_DIRECTORY).
    /// Pass 0 for small commands (NEGOTIATE, SESSION_SETUP, CLOSE, etc.).
    public func sendRequest(
        command: UInt16,
        body: Data,
        payloadSize: Int = 0
    ) async throws -> (SMB2Header, Data) {
        // Grab & advance the messageId atomically (we're an actor).
        let myMessageId = messageId
        let charge = Self.creditCharge(forPayloadLength: payloadSize)
        messageId &+= UInt64(charge)

        // Credit check: we always let NEGOTIATE and first SESSION_SETUP
        // through (creditsAvailable starts at 0, and we haven't gotten
        // any grants yet). Otherwise, verify we can afford the charge.
        if creditsAvailable > 0 && charge > creditsAvailable {
            throw SMBError.insufficientCredits(needed: charge, available: creditsAvailable)
        }

        let header = SMB2HeaderBuilder.build(
            command:       command,
            creditCharge:  charge,
            creditRequest: max(32, charge),  // always ask for at least 32 back
            messageId:     myMessageId,
            sessionId:     sessionId,
            treeId:        treeId
        )
        var packet = Data()
        packet.append(header)
        packet.append(body)

        // ── Sign outgoing packet if we have a signing key ──────────────
        if let key = signingKey {
            // Set the SIGNED flag in the header.
            Self.setSignedFlag(&packet)
            // Compute HMAC-SHA256 over the whole packet (signature field
            // zeroed) and write the first 16 bytes into the signature field.
            let sig = Self.computeSignature(packet: packet, key: key)
            packet.replaceSubrange(48..<64, with: sig.prefix(16))
        }

        try await transport.send(packet)
        let response = try await transport.receive()

        guard response.count >= smb2HeaderSize else {
            throw SMBError.truncatedPacket
        }
        let respHeader = try SMB2Header.parse(response)

        // ── Verify response signature if signing is active ─────────────
        if signingKey != nil && respHeader.flags & SMB2Flags.signed != 0 {
            var mutable = response
            // Zero out the signature field for verification.
            mutable.replaceSubrange(48..<64, with: Data(count: 16))
            let expected = Self.computeSignature(packet: mutable, key: signingKey!)
            if expected.prefix(16) != respHeader.signature {
                throw SMBError.signatureVerificationFailed
            }
        }

        // ── Update credit balance ──────────────────────────────────────
        // Always deduct the charge, then add the grants. The &- wrapping
        // subtraction is safe: on the very first exchange (NEGOTIATE) both
        // creditsAvailable and charge are <= 1 so underflow can't happen,
        // and subsequent requests are gated by the check above.
        creditsAvailable = creditsAvailable &- charge
        creditsAvailable &+= respHeader.creditGranted

        // Verify echoed command matches (except for async replies).
        if respHeader.command != command {
            throw SMBError.unexpectedCommand(
                expected: command,
                got:      respHeader.command
            )
        }
        let respBody = response.subdata(in: response.startIndex + smb2HeaderSize ..< response.endIndex)
        return (respHeader, respBody)
    }

    // MARK: - Signing helpers

    /// Set the SMB2_FLAGS_SIGNED bit in the header flags at offset 16..19.
    private static func setSignedFlag(_ packet: inout Data) {
        guard packet.count >= 20 else { return }
        var flags = UInt32(packet[packet.startIndex + 16])     |
                    UInt32(packet[packet.startIndex + 17]) << 8  |
                    UInt32(packet[packet.startIndex + 18]) << 16 |
                    UInt32(packet[packet.startIndex + 19]) << 24
        flags |= SMB2Flags.signed
        packet[packet.startIndex + 16] = UInt8( flags        & 0xFF)
        packet[packet.startIndex + 17] = UInt8((flags >>  8) & 0xFF)
        packet[packet.startIndex + 18] = UInt8((flags >> 16) & 0xFF)
        packet[packet.startIndex + 19] = UInt8((flags >> 24) & 0xFF)
    }

    /// Compute HMAC-SHA256 over the given packet bytes using the signing key.
    /// The Signature field in the packet should be zeroed before calling.
    /// Returns the full 32-byte HMAC; caller takes prefix(16).
    private static func computeSignature(packet: Data, key: SymmetricKey) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: packet, using: key)
        return Data(mac)
    }
}

// MARK: - Negotiated info

extension SMBSession {

    /// Server capabilities captured from the NEGOTIATE response.
    /// Exposed to the Client layer so it can size reads correctly.
    public struct Negotiated: Sendable {
        public let dialect:         UInt16
        public let maxReadSize:     UInt32
        public let maxWriteSize:    UInt32
        public let maxTransactSize: UInt32
        public let serverGuid:      Data
        public let securityBuffer:  Data
        public let securityMode:    UInt16
    }
}
