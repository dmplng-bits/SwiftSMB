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
///
/// For unauthenticated access, use `.anonymous` explicitly.
/// Anonymous and guest are *different* auth modes on the wire — modern
/// Samba, TrueNAS Scale, and Windows Server reject "guest" by default
/// but still allow anonymous IPC$ connections.
/// See [MS-NLMP] §3.2.5.1.2 (NTLMSSP_NEGOTIATE_ANONYMOUS).
///
/// ## Security note
/// An anonymous / null session carries **no signing key** — every
/// request and response travels the wire unsigned and can be tampered
/// with by an on-path attacker. Use `.anonymous` only for browsing
/// public shares on trusted networks (home LAN, VPN). For anything
/// that reads private data or performs writes, pass real credentials.
public struct SMBCredentials: Sendable {
    public let user:        String
    public let password:    String
    public let domain:      String
    public let workstation: String
    public let isAnonymous: Bool

    public init(
        user: String,
        password: String,
        domain: String = "",
        workstation: String = "",
        isAnonymous: Bool = false
    ) {
        self.user        = user
        self.password    = password
        self.domain      = domain
        self.workstation = workstation
        // Anonymous must be explicit — callers that genuinely want a
        // null session use `.anonymous` or pass `isAnonymous: true`.
        // Empty strings with `isAnonymous: false` send a real NTLMv2
        // AUTHENTICATE with an empty username, which some servers
        // accept and others reject (that's the caller's choice).
        self.isAnonymous = isAnonymous
    }

    /// Explicit anonymous (null-session) access. Emits an empty
    /// NTLMSSP AUTHENTICATE message with the anonymous flag set.
    ///
    /// - Warning: Traffic on an anonymous session is unsigned. Only
    ///   use this on trusted networks.
    public static let anonymous = SMBCredentials(
        user: "", password: "", domain: "", workstation: "", isAnonymous: true
    )

    /// Backwards-compatible alias. Modern servers reject a literal
    /// "guest" NTLMv2 logon, so we route this to the anonymous path
    /// where it's most likely to succeed.
    public static let guest = SMBCredentials.anonymous
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
    // After a successful SESSION_SETUP the session base key is run
    // through the SP800-108 KDF (for SMB 3.x) to derive a signing key.
    // All outgoing packets get an HMAC-SHA256 tag in the Signature
    // field, and all incoming responses are verified.
    //
    // NOTE: [MS-SMB2] §3.1.4.1 says SMB 3.x uses AES-CMAC-128 rather
    // than HMAC-SHA256. We still compute HMAC-SHA256 here; servers that
    // don't enforce strict signature verification accept it, and a
    // correctly-derived key is a prerequisite for a future AES-CMAC
    // upgrade. See `computeSignature` for the algorithm call site.
    private var signingKey: SymmetricKey?
    private var signingRequired: Bool = false

    // ── SMB 3.1.1 preauth integrity ────────────────────────────────────
    // SHA-512 running hash of NEGOTIATE + SESSION_SETUP messages. Fed
    // as the Context into the signing key KDF for the 3.1.1 dialect.
    // `preauthActive` is true from the start of `negotiate()` until
    // signing-key derivation in `authenticate()`.
    private var preauthIntegrityHash: Data = Data(count: 64)
    private var preauthActive: Bool = false

    // ── Encryption (SMB 3.x only) ──────────────────────────────────────
    // When `encryptionEnabled` is true, outgoing packets are wrapped in
    // an SMB2 TRANSFORM_HEADER using `encryptionKey` (AES-128-GCM) and
    // inbound transform-wrapped responses are decrypted with
    // `decryptionKey`. Turned on when the server requests it via
    // SMB2_SESSION_FLAG_ENCRYPT_DATA (session-wide) or
    // SMB2_SHAREFLAG_ENCRYPT_DATA (per share).
    private var encryptionKey: Data = Data()
    private var decryptionKey: Data = Data()
    private var encryptionEnabled: Bool = false

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

    /// Host the underlying transport is targeting. Used by the Client
    /// layer to build proper UNC paths (`\\HOST\share`) and by the share
    /// enumerator to populate the `ServerName` field of NetShareEnumAll.
    /// An empty `\\\share` UNC is rejected by strict Samba builds with
    /// STATUS_INVALID_PARAMETER, which is why we plumb the host through.
    public var currentHost: String { transport.host }
    public var currentPort: UInt16 { transport.port }

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
        encryptionKey = Data()
        decryptionKey = Data()
        encryptionEnabled = false
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
        encryptionKey = Data()
        decryptionKey = Data()
        encryptionEnabled = false
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
        // Reset preauth state and start hashing all NEG / SESSION_SETUP
        // messages — required by SMB 3.1.1, harmless for older dialects.
        preauthIntegrityHash = Data(count: 64)
        preauthActive = true

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
            securityMode:    parsed.securityMode,
            chosenCipher:    parsed.chosenCipher
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

        // Build the AUTHENTICATE message — anonymous or NTLMv2.
        let ntlmAuthenticate: Data
        let sessionBaseKey: Data

        if credentials.isAnonymous {
            // Anonymous / null-session path. Matches Finder's behavior
            // for bare `smb://host` — the server replies with
            // SMB2_SESSION_FLAG_IS_NULL and grants IPC$ access.
            ntlmAuthenticate = NTLMv2.authenticateAnonymous(
                challengeFlags: challenge.flags,
                workstation: credentials.workstation
            )
            // No session base key derivable from an anonymous exchange.
            sessionBaseKey = Data()
        } else {
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

            let (_, ntChallengeResponse, baseKey) = NTLMv2.computeResponse(
                ntlmv2Hash:      ntlmv2Hash,
                serverChallenge: challenge.serverChallenge,
                clientBlob:      clientBlob
            )
            sessionBaseKey = baseKey

            ntlmAuthenticate = NTLMv2.authenticate(
                flags: challenge.flags,
                ntChallengeResponse: ntChallengeResponse,
                domain: domain,
                user:   credentials.user,
                workstation: credentials.workstation
            )
        }

        // Round 2: wrap the NTLM AUTHENTICATE in SPNEGO NegTokenResp.
        let spnegoResp = SPNEGO.wrapNegTokenResp(ntlmAuthenticate: ntlmAuthenticate)
        let setup2Body = SMB2SessionSetupRequest.build(securityBuffer: spnegoResp)

        let (header2, respBody2) = try await sendRequest(
            command: SMB2Command.sessionSetup,
            body: setup2Body
        )
        // SMB2_SESSION_FLAG_IS_GUEST (0x0001) and IS_NULL (0x0002) are
        // *not* failures — the server completed auth with reduced
        // privileges. The SMB2 header status is STATUS_SUCCESS in both
        // cases, so isSuccess is the only thing we need to check.
        guard header2.isSuccess else {
            sessionId = 0
            // Map recognized NTSTATUS codes so callers see a precise error.
            if header2.status == NTStatus.logonFailure
                || header2.status == NTStatus.accountRestriction
                || header2.status == NTStatus.passwordExpired
                || header2.status == NTStatus.noSuchUser
                || header2.status == NTStatus.wrongPassword {
                throw SMBError.authenticationFailed
            }
            throw SMBError.ntStatus(header2.status)
        }

        // ── Derive the signing key from the session base key ───────────
        // [MS-SMB2] §3.1.4.2: SMB 2.x uses the session base key directly;
        // SMB 3.x runs it through SP800-108 HMAC-SHA256 KDF with a
        // dialect-specific label and context. 3.1.1 additionally mixes
        // in the preauth-integrity hash computed over NEGOTIATE +
        // SESSION_SETUP messages.
        //
        // An anonymous session has no base key and therefore can't sign —
        // that's fine, servers that allow anonymous IPC$ don't require it.
        if sessionBaseKey.isEmpty {
            signingKey = nil
            encryptionKey = Data()
            decryptionKey = Data()
        } else {
            let dialect = negotiated?.dialect ?? SMB2Dialect.smb202
            let derived = smbDeriveSigningKey(
                sessionBaseKey:       sessionBaseKey,
                dialect:              dialect,
                preauthIntegrityHash: preauthIntegrityHash
            )
            signingKey = SymmetricKey(data: derived)

            // Derive the encryption key pair for 3.x. No-op on 2.x.
            if let keys = smbDeriveEncryptionKeys(
                sessionBaseKey:       sessionBaseKey,
                dialect:              dialect,
                preauthIntegrityHash: preauthIntegrityHash
            ) {
                encryptionKey = keys.encryption
                decryptionKey = keys.decryption
            } else {
                encryptionKey = Data()
                decryptionKey = Data()
            }
        }

        // Preauth hash is frozen now — stop hashing subsequent traffic.
        preauthActive = false

        // Session-level encryption requirement: if the server set
        // ENCRYPT_DATA in the SessionFlags, every request after this
        // point must be wrapped in a transform header. We only enable
        // this if we can actually honor it — meaning 3.1.1 picked
        // AES-128-GCM. For 3.0/3.0.2 (CCM only) or GCM not chosen, we
        // leave encryption off and let the server reject traffic
        // rather than sending packets we can't wrap correctly.
        if let setup2Resp = try? SMB2SessionSetupResponse.parse(respBody2),
           (setup2Resp.sessionFlags & SMB2SessionFlags.encryptData) != 0,
           canEncrypt() {
            encryptionEnabled = true
        }
    }

    /// Returns true when we have working encryption material — i.e., the
    /// negotiated dialect supports it, the server picked a cipher we
    /// implement (AES-128-GCM), and our key pair is populated.
    private func canEncrypt() -> Bool {
        guard !encryptionKey.isEmpty, !decryptionKey.isEmpty else { return false }
        let dialect = negotiated?.dialect ?? 0
        if dialect == SMB2Dialect.smb311 {
            return negotiated?.chosenCipher == SMB2Cipher.aes128gcm
        }
        // 3.0/3.0.2 only offer CCM in the spec — we don't support it.
        return false
    }

    // SHA-512 hash helper — used to update the preauth integrity value
    // between handshake messages.
    private func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
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
        let parsed = try SMB2TreeConnectResponse.parse(respBody)
        self.treeId = header.treeId

        // Per-share encryption: if the server set ENCRYPT_DATA in the
        // share flags, all subsequent traffic on this tree must be
        // encrypted. We can only honor this on 3.1.1 + GCM.
        if (parsed.shareFlags & SMB2ShareFlags.encryptData) != 0,
           canEncrypt() {
            encryptionEnabled = true
        }
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
            let sig = computeSignature(packet: compound, key: key)
            compound.replaceSubrange(48..<64, with: sig.prefix(16))
        }

        let wireOut: Data
        if encryptionEnabled && !encryptionKey.isEmpty {
            wireOut = try SMB2TransformBuilder.buildGCM(
                plaintext:     compound,
                encryptionKey: encryptionKey,
                sessionId:     sessionId
            )
        } else {
            wireOut = compound
        }

        try await transport.send(wireOut)
        var response = try await transport.receive()

        if SMB2TransformParser.isTransformPacket(response) {
            guard !decryptionKey.isEmpty else {
                throw SMBError.signatureVerificationFailed
            }
            let parsed = try SMB2TransformParser.parse(response)
            response = try SMB2TransformParser.decryptGCM(
                parsed,
                decryptionKey: decryptionKey
            )
        }

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
            let sig = computeSignature(packet: packet, key: key)
            packet.replaceSubrange(48..<64, with: sig.prefix(16))
        }

        // Update the preauth integrity hash BEFORE sending (required by
        // [MS-SMB2] §3.2.5.3.1 for 3.1.1). Covers NEGOTIATE and every
        // SESSION_SETUP request/response exchanged during the handshake.
        if preauthActive,
           command == SMB2Command.negotiate || command == SMB2Command.sessionSetup {
            preauthIntegrityHash = sha512(preauthIntegrityHash + packet)
        }

        // ── Encrypt outgoing packet if encryption is enabled ───────────
        // Wrapping happens AFTER signing — the plaintext still carries
        // its HMAC/CMAC tag, and the transform header provides an outer
        // AEAD tag over the whole envelope.
        let wireOut: Data
        if encryptionEnabled && !encryptionKey.isEmpty {
            wireOut = try SMB2TransformBuilder.buildGCM(
                plaintext:     packet,
                encryptionKey: encryptionKey,
                sessionId:     sessionId
            )
        } else {
            wireOut = packet
        }

        try await transport.send(wireOut)
        var response = try await transport.receive()

        // ── Decrypt inbound transform-wrapped packet ───────────────────
        // Some servers always encrypt responses once encryption is on;
        // others only encrypt when the client did. Detect by protocol id.
        if SMB2TransformParser.isTransformPacket(response) {
            guard !decryptionKey.isEmpty else {
                throw SMBError.signatureVerificationFailed
            }
            let parsed = try SMB2TransformParser.parse(response)
            response = try SMB2TransformParser.decryptGCM(
                parsed,
                decryptionKey: decryptionKey
            )
        }

        guard response.count >= smb2HeaderSize else {
            throw SMBError.truncatedPacket
        }
        let respHeader = try SMB2Header.parse(response)

        // Preauth hash update for the inbound response.
        // NEGOTIATE response is always mixed in. SESSION_SETUP responses
        // are mixed in UNTIL the final round (STATUS_SUCCESS) — the
        // signing key is derived from the hash state just before the
        // final success response, not after it. [MS-SMB2] §3.2.5.3.1.
        if preauthActive {
            if command == SMB2Command.negotiate {
                preauthIntegrityHash = sha512(preauthIntegrityHash + response)
            } else if command == SMB2Command.sessionSetup,
                      !respHeader.isSuccess {
                preauthIntegrityHash = sha512(preauthIntegrityHash + response)
            }
        }

        // ── Verify response signature if signing is active ─────────────
        if signingKey != nil && respHeader.flags & SMB2Flags.signed != 0 {
            var mutable = response
            // Zero out the signature field for verification.
            mutable.replaceSubrange(48..<64, with: Data(count: 16))
            let expected = computeSignature(packet: mutable, key: signingKey!)
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

    /// Compute the SMB2 signature over the packet bytes. Algorithm is
    /// dialect-dependent per [MS-SMB2] §3.1.4.1:
    ///   * SMB 2.x  — HMAC-SHA256
    ///   * SMB 3.x  — AES-CMAC-128
    /// The Signature field in the packet should be zeroed before calling.
    /// Returns at least 16 bytes; caller takes `prefix(16)`.
    private func computeSignature(packet: Data, key: SymmetricKey) -> Data {
        let dialect = negotiated?.dialect ?? SMB2Dialect.smb202
        switch dialect {
        case SMB2Dialect.smb300, SMB2Dialect.smb302, SMB2Dialect.smb311:
            // AES-CMAC-128 needs the raw 16-byte key bytes.
            let keyBytes = key.withUnsafeBytes { Data($0) }
            return aesCMAC(key: keyBytes, data: packet)
        default:
            let mac = HMAC<SHA256>.authenticationCode(for: packet, using: key)
            return Data(mac)
        }
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
        /// Cipher selected by the server (3.1.1 only); 0 if none.
        public let chosenCipher:    UInt16
    }
}
