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
//
// All public methods are async and funnel through `request(command:body:)`.

import Foundation

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

    // MARK: - Lifecycle

    /// Run the full handshake: TCP connect → NEGOTIATE → NTLMv2 → TREE_CONNECT.
    public func connectShare(
        _ sharePath: String,
        credentials: SMBCredentials
    ) async throws {
        try await transport.connect()
        try await negotiate()
        try await authenticate(credentials)
        try await treeConnect(sharePath)
    }

    /// Tear everything down gracefully: TREE_DISCONNECT → LOGOFF → TCP close.
    public func disconnect() async {
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
        await transport.disconnect()
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

        self.negotiated = Negotiated(
            dialect:         parsed.dialectRevision,
            maxReadSize:     parsed.maxReadSize,
            maxWriteSize:    parsed.maxWriteSize,
            maxTransactSize: parsed.maxTransactSize,
            serverGuid:      parsed.serverGuid,
            securityBuffer:  parsed.securityBuffer
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
            // Anything else on round 1 is a protocol error.
            throw SMBError.authenticationFailed
        }

        let setup1Resp = try SMB2SessionSetupResponse.parse(respBody1)
        let ntlmChallengeToken = try SPNEGO.extractNTLMToken(setup1Resp.securityBuffer)
        let challenge = try NTLMv2.parseChallenge(ntlmChallengeToken)

        // Derive NTLMv2 response.
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

        let (_, ntChallengeResponse, _) = NTLMv2.computeResponse(
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
            // Authentication failed — clear the provisional sessionId.
            sessionId = 0
            throw SMBError.authenticationFailed
        }
        // Keep the sessionId as-is — it's the authenticated one now.
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

    // MARK: - Request core

    /// Send one SMB2 request and return the parsed header plus the raw body.
    ///
    /// Callers are expected to parse the body themselves using the command's
    /// dedicated response struct. This keeps `SMBSession` generic.
    public func sendRequest(
        command: UInt16,
        body: Data
    ) async throws -> (SMB2Header, Data) {
        // Grab & advance the messageId atomically (we're an actor).
        let myMessageId = messageId
        messageId &+= 1

        let header = SMB2HeaderBuilder.build(
            command:   command,
            messageId: myMessageId,
            sessionId: sessionId,
            treeId:    treeId
        )
        var packet = Data()
        packet.append(header)
        packet.append(body)

        try await transport.send(packet)
        let response = try await transport.receive()

        guard response.count >= smb2HeaderSize else {
            throw SMBError.truncatedPacket
        }
        let respHeader = try SMB2Header.parse(response)
        // Verify command echoed back matches (except for async replies).
        if respHeader.command != command {
            throw SMBError.unexpectedCommand(
                expected: command,
                got:      respHeader.command
            )
        }
        let respBody = response.subdata(in: response.startIndex + smb2HeaderSize ..< response.endIndex)
        return (respHeader, respBody)
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
    }
}
