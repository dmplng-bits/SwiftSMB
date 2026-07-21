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

    // ── Request serialization ──────────────────────────────────────────
    // Responses are read inline in `sendRequest` (there is no central
    // per-messageId demultiplexing read loop). Because actors are REENTRANT
    // across `await`, two overlapping `sendRequest` calls would each call
    // `transport.receive()` on the same socket and steal each other's bytes,
    // corrupting both responses (observed as failed READs that drop the
    // streaming proxy connection → AVPlayer NSURLError -1005). This FIFO async
    // mutex serializes the entire send→receive round-trip so exactly one
    // request is in flight at a time.
    private var ioBusy = false
    private var ioWaiters: [CheckedContinuation<Void, Never>] = []

    /// Acquire the round-trip mutex (FIFO). Suspends if a request is in flight.
    private func ioAcquire() async {
        if !ioBusy {
            ioBusy = true
            return
        }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            ioWaiters.append(c)
        }
    }

    /// Release the round-trip mutex, handing off to the next waiter if any.
    private func ioRelease() {
        if ioWaiters.isEmpty {
            ioBusy = false
        } else {
            // Hand the lock directly to the next waiter (ioBusy stays true).
            ioWaiters.removeFirst().resume()
        }
    }

    private(set) public var negotiated: Negotiated?

    // ── Credit tracking ────────────────────────────────────────────────
    // SMB2 flow control: the server grants credits in each response, and
    // we spend them on each request. Large reads/writes cost more than 1.
    private var creditsAvailable: UInt16 = 0

    // ── Pipelining (multiple requests in flight) ────────────────────────
    // The serial path above allows exactly ONE request on the wire at a
    // time. That caps throughput on a latency-bound link because every
    // read/write pays a full round-trip back-to-back. The pipeline below
    // lets many requests be outstanding at once: senders emit under a short
    // wire lock and then suspend on a per-messageId continuation; a single
    // background reader task owns `transport.receive()`, matches each reply
    // to its request by MessageId, and resumes the right sender.
    //
    // Pipelining is only active AFTER the handshake (the handshake needs
    // strict request/response ordering for the preauth-integrity hash and
    // runs on the serial path with the reader stopped).
    //
    // Pipelining is STRICTLY OPT-IN: `maxInFlightRequests` defaults to 1, so an
    // unconfigured session behaves exactly like the original serial
    // implementation. Only bulk-throughput-bound workloads (e.g. the direct-play
    // streaming proxy) should raise it. Latency/jitter-sensitive callers — the
    // real-time transmux/sample-buffer path that reads via `contents(range:)` —
    // must leave it at 1: the background reader, parallel reads, and credit
    // bookkeeping otherwise compete with real-time decode and cause playback
    // jitter (see the pipelining-opt-in handoff).

    /// Maximum SMB2 requests allowed on the wire at once. **Defaults to 1
    /// (serial); pipelining is opt-in.** Raise it only for bulk-transfer
    /// sessions, via the `maxInFlightRequests:` initializer parameter or
    /// ``setMaxInFlightRequests(_:)``.
    ///
    /// Snapshotted ONCE, at connect, into `activeConcurrency`/`pipeliningEnabled`
    /// — so configure it BEFORE `connectShare`. Mutating it on a connected
    /// session has no effect until the next connect, which also guarantees the
    /// pipeline can never flip to serial mid-session (two readers on one socket).
    ///
    /// Externally read-only: set it through the initializer or
    /// ``setMaxInFlightRequests(_:)`` (writing an actor's stored property from
    /// outside the actor is not allowed).
    public private(set) var maxInFlightRequests: Int = 1

    /// Snapshot of `maxInFlightRequests` taken when the reader started. Governs
    /// whether pipelining is active and the read/write fan-out width.
    private var pipeliningEnabled = false
    private var activeConcurrency = 1

    /// True once `startReader()` has spun up the background reader.
    private var readerRunning = false
    private var readerTask: Task<Void, Never>?

    /// Fatal pipeline error (transport died / desync). While set, pipelined
    /// sends fail fast; cleared on reconnect.
    private var pipelineDead: Error?

    /// One outstanding request awaiting its reply.
    private struct Pending {
        let command: UInt16
        let continuation: CheckedContinuation<(SMB2Header, Data), Error>
    }
    /// messageId → waiting sender.
    private var pending: [UInt64: Pending] = [:]
    /// Replies that arrived before the sender finished registering its
    /// continuation (the reader can run between our send and our await).
    private var earlyReplies: [UInt64: Result<(SMB2Header, Data), Error>] = [:]
    /// MessageIds we've emitted and are still awaiting a FINAL reply for. This
    /// (not a bare counter) is the source of truth for "is a reply expected":
    /// it lets the reader (a) park only when genuinely idle and (b) ignore
    /// unsolicited server messages (oplock/lease breaks, duplicates) instead of
    /// mistaking them for a reply and parking with a real read still in flight.
    private var awaiting: Set<UInt64> = []

    /// At most one request may be sent "optimistically" when the credit balance
    /// is empty and nothing is in flight to replenish it — mirrors the serial
    /// path (which never blocks on credits) without letting a herd of waiters
    /// all over-subscribe at once. Cleared when a real grant arrives.
    private var optimisticInFlight = false

    // Wire-emission mutex: makes "assign messageId → build → sign → encrypt →
    // send" atomic and in messageId order, without holding across the reply.
    private var wireBusy = false
    private var wireWaiters: [CheckedContinuation<Void, Never>] = []

    // Weighted async credit gate. Waiters are woken on every grant and
    // re-check; those still short re-suspend (correct for mixed charges).
    private var creditWaiters: [CheckedContinuation<Void, Never>] = []

    // Reader parks here when nothing is outstanding, to avoid tripping the
    // transport's idle receive timeout. Unparked when a request is emitted.
    private var readerParkCont: CheckedContinuation<Void, Never>?

    // ── Signing ────────────────────────────────────────────────────────
    // After a successful SESSION_SETUP the session base key is run
    // through the SP800-108 KDF (for SMB 3.x) to derive a signing key.
    // All outgoing packets get a MAC in the Signature field and all
    // incoming responses are verified.
    //
    // Per [MS-SMB2] §3.1.4.1 the algorithm is dialect-dependent:
    //   * SMB 2.x  — HMAC-SHA256 (16-byte prefix of the tag)
    //   * SMB 3.x  — AES-CMAC-128
    // `computeSignature` picks the right one based on `negotiated.dialect`.
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

    /// - Parameter maxInFlightRequests: request-pipelining width. Defaults to 1
    ///   (serial). Raise it only for bulk-transfer sessions (see the property
    ///   docs). Clamped to ≥ 1.
    public init(transport: SMBTransport, maxInFlightRequests: Int = 1) {
        self.transport = transport
        self.maxInFlightRequests = max(1, maxInFlightRequests)
    }

    // Note: in Swift 6 actor inits cannot be marked `convenience`, and
    // they also cannot delegate via `self.init(...)` (that pattern
    // implicitly requires `convenience`). So this secondary init
    // initialises the stored property directly instead.
    /// - Parameter maxInFlightRequests: request-pipelining width. Defaults to 1
    ///   (serial). Raise it only for bulk-transfer sessions. Clamped to ≥ 1.
    public init(host: String, port: UInt16 = 445, maxInFlightRequests: Int = 1) {
        self.transport = SMBTransport(host: host, port: port)
        self.maxInFlightRequests = max(1, maxInFlightRequests)
    }

    /// Opt this session into (or out of) request pipelining. `n` is the maximum
    /// number of SMB2 requests allowed on the wire at once; 1 = serial (the
    /// default). Clamped to ≥ 1.
    ///
    /// - Important: takes effect at the NEXT `connectShare`/`reconnect` — the
    ///   value is snapshotted when the background reader starts. Call it BEFORE
    ///   connecting; changing it on an already-connected session is a no-op
    ///   until the next connect.
    public func setMaxInFlightRequests(_ n: Int) {
        maxInFlightRequests = max(1, n)
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

        // Start from clean state in case this session object is being reused:
        // stop any prior reader, wipe pipeline state, and zero the SMB2 counters
        // so NEGOTIATE goes out with MessageId 0 and a fresh credit balance.
        stopReader()
        resetPipelineState()
        messageId        = 0
        creditsAvailable = 0
        sessionId        = 0
        treeId           = 0

        try await transport.connect()
        try await negotiate()
        try await authenticate(credentials)
        try await treeConnect(sharePath)
        startKeepalive()
        // Handshake done and preauth frozen — safe to enable pipelining now.
        startReader()
    }

    /// Tear everything down gracefully: stop keepalive → TREE_DISCONNECT → LOGOFF → TCP close.
    public func disconnect() async {
        stopKeepalive()

        // Send the graceful TREE_DISCONNECT/LOGOFF FIRST, while the reader is
        // still running — they go through whichever path is active (pipelined
        // if the reader is up). Doing this before stopping the reader avoids
        // two concurrent `transport.receive()` calls (reader + serial logoff)
        // stealing each other's bytes.
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

        // Now stop the reader and fail anything still pending before closing,
        // then wipe pipeline state so a later connectShare on this session is
        // clean (also clears any stuck wire mutex).
        stopReader()
        failPipeline(SMBError.connectionLost)
        resetPipelineState()

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
        // Stop the reader and fail every in-flight/waiting pipelined request,
        // then wipe all pipeline state so the fresh session starts clean. This
        // is the coordination the handoff flagged as missing between reconnect()
        // and the in-flight machinery.
        stopReader()
        failPipeline(SMBError.connectionLost)
        resetPipelineState()
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
            startReader()
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

        // ── Cipher-downgrade protection ────────────────────────────────
        // [MS-SMB2] §3.2.5.2: if the server returns an
        // EncryptionCapabilities context, the single cipher it chose MUST
        // be one the client advertised. Anything else is a downgrade
        // attempt (or a buggy server) — refuse to continue since we'd
        // otherwise silently disable encryption.
        // `chosenCipher == 0` means "no cipher context / no encryption"
        // which is legal and just leaves encryption off.
        // A chosen cipher on a pre-3.1.1 dialect is also a spec violation.
        if parsed.chosenCipher != 0 {
            let offered: Set<UInt16> = [
                SMB2Cipher.aes128ccm,
                SMB2Cipher.aes128gcm
            ]
            guard parsed.dialectRevision == SMB2Dialect.smb311,
                  offered.contains(parsed.chosenCipher) else {
                throw SMBError.negotiationFailed(
                    "server selected cipher 0x\(String(parsed.chosenCipher, radix: 16)) " +
                    "that was not offered (possible downgrade attack or non-compliant server)"
                )
            }
        }

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

        // Streaming throughput is bounded by how big a single SMB2 READ can be.
        // If a server (or a fallback) leaves maxReadSize at the 64 KiB floor,
        // every read pays a full round-trip for very little data and playback
        // stutters — so surface the negotiated size for diagnosis. [SwiftSMB]
        #if DEBUG
        let dialectHex = String(parsed.dialectRevision, radix: 16)
        print("[SwiftSMB] negotiated dialect=0x\(dialectHex) " +
              "maxReadSize=\(parsed.maxReadSize) " +
              "maxWriteSize=\(parsed.maxWriteSize) " +
              "maxTransactSize=\(parsed.maxTransactSize)")
        #endif
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
        // [MS-SMB2] §3.2.5.3.1: if the server advertised SIGNING_REQUIRED in
        // the NEGOTIATE response, a session that can't sign must not be
        // used. Fail-closed rather than letting the server reject every
        // subsequent request with ACCESS_DENIED.
        if sessionBaseKey.isEmpty {
            if signingRequired {
                sessionId = 0
                throw SMBError.signingRequired
            }
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
        // [MS-SMB2] §3.1.4.1: "If the message is a compounded request or
        // response, each message MUST be signed separately." That means
        // every chained SMB2 header gets SMB2_FLAGS_SIGNED set, its own
        // signature field zeroed, and then a MAC computed over just that
        // message's bytes (header + body + any tail padding). Previous
        // revisions signed the whole compound as a single blob which
        // Windows Server rejects once signing is enforced.
        if let key = signingKey {
            signCompoundPacket(&compound, key: key)
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

        // Verify each chained response's signature before handing any of
        // them back to callers. The single-request path does this at the
        // end of `sendRequest`; the compound path used to skip it, which
        // let a tampered inner response slip past.
        if let key = signingKey {
            guard verifyCompoundSignatures(response, key: key) else {
                throw SMBError.signatureVerificationFailed
            }
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

    /// True when the pipelined path should handle a request: pipelining is
    /// enabled, the background reader is up, we're past the handshake, and the
    /// pipeline hasn't died. The handshake (preauthActive) and teardown always
    /// fall back to the serial path.
    private var pipeliningActive: Bool {
        // Deliberately does NOT read `maxInFlightRequests` (which can be mutated
        // at runtime) — `readerRunning` already implies the reader was started
        // with pipelining enabled, so this can't flip to serial mid-session.
        pipeliningEnabled && readerRunning && !preauthActive && pipelineDead == nil
    }

    /// Send one SMB2 request and return the parsed header plus the raw body.
    ///
    /// Dispatches to the pipelined engine when it's active (many requests in
    /// flight) or the original serial round-trip otherwise (handshake, and the
    /// `maxInFlightRequests == 1` fallback).
    ///
    /// `payloadSize` sizes the `CreditCharge` for large ops (READ, WRITE,
    /// QUERY_DIRECTORY). Pass 0 for small commands.
    public func sendRequest(
        command: UInt16,
        body: Data,
        payloadSize: Int = 0
    ) async throws -> (SMB2Header, Data) {
        if pipeliningActive {
            let charge = Self.creditCharge(forPayloadLength: payloadSize)
            try await creditAcquire(charge)
            return try await sendPipelined(command: command, body: body, charge: charge)
        }
        return try await sendRequestSerial(command: command, body: body, payloadSize: payloadSize)
    }

    /// The original single-in-flight round-trip. Kept verbatim: it is the
    /// handshake path (preauth ordering) and the serial fallback.
    private func sendRequestSerial(
        command: UInt16,
        body: Data,
        payloadSize: Int = 0
    ) async throws -> (SMB2Header, Data) {
        // Serialize the entire round-trip. messageId assignment, preauth-hash
        // updates, signing, the send, and the inline response read must all
        // complete for one request before the next begins — the actor alone
        // does not guarantee this because it is reentrant across `await`.
        await ioAcquire()
        defer { ioRelease() }

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

        // Read the response, transparently skipping SMB2 async INTERIM
        // responses. Per [MS-SMB2] §3.2.5.1.5, when a server can't satisfy a
        // request immediately (common for READ on large files, or any op on a
        // busy NAS) it first sends an INTERIM response with Status =
        // STATUS_PENDING (0x00000103) and the SMB2_FLAGS_ASYNC_COMMAND flag
        // set, then sends the FINAL response later on the same connection.
        // The interim packet is NOT the result — if we returned it, the real
        // response would be left unread and the NEXT request would read it,
        // desyncing the whole stream (observed as STATUS_PENDING reads followed
        // by cascading "unexpected command" errors). Loop until the final,
        // non-interim response arrives.
        var response: Data
        var respHeader: SMB2Header
        var interimGuard = 0
        repeat {
            response = try await transport.receive()

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
            respHeader = try SMB2Header.parse(response)

            interimGuard += 1
            if interimGuard > 64 { break }   // safety valve against a stuck peer
        } while respHeader.status == NTStatus.pending
            && (respHeader.flags & SMB2Flags.asyncCommand) != 0

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

    // MARK: - Pipelined request engine

    /// True when pipelining is currently handling requests. Read by the client
    /// layer to decide whether to fan out parallel reads/writes.
    public var isPipelining: Bool { pipeliningActive }

    /// Read/write fan-out width (never < 1). Snapshot taken at connect.
    public func readWriteConcurrency() -> Int { max(1, activeConcurrency) }

    /// Per-request credit ask: keep the balance healthy enough to sustain many
    /// in-flight requests, bounded so we never request an absurd amount.
    private static func pipelinedCreditRequest(_ charge: UInt16) -> UInt16 {
        UInt16(min(512, max(64, Int(charge) * 8)))
    }

    // ── Credit gate ─────────────────────────────────────────────────────

    /// Reserve exactly `charge` credits, suspending until the balance covers
    /// it. Used by small control ops whose charge is tiny (always affordable
    /// once the session is up); large reads/writes use `reserveCredits`.
    func creditAcquire(_ charge: UInt16) async throws {
        let need = max(1, charge)
        while true {
            if let f = pipelineDead { throw f }
            if creditsAvailable >= need {
                creditsAvailable &-= need
                return
            }
            // Balance can't cover this. If nothing is outstanding to replenish
            // it, send optimistically (like the serial path, which never blocks
            // on credits) — the request itself elicits a fresh grant. Only one
            // waiter may do this at a time, to avoid a herd over-subscribing.
            if awaiting.isEmpty && !optimisticInFlight {
                optimisticInFlight = true
                // Spend whatever partial balance we have (keeps accounting sane);
                // callers pre-size large transfers via `reserveCredits`, so this
                // path effectively only ever fires for charge-1 control ops.
                creditsAvailable &-= min(need, creditsAvailable)
                return
            }
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                creditWaiters.append(c)
            }
        }
    }

    /// Reserve up to `desired` credits, returning how many were actually taken
    /// (always ≥ 1). Suspends only while the balance is completely empty — so a
    /// read/write shrinks to what's affordable instead of dead-locking on a
    /// stingy server (mirrors the serial path's `affordablePayloadLength`).
    public func reserveCredits(upTo desired: UInt16) async throws -> UInt16 {
        let want = max(1, desired)
        while true {
            if let f = pipelineDead { throw f }
            if creditsAvailable >= 1 {
                let take = min(want, creditsAvailable)
                creditsAvailable &-= take
                return take
            }
            // Empty balance. If nothing is in flight to replenish it, take a
            // single credit optimistically so the read/write can go out and
            // elicit a grant (mirrors the serial path). One waiter at a time.
            if awaiting.isEmpty && !optimisticInFlight {
                optimisticInFlight = true
                return 1
            }
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                creditWaiters.append(c)
            }
        }
    }

    /// Hand back credits reserved but not spent (e.g. a read shrank below its
    /// reservation). Does not represent a server grant.
    public func releaseCredits(_ n: UInt16) {
        guard n > 0 else { return }
        creditsAvailable &+= n
        wakeCreditWaiters()
    }

    /// Apply a server credit grant from a response and wake waiters. A real
    /// grant clears the optimism gate so normal crediting resumes.
    private func creditGrant(_ granted: UInt16) {
        creditsAvailable &+= granted
        optimisticInFlight = false
        wakeCreditWaiters()
    }

    /// Wake every credit waiter; each re-checks and re-suspends if still short.
    /// (Wake-all is required because waiters have different charges — a strict
    /// FIFO could park a small waiter behind a large one that can't yet run.)
    private func wakeCreditWaiters() {
        guard !creditWaiters.isEmpty else { return }
        let waiters = creditWaiters
        creditWaiters.removeAll()
        for c in waiters { c.resume() }
    }

    // ── Wire-emission mutex ─────────────────────────────────────────────

    private func wireAcquire() async {
        if !wireBusy { wireBusy = true; return }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            wireWaiters.append(c)
        }
    }
    private func wireRelease() {
        if wireWaiters.isEmpty { wireBusy = false }
        else { wireWaiters.removeFirst().resume() }
    }

    // ── Send + await reply ──────────────────────────────────────────────

    /// Emit a request whose `charge` credits were ALREADY reserved (via
    /// `creditAcquire`/`reserveCredits`) and suspend until its reply arrives.
    /// The single background reader resumes us by MessageId.
    public func sendPipelined(
        command: UInt16,
        body: Data,
        charge: UInt16
    ) async throws -> (SMB2Header, Data) {
        if let f = pipelineDead { throw f }
        let mid: UInt64
        do {
            mid = try await emitOnWire(command: command, body: body, charge: charge)
        } catch {
            failPipeline(error)
            throw error
        }
        return try await withCheckedThrowingContinuation {
            (cont: CheckedContinuation<(SMB2Header, Data), Error>) in
            // The reader can run between our send and here; check both the
            // failure flag and the early-reply stash before parking.
            if let f = pipelineDead {
                cont.resume(throwing: f)
            } else if let early = earlyReplies.removeValue(forKey: mid) {
                cont.resume(with: verifyCommand(early, expected: command))
            } else {
                pending[mid] = Pending(command: command, continuation: cont)
            }
        }
    }

    /// Assign a MessageId, build/sign/encrypt the packet, and put it on the
    /// wire — all under the wire mutex so packets leave in MessageId order.
    private func emitOnWire(command: UInt16, body: Data, charge: UInt16) async throws -> UInt64 {
        await wireAcquire()
        defer { wireRelease() }
        if let f = pipelineDead { throw f }

        let mid = messageId
        messageId &+= UInt64(charge)

        let header = SMB2HeaderBuilder.build(
            command:       command,
            creditCharge:  charge,
            creditRequest: Self.pipelinedCreditRequest(charge),
            messageId:     mid,
            sessionId:     sessionId,
            treeId:        treeId
        )
        var packet = Data()
        packet.append(header)
        packet.append(body)

        if let key = signingKey {
            Self.setSignedFlag(&packet)
            let sig = computeSignature(packet: packet, key: key)
            packet.replaceSubrange(48..<64, with: sig.prefix(16))
        }

        // No preauth-hash update here — pipelining is only active after the
        // handshake has frozen the preauth hash.

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
        awaiting.insert(mid)
        unparkReader()
        return mid
    }

    /// Enforce that a reply's command matches the request it's delivered to.
    private func verifyCommand(
        _ result: Result<(SMB2Header, Data), Error>,
        expected: UInt16
    ) -> Result<(SMB2Header, Data), Error> {
        if case .success(let (h, _)) = result, h.command != expected {
            return .failure(SMBError.unexpectedCommand(expected: expected, got: h.command))
        }
        return result
    }

    // ── Background reader ───────────────────────────────────────────────

    /// Start the single reader task (no-op unless pipelining is enabled).
    /// Snapshots `maxInFlightRequests` so runtime mutation can't destabilize a
    /// live session.
    public func startReader() {
        guard maxInFlightRequests > 1, readerTask == nil else { return }
        pipelineDead = nil
        pipeliningEnabled = true
        activeConcurrency = maxInFlightRequests
        readerRunning = true
        readerTask = Task { [weak self] in
            await self?.readerLoop()
        }
    }

    /// Stop the reader task. Does not by itself fail in-flight requests —
    /// callers pair it with `failPipeline` when tearing the session down.
    public func stopReader() {
        readerRunning = false
        pipeliningEnabled = false
        let t = readerTask
        readerTask = nil
        unparkReader()
        t?.cancel()
    }

    private func parkReader() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            readerParkCont = c
        }
    }
    private func unparkReader() {
        if let c = readerParkCont { readerParkCont = nil; c.resume() }
    }

    private func readerLoop() async {
        while readerRunning {
            // Nothing outstanding → park rather than block on receive() and trip
            // its idle timeout. Unparked by the next emitOnWire.
            if awaiting.isEmpty {
                await parkReader()
                continue
            }
            let raw: Data
            do {
                raw = try await transport.receive()
            } catch {
                failPipeline(error)
                return
            }
            route(raw)
        }
    }

    /// Decrypt, verify, credit, and dispatch a single received message.
    private func route(_ raw: Data) {
        var data = raw

        if SMB2TransformParser.isTransformPacket(data) {
            guard !decryptionKey.isEmpty else {
                failPipeline(SMBError.signatureVerificationFailed); return
            }
            do {
                let parsed = try SMB2TransformParser.parse(data)
                data = try SMB2TransformParser.decryptGCM(parsed, decryptionKey: decryptionKey)
            } catch { failPipeline(error); return }
        }

        guard data.count >= smb2HeaderSize else {
            failPipeline(SMBError.truncatedPacket); return
        }
        let header: SMB2Header
        do { header = try SMB2Header.parse(data) } catch { failPipeline(error); return }
        let mid = header.messageId

        // Interim async STATUS_PENDING is NOT the final reply — absorb any
        // credit grant it carries and keep the request awaiting.
        if header.status == NTStatus.pending && (header.flags & SMB2Flags.asyncCommand) != 0 {
            creditGrant(header.creditGranted)
            return
        }

        // Only messages we actually sent count as replies. Anything else — an
        // unsolicited oplock/lease break (MessageId 0xFFFF…FFFF), a duplicate,
        // or a stray — is absorbed for its credit grant and otherwise ignored,
        // so it can never decrement `awaiting` or park the reader while a real
        // reply is still in flight. (We don't ACK oplock breaks; the previous
        // serial code didn't handle them either.)
        guard awaiting.contains(mid) else {
            creditGrant(header.creditGranted)
            return
        }

        // Verify signature (mirrors the serial path).
        if signingKey != nil && (header.flags & SMB2Flags.signed) != 0 {
            var mutable = data
            mutable.replaceSubrange(48..<64, with: Data(count: 16))
            let expected = computeSignature(packet: mutable, key: signingKey!)
            if expected.prefix(16) != header.signature {
                creditGrant(header.creditGranted)
                awaiting.remove(mid)
                deliver(mid, .failure(SMBError.signatureVerificationFailed))
                return
            }
        }

        creditGrant(header.creditGranted)
        awaiting.remove(mid)
        let body = data.subdata(in: data.startIndex + smb2HeaderSize ..< data.endIndex)
        deliver(mid, .success((header, body)))
    }

    private func deliver(_ mid: UInt64, _ result: Result<(SMB2Header, Data), Error>) {
        if let entry = pending.removeValue(forKey: mid) {
            entry.continuation.resume(with: verifyCommand(result, expected: entry.command))
        } else {
            // Reply for an awaited request landed before the sender registered
            // its continuation — stash it; `sendPipelined` claims it on wake.
            earlyReplies[mid] = result
        }
    }

    /// Fatal pipeline error: fail every in-flight and waiting request, stop the
    /// reader, and put the session into a state where further pipelined sends
    /// throw until `reconnect()` resets it.
    private func failPipeline(_ error: Error) {
        if pipelineDead == nil { pipelineDead = error }
        readerRunning = false
        let inflight = pending
        pending.removeAll()
        for (_, e) in inflight { e.continuation.resume(throwing: error) }
        earlyReplies.removeAll()
        awaiting.removeAll()
        optimisticInFlight = false
        // Credit waiters re-check, see pipelineDead, and throw. (Waiters in the
        // wire mutex unwind naturally as the current holder releases and its
        // emitOnWire sees pipelineDead.)
        wakeCreditWaiters()
        unparkReader()
    }

    /// Clear all pipeline state for a fresh connection (used by reconnect and
    /// before/after connect so a reused session starts clean).
    private func resetPipelineState() {
        pipelineDead = nil
        pending.removeAll()
        earlyReplies.removeAll()
        awaiting.removeAll()
        optimisticInFlight = false
        creditWaiters.removeAll()
        readerParkCont = nil
        wireBusy = false
        wireWaiters.removeAll()
    }

    #if DEBUG
    // ── Test hooks (DEBUG only) ─────────────────────────────────────────
    // Let unit tests drive the credit gate without a live server. The gate
    // touches no transport state, so it can be exercised on an unconnected
    // session.
    func _testApplyGrant(_ n: UInt16) { creditGrant(n) }
    var _testCreditsAvailable: UInt16 { creditsAvailable }
    func _testSetCredits(_ n: UInt16) { creditsAvailable = n }
    /// Simulate an in-flight request so the credit gate blocks (rather than
    /// taking the optimistic no-outstanding escape) when the balance is short.
    func _testMarkAwaiting(_ mid: UInt64) { awaiting.insert(mid) }
    #endif

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

    /// Walk a (possibly compounded) SMB2 packet and return the byte
    /// ranges of each chained message. Ranges are expressed as
    /// `packet`-relative `(offset, length)` pairs so the caller can index
    /// with `packet.startIndex + offset`.
    private static func compoundRanges(in packet: Data) -> [(offset: Int, length: Int)] {
        var ranges: [(Int, Int)] = []
        var offset = 0
        while offset + smb2HeaderSize <= packet.count {
            // NextCommand sits at header offset +20..+24 (little-endian).
            let base = packet.startIndex + offset + 20
            let nextCommand =
                UInt32(packet[base])                 |
                UInt32(packet[base + 1]) <<  8 |
                UInt32(packet[base + 2]) << 16 |
                UInt32(packet[base + 3]) << 24
            let len = (nextCommand == 0)
                ? (packet.count - offset)
                : Int(nextCommand)
            // Defensive — a corrupt NextCommand must not walk past the end.
            guard len >= smb2HeaderSize, offset + len <= packet.count else {
                // Bail out; verifier will treat this as a failure.
                return ranges
            }
            ranges.append((offset, len))
            if nextCommand == 0 { break }
            offset += Int(nextCommand)
        }
        return ranges
    }

    /// Sign every chained message in `packet` individually as required by
    /// [MS-SMB2] §3.1.4.1. Sets SMB2_FLAGS_SIGNED on each header, zeros
    /// its signature field, then computes a MAC over just that message's
    /// bytes and writes it back into that header's signature field.
    private func signCompoundPacket(_ packet: inout Data, key: SymmetricKey) {
        let ranges = Self.compoundRanges(in: packet)

        // Pass 1: set SIGNED flag and zero every signature field. Signing
        // each message covers the signature-zeroed bytes of its OWN
        // header — having the other headers zeroed or not doesn't matter
        // since no inter-message bytes are hashed into any single MAC.
        for (offset, _) in ranges {
            // Flags at +16..+20.
            let flagsOff = packet.startIndex + offset + 16
            var flags: UInt32 = 0
            for i in 0..<4 {
                flags |= UInt32(packet[flagsOff + i]) << (8 * i)
            }
            flags |= SMB2Flags.signed
            for i in 0..<4 {
                packet[flagsOff + i] = UInt8((flags >> (8 * i)) & 0xFF)
            }
            // Signature at +48..+64.
            let sigStart = packet.startIndex + offset + 48
            packet.replaceSubrange(sigStart ..< sigStart + 16,
                                   with: Data(count: 16))
        }

        // Pass 2: MAC each message, write signature back.
        // Use an explicit byte-array copy so the extracted Data has
        // startIndex == 0, which `computeSignature` expects.
        for (offset, length) in ranges {
            let start = packet.startIndex + offset
            let end   = start + length
            let msg   = Data([UInt8](packet[start ..< end]))
            let sig   = computeSignature(packet: msg, key: key)
            let sigStart = start + 48
            packet.replaceSubrange(sigStart ..< sigStart + 16,
                                   with: sig.prefix(16))
        }
    }

    /// Verify each signed message in a (possibly compounded) response.
    /// Returns true iff every message whose header carries the SIGNED
    /// flag verifies under `key`. Messages without the SIGNED flag are
    /// ignored — that matches the single-request path at line ~746.
    private func verifyCompoundSignatures(_ packet: Data, key: SymmetricKey) -> Bool {
        let ranges = Self.compoundRanges(in: packet)
        guard !ranges.isEmpty else { return false }

        for (offset, length) in ranges {
            let flagsOff = packet.startIndex + offset + 16
            var flags: UInt32 = 0
            for i in 0..<4 {
                flags |= UInt32(packet[flagsOff + i]) << (8 * i)
            }
            guard flags & SMB2Flags.signed != 0 else { continue }

            // Build a zero-indexed byte-array copy of the message so the
            // 48..<64 indices below are unambiguous.
            let start = packet.startIndex + offset
            let end   = start + length
            var msg   = Data([UInt8](packet[start ..< end]))

            // Stash the wire signature, zero the field for the MAC recompute.
            let expected = Data(msg[48 ..< 64])
            msg.replaceSubrange(48 ..< 64, with: Data(count: 16))

            let computed = computeSignature(packet: msg, key: key)
            if computed.prefix(16) != expected {
                return false
            }
        }
        return true
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
