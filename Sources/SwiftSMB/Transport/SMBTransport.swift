//
//  SMBTransport.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Transport layer for SwiftSMB.
//
// Wraps Network.framework's NWConnection to provide an async/await TCP
// socket with NetBIOS-style 4-byte big-endian length framing.
//
// Wire format on port 445 (Direct TCP) looks like:
//
//     ┌──────────────┬───────────────────────────────┐
//     │ 4-byte length│   SMB2 message (header+body)  │
//     │ (big-endian) │                               │
//     └──────────────┴───────────────────────────────┘
//
// The top byte of the length field is reserved (should be 0) and the low
// 24 bits carry the message length. We always set the top byte to 0 when
// sending and tolerate it when receiving.
//
// This layer knows nothing about SMB2 semantics — it just moves framed
// blobs over TCP. The Session layer is responsible for building/parsing
// those blobs.

import Foundation
import Network

/// Low-level framed TCP transport used by SwiftSMB.
///
/// `SMBTransport` is an actor so that `send` / `receive` can be called
/// concurrently without stepping on each other. All I/O is async.
public actor SMBTransport {

    // MARK: - Configuration

    /// Host and port the transport is (or will be) connected to.
    public struct Endpoint: Sendable, Equatable {
        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16 = 445) {
            self.host = host
            self.port = port
        }
    }

    /// Operational timeouts, in seconds.
    public struct Timeouts: Sendable {
        public var connect:  TimeInterval
        public var send:     TimeInterval
        public var receive:  TimeInterval

        public init(
            connect: TimeInterval = 10,
            send:    TimeInterval = 30,
            receive: TimeInterval = 30
        ) {
            self.connect = connect
            self.send    = send
            self.receive = receive
        }
    }

    // MARK: - State

    private let endpoint: Endpoint
    private let timeouts: Timeouts
    private var connection: NWConnection?
    private var isReady: Bool = false

    /// Maximum single-message size the transport will accept. SMB2 messages
    /// with compounding or large READ/WRITE payloads can be several MB;
    /// 16 MiB is a safe upper bound for consumer NAS devices.
    public static let maxMessageSize: Int = 16 * 1024 * 1024

    // MARK: - Init

    public init(endpoint: Endpoint, timeouts: Timeouts = Timeouts()) {
        self.endpoint = endpoint
        self.timeouts = timeouts
    }

    // In Swift 6 actor inits cannot be marked `convenience`, and they
    // also cannot delegate via `self.init(...)` (that pattern implicitly
    // requires `convenience`). This secondary init sets the stored
    // properties directly instead.
    public init(host: String, port: UInt16 = 445) {
        self.endpoint = Endpoint(host: host, port: port)
        self.timeouts = Timeouts()
    }

    /// Host this transport connects to. Used by upper layers when they
    /// need to build a UNC path (e.g. `\\HOST\share`) without forcing the
    /// caller to pass the host twice.
    ///
    /// Marked `nonisolated` because `endpoint` is an immutable `let` that
    /// is fixed at init time — actor isolation would force every caller
    /// to `await`, which is needless ceremony for a constant read.
    public nonisolated var host: String { endpoint.host }
    public nonisolated var port: UInt16 { endpoint.port }

    // MARK: - Lifecycle

    /// Establish a TCP connection to the server.
    ///
    /// Throws `SMBError.connectionFailed` if the connection cannot be
    /// opened within the configured connect timeout.
    public func connect() async throws {
        if isReady { return }

        // Tear down any previous attempt so we don't leak state.
        connection?.cancel()
        connection = nil

        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw SMBError.connectionFailed("Invalid port \(endpoint.port)")
        }
        let host = NWEndpoint.Host(endpoint.host)

        // Plain TCP — SMB2 runs over raw TCP on port 445.
        let params = NWParameters.tcp
        // SMB servers don't like Nagle holding small messages.
        if let tcpOptions = params.defaultProtocolStack
            .transportProtocol as? NWProtocolTCP.Options {
            tcpOptions.noDelay = true
            tcpOptions.enableKeepalive = true
            tcpOptions.keepaliveIdle = 30
        }

        let conn = NWConnection(host: host, port: port, using: params)
        self.connection = conn

        try await withTimeout(seconds: timeouts.connect, error: .timeout) {
            try await self.waitForReady(conn)
        }
        self.isReady = true
    }

    /// Cleanly close the transport.
    public func disconnect() {
        connection?.cancel()
        connection = nil
        isReady = false
    }

    deinit {
        connection?.cancel()
    }

    // MARK: - Send

    /// Send a single SMB2 message. The transport prepends the 4-byte
    /// big-endian NetBIOS length header.
    public func send(_ message: Data) async throws {
        guard let conn = connection, isReady else {
            throw SMBError.notConnected
        }
        guard message.count <= Self.maxMessageSize else {
            throw SMBError.connectionFailed("Outbound message too large: \(message.count) bytes")
        }

        // Build the framed packet as an immutable `let` so it can be
        // captured by the @Sendable closure below without a Swift 6
        // captured-var warning.
        let framed: Data = {
            var f = Data(capacity: message.count + 4)
            f.append(contentsOf: Self.encodeLength(UInt32(message.count)))
            f.append(message)
            return f
        }()

        try await withTimeout(seconds: timeouts.send, error: .timeout) {
            try await self.rawSend(conn, data: framed)
        }
    }

    // MARK: - Receive

    /// Receive a single SMB2 message. Strips the 4-byte length header.
    public func receive() async throws -> Data {
        guard let conn = connection, isReady else {
            throw SMBError.notConnected
        }

        return try await withTimeout(seconds: timeouts.receive, error: .timeout) {
            // Read 4-byte NetBIOS header.
            let header = try await self.rawReceive(conn, length: 4)
            let length = Self.decodeLength(header)
            guard length > 0 else { return Data() }
            guard length <= UInt32(Self.maxMessageSize) else {
                throw SMBError.connectionFailed("Inbound message too large: \(length) bytes")
            }
            // Read the body.
            return try await self.rawReceive(conn, length: Int(length))
        }
    }

    // MARK: - Framing helpers (package-internal, exposed for tests)

    /// Encode a NetBIOS-session-style 4-byte length header.
    ///
    /// The top byte is reserved (0), the low 24 bits carry the message length.
    static func encodeLength(_ length: UInt32) -> [UInt8] {
        precondition(length <= 0x00FF_FFFF, "SMB2 message length must fit in 24 bits")
        return [
            0x00,                                       // Session type = SESSION MESSAGE (0)
            UInt8((length >> 16) & 0xFF),
            UInt8((length >>  8) & 0xFF),
            UInt8( length        & 0xFF),
        ]
    }

    /// Decode a NetBIOS-session-style 4-byte length header.
    ///
    /// Only the low 24 bits are considered the length; the top byte is
    /// the NetBIOS session type and is ignored for our purposes.
    static func decodeLength(_ header: Data) -> UInt32 {
        precondition(header.count >= 4)
        let b = Array(header.prefix(4))
        return (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
    }

    // MARK: - NWConnection primitives

    private func waitForReady(_ conn: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // ResumeOnce lets us safely gate resumption from a Sendable closure.
            let gate = ResumeOnce()
            let resume: (Result<Void, Error>) -> Void = { result in
                if gate.fire() {
                    continuation.resume(with: result)
                }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    resume(.success(()))
                case .failed(let err):
                    resume(.failure(SMBError.connectionFailed(err.localizedDescription)))
                case .cancelled:
                    resume(.failure(SMBError.connectionLost))
                case .waiting(let err):
                    // `.waiting` means we're waiting on network availability.
                    // Treat it as a failure so the caller can decide to retry.
                    resume(.failure(SMBError.connectionFailed(err.localizedDescription)))
                default:
                    break
                }
            }

            conn.start(queue: .global(qos: .userInitiated))
        }
    }

    private func rawSend(_ conn: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: SMBError.connectionFailed(error.localizedDescription))
                } else {
                    continuation.resume(returning: ())
                }
            })
        }
    }

    /// Read exactly `length` bytes from the connection.
    ///
    /// NWConnection may deliver data in chunks, so we loop until we have
    /// everything or the peer closes the connection.
    private func rawReceive(_ conn: NWConnection, length: Int) async throws -> Data {
        var collected = Data()
        collected.reserveCapacity(length)

        while collected.count < length {
            let remaining = length - collected.count
            let chunk = try await receiveChunk(conn, minimum: 1, maximum: remaining)
            if chunk.isEmpty {
                throw SMBError.connectionLost
            }
            collected.append(chunk)
        }
        return collected
    }

    private func receiveChunk(_ conn: NWConnection, minimum: Int, maximum: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            conn.receive(minimumIncompleteLength: minimum, maximumLength: maximum) { data, _, isComplete, error in
                if let error = error {
                    continuation.resume(throwing: SMBError.connectionFailed(error.localizedDescription))
                    return
                }
                if let data = data, !data.isEmpty {
                    continuation.resume(returning: data)
                    return
                }
                if isComplete {
                    continuation.resume(returning: Data())
                    return
                }
                // No data and not complete — shouldn't normally happen, but
                // return empty to let the caller decide.
                continuation.resume(returning: Data())
            }
        }
    }

    // MARK: - Timeout helper

    /// Race an async operation against a timeout. Throws `error` if the
    /// timeout expires before the operation completes.
    private func withTimeout<T: Sendable>(
        seconds: TimeInterval,
        error: SMBError,
        operation: @Sendable @escaping () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                let nanos = UInt64(seconds * 1_000_000_000)
                try await Task.sleep(nanoseconds: nanos)
                throw error
            }
            guard let result = try await group.next() else {
                throw SMBError.connectionLost
            }
            group.cancelAll()
            return result
        }
    }
}
