//
//  SMBStreamingProxy.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Local HTTP/1.1 proxy that lets AVPlayer stream files from an SMB share.
//
// AVPlayer can only read from HTTP(S) URLs or local files — it has no
// idea what SMB is. This proxy bridges the gap:
//
//   AVPlayer ──HTTP GET /stream?token=…──▶  SMBStreamingProxy
//                                              │
//                                              ├─ parses Range header
//                                              ├─ calls SMBClient.contents(…)
//                                              └─ returns HTTP 206 + bytes
//
// The proxy binds to 127.0.0.1 on a random high port, so nothing outside
// the device can reach it. Tokens are opaque and scoped to this process.
//
// HTTP is intentionally minimal:
//   * Only GET and HEAD
//   * Only a single `Range: bytes=start-end` header
//   * 200 OK for whole-file, 206 Partial Content for ranges
//   * 404 for unknown tokens, 416 for bad ranges, 500 on I/O failure

import Foundation
import Network

/// A local HTTP proxy that serves ranged reads from an `SMBClient`.
///
/// One proxy instance is shared by one `SMBClient`. Call `start()` before
/// generating URLs, and `stop()` when tearing down the client.
public actor SMBStreamingProxy {

    // MARK: State

    /// Back-reference to the client we forward reads to. Held weakly so
    /// the proxy never keeps the client alive and never dereferences a
    /// stale client if the owner was deallocated.
    private weak var client: SMBClient?

    private var listener: NWListener?
    private var boundPort: UInt16 = 0
    private var isRunning: Bool = false

    /// token → SMB path (relative, using backslashes) mapping.
    /// Tokens are opaque UUIDs so the URL never leaks the real file path.
    private var tokenTable: [String: String] = [:]
    /// Reverse map so repeated `url(forPath:)` calls reuse the same token.
    private var pathToToken: [String: String] = [:]

    // MARK: Init

    public init(client: SMBClient) {
        self.client = client
    }

    // MARK: - Lifecycle

    /// Start listening on an ephemeral loopback port.
    public func start() async throws {
        if isRunning { return }

        let params = NWParameters.tcp
        // NOTE: `requiredInterfaceType = .loopback` was removed. On the tvOS
        // simulator the loopback interface isn't enumerated the same way as on
        // device, so a listener that *requires* it binds to a port but never
        // fires `newConnectionHandler` — AVPlayer's connection to 127.0.0.1 is
        // reset (NSURLError -1005). `acceptLocalOnly` still keeps it local.
        params.acceptLocalOnly = true
        params.allowLocalEndpointReuse = true

        let listener: NWListener
        do {
            // Port 0 → OS picks an available ephemeral port.
            listener = try NWListener(using: params, on: .any)
        } catch {
            throw SMBError.connectionFailed("proxy listener: \(error.localizedDescription)")
        }

        listener.newConnectionHandler = { [weak self] connection in
            guard let self = self else { connection.cancel(); return }
            connection.start(queue: .global(qos: .userInitiated))
            Task { await self.handle(connection) }
        }

        // Start the listener and wait for `.ready` so we can read the port.
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // ResumeOnce lets us safely gate resumption from a Sendable closure.
            let gate = ResumeOnce()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if gate.fire() {
                        continuation.resume(returning: ())
                    }
                case .failed(let err):
                    if gate.fire() {
                        continuation.resume(throwing: SMBError.connectionFailed("proxy ready: \(err.localizedDescription)"))
                    }
                default:
                    break
                }
            }
            listener.start(queue: .global(qos: .userInitiated))
        }

        self.boundPort = listener.port?.rawValue ?? 0
        self.listener = listener
        self.isRunning = true
    }

    /// Stop listening and drop all tokens.
    public func stop() async {
        listener?.cancel()
        listener = nil
        isRunning = false
        tokenTable.removeAll()
        pathToToken.removeAll()
        boundPort = 0
    }

    // MARK: - URL minting

    /// Mint (or return an existing) streaming URL for a file on the share.
    /// The URL is stable for the lifetime of the proxy.
    public func url(forPath path: String) async throws -> URL {
        guard isRunning, boundPort > 0 else {
            throw SMBError.notConnected
        }

        if let existing = pathToToken[path],
           let url = buildURL(token: existing) {
            return url
        }

        let token = UUID().uuidString.lowercased()
        tokenTable[token]   = path
        pathToToken[path]   = token

        guard let url = buildURL(token: token) else {
            throw SMBError.connectionFailed("proxy: failed to build URL")
        }
        return url
    }

    private func buildURL(token: String) -> URL? {
        URL(string: "http://127.0.0.1:\(boundPort)/stream/\(token)")
    }

    // MARK: - HTTP handling

    private func handle(_ connection: NWConnection) async {
        // Read the request headers (until CRLF CRLF).
        let requestData = await Self.readRequestHeaders(connection)
        guard let requestString = String(data: requestData, encoding: .utf8) else {
            await Self.sendResponse(connection, status: "400 Bad Request", headers: [:])
            connection.cancel()
            return
        }

        guard let request = ParsedRequest.parse(requestString) else {
            await Self.sendResponse(connection, status: "400 Bad Request", headers: [:])
            connection.cancel()
            return
        }

        guard request.method == "GET" || request.method == "HEAD" else {
            await Self.sendResponse(
                connection,
                status: "405 Method Not Allowed",
                headers: ["Allow": "GET, HEAD"]
            )
            connection.cancel()
            return
        }

        // Extract token.
        guard let token = Self.extractToken(from: request.path),
              let smbPath = tokenTable[token] else {
            await Self.sendResponse(connection, status: "404 Not Found", headers: [:])
            connection.cancel()
            return
        }

        // Get total file size (needed for Content-Length / Content-Range).
        guard let client = client else {
            await Self.sendResponse(connection, status: "503 Service Unavailable", headers: [:])
            connection.cancel()
            return
        }
        let totalSize: UInt64
        do {
            totalSize = try await client.internalFileSize(at: smbPath)
        } catch {
            await Self.sendResponse(
                connection,
                status: "500 Internal Server Error",
                headers: [:]
            )
            connection.cancel()
            return
        }

        // Parse Range header (optional).
        let (start, end, isRanged): (UInt64, UInt64, Bool)
        if let rangeHeader = request.headers["range"],
           let parsed = Self.parseRangeHeader(rangeHeader, fileSize: totalSize) {
            start     = parsed.lowerBound
            end       = parsed.upperBound   // exclusive
            isRanged  = true
        } else {
            start    = 0
            end      = totalSize
            isRanged = false
        }

        // Guard against malformed or unsatisfiable ranges.
        if start >= totalSize || end > totalSize || start > end {
            await Self.sendResponse(
                connection,
                status: "416 Range Not Satisfiable",
                headers: [
                    "Content-Range": "bytes */\(totalSize)",
                    "Content-Length": "0",
                ]
            )
            connection.cancel()
            return
        }

        let contentLength = end - start
        var headers: [String: String] = [
            "Accept-Ranges":  "bytes",
            "Content-Length": "\(contentLength)",
            "Content-Type":   Self.guessContentType(for: smbPath),
            "Connection":     "close",
        ]
        if isRanged {
            headers["Content-Range"] = "bytes \(start)-\(end - 1)/\(totalSize)"
        }

        let statusLine = isRanged ? "206 Partial Content" : "200 OK"

        // Send headers first.
        await Self.sendResponseHeaders(connection, status: statusLine, headers: headers)

        // HEAD → we're done after headers.
        if request.method == "HEAD" {
            connection.cancel()
            return
        }

        // GET → stream bytes in chunks so we never buffer the whole file.
        await streamBody(connection, smbPath: smbPath, range: start..<end)
        connection.cancel()
    }

    /// Pump the requested byte range from SMB to the HTTP connection using a
    /// read-ahead **producer → consumer** pipeline.
    ///
    /// The old implementation read a 512 KiB chunk, then sent it, then read the
    /// next — strictly serial, so while a chunk was being pushed to AVPlayer
    /// nothing was being read from SMB and vice-versa. Half the wall-clock was
    /// wasted, and 512 KiB chunks doubled the SMB round-trip count vs the
    /// server's `maxReadSize`.
    ///
    /// Now:
    ///   * a **producer** task calls `client.streamRange`, which opens the SMB2
    ///     handle ONCE and reads `streamingReadSize()`-sized chunks back-to-back
    ///     (removes the per-chunk CREATE/CLOSE round-trips, and reads at the
    ///     negotiated max size — Lever 1);
    ///   * each chunk is handed to a bounded queue that applies back-pressure
    ///     (so we never buffer the whole file);
    ///   * a **consumer** — this function's own loop — drains the queue to the
    ///     socket. The next SMB read overlaps the current socket send (Lever 2).
    ///
    /// On any socket send failure we cancel the producer and finish the queue so
    /// a producer parked on back-pressure wakes and unwinds (closing the SMB
    /// handle). We then await the producer so no SMB read is left in flight when
    /// the caller cancels the connection.
    private func streamBody(
        _ connection: NWConnection,
        smbPath: String,
        range: Range<UInt64>
    ) async {
        guard let client = client else { return }

        // Chunk = negotiated maxReadSize (Lever 1). Keep a few chunks in flight
        // so a read always overlaps a send (Lever 2). Reads are serialized by
        // SMBSession's io-mutex, so a small depth already keeps the consumer
        // fed; cap the in-flight bytes (~8 MiB) to bound memory on tvOS.
        let chunkSize = await client.streamingReadSize()
        let targetInFlight = 8 * 1024 * 1024
        let prefetch = max(2, min(4, targetInFlight / max(chunkSize, 1)))
        let queue = BoundedDataQueue(capacity: prefetch)

        // Producer: open once, read ahead into the bounded queue. `enqueue`
        // returns false once the consumer has finished the queue (client gone),
        // which stops `streamRange` early.
        let producer = Task {
            do {
                try await client.streamRange(atPath: smbPath, range: range) { slice in
                    await queue.enqueue(slice)
                }
            } catch {
                // Headers are already on the wire; nothing to do but stop.
            }
            await queue.finish()
        }

        // Consumer: drain to the socket. A send failure means AVPlayer hung up.
        while let slice = await queue.dequeue() {
            do {
                try await Self.rawSend(connection, data: slice)
            } catch {
                break
            }
        }

        // Unwind the producer: cancel it, then finish the queue so a producer
        // parked on a full queue wakes, sees the queue is closed, and returns.
        producer.cancel()
        await queue.finish()
        _ = await producer.value
    }

    // MARK: - Request parsing helpers

    /// Pulls bytes from the socket until we see the end-of-headers marker.
    private static func readRequestHeaders(_ connection: NWConnection) async -> Data {
        var buffer = Data()
        let marker = Data("\r\n\r\n".utf8)
        let maxHeaderBytes = 16 * 1024  // more than enough for any browser

        while buffer.count < maxHeaderBytes {
            let chunk: Data
            do {
                chunk = try await receiveChunk(connection, maximum: 4096)
            } catch {
                return buffer
            }
            if chunk.isEmpty { return buffer }
            buffer.append(chunk)
            if buffer.range(of: marker) != nil { return buffer }
        }
        return buffer
    }

    private static func receiveChunk(_ connection: NWConnection, maximum: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { data, _, isComplete, error in
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
                continuation.resume(returning: Data())
            }
        }
    }

    private static func rawSend(_ connection: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: SMBError.connectionFailed(error.localizedDescription))
                } else {
                    continuation.resume(returning: ())
                }
            })
        }
    }

    /// Build a simple HTTP response (status line + headers + empty body)
    /// and send it on the given connection.
    private static func sendResponse(
        _ connection: NWConnection,
        status: String,
        headers: [String: String]
    ) async {
        await sendResponseHeaders(connection, status: status, headers: headers)
    }

    private static func sendResponseHeaders(
        _ connection: NWConnection,
        status: String,
        headers: [String: String]
    ) async {
        var resp = "HTTP/1.1 \(status)\r\n"
        for (k, v) in headers {
            resp += "\(k): \(v)\r\n"
        }
        resp += "\r\n"
        let data = Data(resp.utf8)
        try? await rawSend(connection, data: data)
    }

    // MARK: - URL path helpers

    /// Extract the token from "/stream/<token>".
    static func extractToken(from path: String) -> String? {
        let prefix = "/stream/"
        guard path.hasPrefix(prefix) else { return nil }
        var token = String(path.dropFirst(prefix.count))
        if let q = token.firstIndex(of: "?") {
            token = String(token[..<q])
        }
        if token.isEmpty { return nil }
        return token
    }

    // MARK: - Range header parser

    /// Parse an HTTP/1.1 `Range: bytes=<first>-<last>` header. Supports:
    ///   * bytes=0-           → 0 ..< fileSize
    ///   * bytes=500-999      → 500 ..< 1000
    ///   * bytes=-500         → last 500 bytes
    /// Returns a half-open range `[start ..< end)`.
    static func parseRangeHeader(_ header: String, fileSize: UInt64) -> Range<UInt64>? {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("bytes=") else { return nil }
        let spec = trimmed.dropFirst("bytes=".count)

        // Only take the first range if multiple are given.
        let firstRangeSpec = spec.split(separator: ",").first.map(String.init) ?? String(spec)
        let parts = firstRangeSpec.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }

        let firstStr = String(parts[0]).trimmingCharacters(in: .whitespaces)
        let lastStr  = String(parts[1]).trimmingCharacters(in: .whitespaces)

        if firstStr.isEmpty {
            // Suffix range: last N bytes.
            guard let suffix = UInt64(lastStr), suffix > 0 else { return nil }
            let start = fileSize > suffix ? fileSize - suffix : 0
            return start..<fileSize
        } else if lastStr.isEmpty {
            // Open-ended: bytes=N-
            guard let start = UInt64(firstStr), start < fileSize else { return nil }
            return start..<fileSize
        } else {
            guard let start = UInt64(firstStr),
                  let last  = UInt64(lastStr),
                  start <= last else {
                return nil
            }
            let end = min(last + 1, fileSize)
            if start >= fileSize { return nil }
            return start..<end
        }
    }

    // MARK: - Content-Type guessing

    /// Return a reasonable Content-Type based on the file extension.
    /// Only the media types AVPlayer actually cares about are enumerated;
    /// everything else becomes "application/octet-stream".
    static func guessContentType(for path: String) -> String {
        let ext = (path as NSString).pathExtension.lowercased()
        switch ext {
        case "mp4", "m4v":   return "video/mp4"
        case "mkv":          return "video/x-matroska"
        case "mov":          return "video/quicktime"
        case "avi":          return "video/x-msvideo"
        case "webm":         return "video/webm"
        case "mp3":          return "audio/mpeg"
        case "aac", "m4a":   return "audio/aac"
        case "flac":         return "audio/flac"
        case "wav":          return "audio/wav"
        case "jpg", "jpeg":  return "image/jpeg"
        case "png":          return "image/png"
        case "gif":          return "image/gif"
        case "heic":         return "image/heic"
        case "srt":          return "application/x-subrip"
        case "vtt":          return "text/vtt"
        default:             return "application/octet-stream"
        }
    }
}

// MARK: - Parsed HTTP request

extension SMBStreamingProxy {

    struct ParsedRequest {
        let method:  String
        let path:    String
        let version: String
        let headers: [String: String]   // header names lowercased

        static func parse(_ raw: String) -> ParsedRequest? {
            // Split the request at the first CRLF CRLF to get just the
            // request line + headers.
            let headerBlock: String
            if let range = raw.range(of: "\r\n\r\n") {
                headerBlock = String(raw[..<range.lowerBound])
            } else {
                headerBlock = raw
            }
            let lines = headerBlock.components(separatedBy: "\r\n")
            guard let requestLine = lines.first else { return nil }

            let parts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count == 3 else { return nil }
            let method  = String(parts[0])
            let path    = String(parts[1])
            let version = String(parts[2])

            var headers: [String: String] = [:]
            for line in lines.dropFirst() where !line.isEmpty {
                guard let colon = line.firstIndex(of: ":") else { continue }
                let name  = String(line[..<colon]).lowercased()
                var value = String(line[line.index(after: colon)...])
                value = value.trimmingCharacters(in: .whitespaces)
                headers[name] = value
            }

            return ParsedRequest(method: method, path: path, version: version, headers: headers)
        }
    }
}

// MARK: - Bounded async queue (producer/consumer back-pressure)

/// A bounded FIFO of `Data` buffers connecting exactly one producer to one
/// consumer, with async back-pressure in both directions:
///   * `enqueue` suspends while the queue is full (so the producer can't read
///     the whole file into memory — it stalls until the consumer drains);
///   * `dequeue` suspends while the queue is empty (so the consumer waits for
///     the next chunk instead of spinning);
///   * `finish` marks end-of-stream and wakes every waiter, so neither side can
///     deadlock once the other stops.
///
/// Sized for the single-producer/single-consumer streaming path — it does not
/// try to be a general multi-writer queue.
actor BoundedDataQueue {
    private let capacity: Int
    private var buffer: [Data] = []
    private var finished = false
    private var spaceWaiters: [CheckedContinuation<Void, Never>] = []
    private var itemWaiters:  [CheckedContinuation<Data?, Never>] = []

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    /// Append `data`, suspending while the queue is full. Returns `false` if the
    /// queue was finished (consumer gone) — the caller should stop producing.
    @discardableResult
    func enqueue(_ data: Data) async -> Bool {
        // Wait for space. Re-check after each wake: another actor hop may have
        // refilled the buffer or finished the stream.
        while buffer.count >= capacity && !finished {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                spaceWaiters.append(c)
            }
        }
        if finished { return false }

        // Hand off directly to a parked consumer if one is waiting; otherwise
        // buffer it. (A consumer only parks when the buffer is empty, so a
        // direct hand-off never violates the capacity bound.)
        if !itemWaiters.isEmpty {
            itemWaiters.removeFirst().resume(returning: data)
        } else {
            buffer.append(data)
        }
        return true
    }

    /// Remove and return the oldest buffered chunk, suspending while empty.
    /// Returns `nil` once the queue is finished AND drained.
    func dequeue() async -> Data? {
        if !buffer.isEmpty {
            let next = buffer.removeFirst()
            // Wake one producer waiting for space.
            if !spaceWaiters.isEmpty {
                spaceWaiters.removeFirst().resume()
            }
            return next
        }
        if finished { return nil }
        return await withCheckedContinuation { (c: CheckedContinuation<Data?, Never>) in
            itemWaiters.append(c)
        }
    }

    /// Signal end-of-stream and wake all waiters. Idempotent.
    func finish() {
        guard !finished else { return }
        finished = true
        for c in itemWaiters { c.resume(returning: nil) }
        itemWaiters.removeAll()
        for c in spaceWaiters { c.resume() }
        spaceWaiters.removeAll()
    }
}
