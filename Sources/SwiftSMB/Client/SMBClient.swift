//
//  SMBClient.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// High-level public API for SwiftSMB.
//
// `SMBClient` is what apps like a media player import and use:
//   let client = SMBClient(host: "192.168.1.100")
//   try await client.connectShare("Videos", credentials: .init(user: "me", password: "pw"))
//   let files = try await client.listDirectory("Movies")
//   let size  = try await client.fileSize(at: "Movies/film.mkv")
//   let all   = try await client.contents(atPath: "Movies/film.mkv")
//   let bytes = try await client.contents(atPath: "Movies/film.mkv", range: 0..<1024)
//   let url   = try await client.url(ofItem: "Movies/film.mkv")   // streaming URL
//
// SMBFile overloads let you skip the path string:
//   let photo = files.first { $0.fileExtension == "jpg" }!
//   let data  = try await client.contents(of: photo)
//   let thumb = try await client.contents(of: photo, range: 0..<65536)
//
// Internally it wraps an `SMBSession` and calls the low-level SMB2
// builders/parsers. Paths use '/' as the separator; the client normalizes
// them to '\' for the wire.

import Foundation

/// Thin high-level facade around `SMBSession`.
///
/// `SMBClient` is an actor so it's safe to share across concurrent callers.
/// Every public method is `async throws`.
public actor SMBClient {

    // MARK: State

    private let session: SMBSession

    /// Kept so we can launch a streaming proxy later (Step 7). The client
    /// itself doesn't use it, but `url(ofItem:)` does.
    private var streamingProxy: SMBStreamingProxy?

    /// In-flight proxy-start task. Coalesces concurrent `url(ofItem:)` callers
    /// onto a SINGLE proxy. Without this, the actor-reentrancy gap at
    /// `await proxy.start()` lets N concurrent callers each create+start their
    /// own proxy+listener; all but the last get deallocated, cancelling their
    /// listeners, so the URLs they minted point at dead ports (→ connection
    /// reset / NSURLError -1005 in AVPlayer).
    private var proxyStartTask: Task<SMBStreamingProxy, Error>?

    // MARK: Init

    public init(session: SMBSession) {
        self.session = session
    }

    /// - Parameter maxInFlightRequests: request-pipelining width for the
    ///   underlying session. Defaults to 1 (serial). Raise it only for a client
    ///   dedicated to bulk transfer (e.g. the direct-play streaming path);
    ///   leave it at 1 for latency-sensitive `contents(range:)` readers.
    public init(host: String, port: UInt16 = 445, maxInFlightRequests: Int = 1) {
        self.session = SMBSession(host: host, port: port, maxInFlightRequests: maxInFlightRequests)
    }

    /// Opt this client's session into (or out of) request pipelining.
    /// See ``SMBSession/setMaxInFlightRequests(_:)``. `n` = max SMB2 requests in
    /// flight at once; 1 = serial (default). Call BEFORE `connectShare` — it's
    /// snapshotted at connect time.
    public func setMaxInFlightRequests(_ n: Int) async {
        await session.setMaxInFlightRequests(n)
    }

    // MARK: - Connection lifecycle

    /// Connect to the server, authenticate with NTLMv2, and bind to a share.
    ///
    /// - `share`: the share name, e.g. "Videos" or "\\\\server\\Videos".
    ///   A bare name is interpreted relative to the session's host.
    public func connectShare(
        _ share: String,
        credentials: SMBCredentials
    ) async throws {
        let fullPath: String
        if share.hasPrefix("\\\\") || share.hasPrefix("//") {
            fullPath = share.replacingOccurrences(of: "/", with: "\\")
        } else {
            // Build a real UNC `\\HOST\share`. Earlier versions used an
            // empty host (`\\\share`) hoping the server would substitute
            // its own name, but Samba 4.x and TrueNAS Scale reject that
            // form with STATUS_INVALID_PARAMETER on TREE_CONNECT. Modern
            // Samba parses the UNC strictly and requires a non-empty
            // hostname.
            let h = await session.currentHost
            fullPath = "\\\\\(h)\\\(share)"
        }
        try await session.connectShare(fullPath, credentials: credentials)
    }

    /// Close the tree, log off, and tear down the TCP connection.
    public func disconnect() async {
        await streamingProxy?.stop()
        streamingProxy = nil
        await session.disconnect()
    }

    // MARK: - Reconnect

    /// Attempt to transparently re-establish the session using the
    /// credentials and share path from the last `connectShare`.
    /// Returns `true` if the reconnect succeeded.
    public func reconnect() async -> Bool {
        await session.reconnect()
    }

    // MARK: - Directory listing

    /// List the contents of a directory relative to the share root.
    ///
    /// Passing "" or "/" lists the share root. Paths use forward slashes.
    public func listDirectory(_ path: String = "") async throws -> [SMBFile] {
        let normalized = Self.normalize(path)
        let displayParent = normalized.replacingOccurrences(of: "\\", with: "/")

        return try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.openDirectory(path: normalized)
        ) { fileId in
            var results: [SMBFile] = []
            var first = true

            // Loop QUERY_DIRECTORY calls until the server signals NO_MORE_FILES.
            while true {
                let flags: UInt8 = first ? SMB2QueryDirectoryRequest.Flags.restart : 0
                first = false

                let outputBufferLength: UInt32 = 65536
                let body = SMB2QueryDirectoryRequest.build(
                    fileId:  fileId,
                    pattern: "*",
                    flags:   flags,
                    outputBufferLength: outputBufferLength
                )
                let (header, respBody) = try await self.session.sendRequest(
                    command: SMB2Command.queryDirectory,
                    body: body,
                    payloadSize: Int(outputBufferLength)
                )

                if header.status == NTStatus.noMoreFiles { break }

                if !header.isSuccess {
                    throw Self.mapNTStatus(header.status, path: normalized)
                }

                let parsed = try SMB2QueryDirectoryResponse.parse(respBody)
                let entries = FileBothDirectoryInfo.parseAll(from: parsed.outputBuffer)
                for entry in entries {
                    // Skip the usual "." and ".." entries.
                    if entry.fileName == "." || entry.fileName == ".." { continue }
                    results.append(SMBFile.from(entry, parentPath: displayParent))
                }
            }

            return results
        }
    }

    // MARK: - File metadata

    /// Return the size of a file in bytes.
    public func fileSize(at path: String) async throws -> UInt64 {
        let normalized = Self.normalize(path)

        return try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.openFile(path: normalized)
        ) { fileId in
            // Ask for FILE_STANDARD_INFORMATION — the cheapest way to get size.
            let body = SMB2QueryInfoRequest.build(
                fileId: fileId,
                infoType: SMB2InfoType.file,
                fileInfoClass: SMB2FileInformationClass.fileStandardInformation
            )
            let (header, respBody) = try await self.session.sendRequest(
                command: SMB2Command.queryInfo,
                body: body
            )
            guard header.isSuccess else {
                throw Self.mapNTStatus(header.status, path: normalized)
            }
            let parsed = try SMB2QueryInfoResponse.parse(respBody)
            let info   = try FileStandardInfo.parse(parsed.outputBuffer)
            return info.endOfFile
        }
    }

    // MARK: - File reading

    /// Read the entire contents of a file into memory.
    ///
    /// For large files (RAW photos, archives), prefer ``contents(atPath:range:)``
    /// to avoid loading tens of megabytes in one shot.
    public func contents(atPath path: String) async throws -> Data {
        let size = try await fileSize(at: path)
        guard size > 0 else { return Data() }
        return try await contents(atPath: path, range: 0..<size)
    }

    /// Read a byte range from a file.
    ///
    /// - `path`: file path relative to the share root.
    /// - `range`: half-open byte range `[start ..< end)`. Must be non-empty.
    ///
    /// Internally splits the request into chunks no larger than
    /// `maxReadSize` advertised by the server and concatenates the result.
    public func contents(
        atPath path: String,
        range: Range<UInt64>
    ) async throws -> Data {
        guard !range.isEmpty else { return Data() }
        let normalized = Self.normalize(path)

        // Same windowed engine as streaming: parallel reads (in order) when
        // pipelining is on, single-in-flight otherwise. Routing big reads
        // through `windowedRead`/`reserveCredits` (rather than the plain gate)
        // also keeps large charges off the optimistic credit path.
        let pipelining = await session.isPipelining
        let width = pipelining ? await session.readWriteConcurrency() : 1
        let chunk = pipelining
            ? min(Int(await chunkReadSize()), 1 << 20)
            : Int(await chunkReadSize())

        return try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.openFile(path: normalized)
        ) { fileId in
            var collected = Data()
            collected.reserveCapacity(Int(range.upperBound - range.lowerBound))
            try await self.windowedRead(
                fileId: fileId, path: normalized, range: range,
                chunk: chunk, width: width
            ) { slice in
                collected.append(slice)
                return true
            }
            return collected
        }
    }

    // MARK: - File writing

    /// Write data to a file at the given path, creating it if needed.
    /// Overwrites existing content starting at `offset`.
    public func writeData(
        _ data: Data,
        toPath path: String,
        offset: UInt64 = 0
    ) async throws {
        let normalized = Self.normalize(path)
        let chunkSize = await chunkWriteSize()

        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.build(
                path: normalized,
                desiredAccess: SMB2AccessMask.genericWrite | SMB2AccessMask.fileWriteData | SMB2AccessMask.fileWriteAttributes,
                shareAccess: SMB2ShareAccess.read,
                createDisposition: SMB2CreateDisposition.openIf,
                createOptions: SMB2CreateOptions.nonDirectoryFile
            )
        ) { fileId in
            let width = await self.session.isPipelining
                ? await self.session.readWriteConcurrency() : 1
            try await self.windowedWrite(
                fileId: fileId, path: normalized, baseOffset: offset,
                data: data, chunk: Int(chunkSize), width: width
            )
        }
    }

    /// Upload a file from local Data, creating or overwriting the remote file.
    public func uploadFile(
        _ data: Data,
        toPath path: String
    ) async throws {
        let normalized = Self.normalize(path)

        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.build(
                path: normalized,
                desiredAccess: SMB2AccessMask.genericWrite | SMB2AccessMask.fileWriteData | SMB2AccessMask.fileWriteAttributes,
                shareAccess: 0, // exclusive access for upload
                createDisposition: SMB2CreateDisposition.overwriteIf,
                createOptions: SMB2CreateOptions.nonDirectoryFile
            )
        ) { fileId in
            let chunkSize = await self.chunkWriteSize()
            let width = await self.session.isPipelining
                ? await self.session.readWriteConcurrency() : 1
            try await self.windowedWrite(
                fileId: fileId, path: normalized, baseOffset: 0,
                data: data, chunk: Int(chunkSize), width: width
            )
        }
    }

    /// Write `data` to an open handle starting at `baseOffset`. With pipelining
    /// on, up to `width` SMB2 WRITEs run concurrently (writes to distinct
    /// offsets are independent, so order doesn't matter); otherwise it's the
    /// original single-in-flight loop.
    private func windowedWrite(
        fileId: SMB2FileId,
        path: String,
        baseOffset: UInt64,
        data: Data,
        chunk: Int,
        width: Int
    ) async throws {
        let total = data.count
        guard total > 0 else { return }
        let step = max(1, chunk)
        let pipelining = await session.isPipelining

        // ── Serial path ─────────────────────────────────────────────────
        if !pipelining || width <= 1 {
            var pos = 0
            while pos < total {
                let affordable = await session.affordablePayloadLength(desired: step)
                let end = min(pos + max(1, affordable), total)
                let slice = data.subdata(in: data.startIndex + pos ..< data.startIndex + end)
                let body = SMB2WriteRequest.build(fileId: fileId, offset: baseOffset + UInt64(pos), data: slice)
                let (header, respBody) = try await session.sendRequest(
                    command: SMB2Command.write, body: body, payloadSize: slice.count
                )
                guard header.isSuccess else { throw Self.mapNTStatus(header.status, path: path) }
                let parsed = try SMB2WriteResponse.parse(respBody)
                guard parsed.count > 0 else { throw Self.mapNTStatus(header.status, path: path) }
                pos += Int(parsed.count)
            }
            return
        }

        // ── Pipelined path: up to `width` concurrent write slices ────────
        var starts: [Int] = []
        var s = 0
        while s < total { starts.append(s); s += step }
        var idx = 0
        var inflight: [Task<Void, Error>] = []
        inflight.reserveCapacity(width)

        func spawn() {
            guard idx < starts.count else { return }
            let start = starts[idx]; idx += 1
            let end = min(start + step, total)
            let slice = data.subdata(in: data.startIndex + start ..< data.startIndex + end)
            let fileOffset = baseOffset + UInt64(start)
            inflight.append(Task { [weak self] in
                guard let self = self else { return }
                try await self.pipelinedWriteSlice(fileId: fileId, offset: fileOffset, slice: slice, path: path)
            })
        }

        func drain() async {
            for t in inflight { t.cancel() }
            for t in inflight { _ = try? await t.value }
            inflight.removeAll()
        }

        for _ in 0..<max(1, width) { spawn() }
        while !inflight.isEmpty {
            do {
                try await inflight.removeFirst().value
            } catch {
                await drain()
                throw error
            }
            spawn()
        }
    }

    /// Write an entire slice at `offset`, issuing pipelined SMB2 WRITEs sized to
    /// affordable credits and looping over any partial writes.
    private func pipelinedWriteSlice(
        fileId: SMB2FileId,
        offset: UInt64,
        slice: Data,
        path: String
    ) async throws {
        let n = slice.count
        var pos = 0
        while pos < n {
            let remaining = n - pos
            let desiredCharge = SMBSession.creditCharge(forPayloadLength: remaining)
            let take = try await session.reserveCredits(upTo: desiredCharge)
            let len = min(remaining, Int(take) * 65536)
            let actualCharge = SMBSession.creditCharge(forPayloadLength: len)
            if take > actualCharge { await session.releaseCredits(take - actualCharge) }

            let chunkData = slice.subdata(in: slice.startIndex + pos ..< slice.startIndex + pos + len)
            let body = SMB2WriteRequest.build(fileId: fileId, offset: offset + UInt64(pos), data: chunkData)
            let (header, respBody) = try await session.sendPipelined(
                command: SMB2Command.write, body: body, charge: actualCharge
            )
            guard header.isSuccess else { throw Self.mapNTStatus(header.status, path: path) }
            let parsed = try SMB2WriteResponse.parse(respBody)
            guard parsed.count > 0 else { throw Self.mapNTStatus(header.status, path: path) }
            pos += Int(parsed.count)
        }
    }

    // MARK: - File management

    /// Create a directory at the given path. Parent directories must exist.
    public func createDirectory(_ path: String) async throws {
        let normalized = Self.normalize(path)
        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.build(
                path: normalized,
                desiredAccess: SMB2AccessMask.fileReadAttributes,
                fileAttributes: SMB2FileAttributes.directory,
                shareAccess: SMB2ShareAccess.read,
                createDisposition: SMB2CreateDisposition.create,
                createOptions: SMB2CreateOptions.directoryFile
            )
        ) { _ in
            // Directory created; handle will be closed by withFileHandle.
        }
    }

    /// Rename or move a file/directory from `sourcePath` to `destinationPath`.
    /// Both paths are relative to the share root.
    public func rename(
        atPath sourcePath: String,
        toPath destinationPath: String,
        replaceIfExists: Bool = false
    ) async throws {
        let normalizedSrc = Self.normalize(sourcePath)
        let normalizedDst = Self.normalize(destinationPath)

        try await withFileHandle(
            path: normalizedSrc,
            body: SMB2CreateRequest.build(
                path: normalizedSrc,
                desiredAccess: SMB2AccessMask.delete | SMB2AccessMask.fileWriteAttributes,
                shareAccess: SMB2ShareAccess.read | SMB2ShareAccess.write | SMB2ShareAccess.delete,
                createDisposition: SMB2CreateDisposition.open,
                createOptions: 0
            )
        ) { fileId in
            let renameBuffer = FileRenameInfo.build(
                newName: normalizedDst,
                replaceIfExists: replaceIfExists
            )
            let body = SMB2SetInfoRequest.build(
                fileId: fileId,
                fileInfoClass: SMB2FileInformationClass.fileRenameInformation,
                buffer: renameBuffer
            )
            let (header, _) = try await self.session.sendRequest(
                command: SMB2Command.setInfo,
                body: body
            )
            guard header.isSuccess else {
                throw Self.mapNTStatus(header.status, path: normalizedSrc)
            }
        }
    }

    /// Delete a file at the given path.
    public func deleteFile(atPath path: String) async throws {
        let normalized = Self.normalize(path)

        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.build(
                path: normalized,
                desiredAccess: SMB2AccessMask.delete | SMB2AccessMask.fileReadAttributes,
                shareAccess: SMB2ShareAccess.delete,
                createDisposition: SMB2CreateDisposition.open,
                createOptions: SMB2CreateOptions.nonDirectoryFile
            )
        ) { fileId in
            let dispBuffer = FileDispositionInfo.build(deleteOnClose: true)
            let body = SMB2SetInfoRequest.build(
                fileId: fileId,
                fileInfoClass: SMB2FileInformationClass.fileDispositionInformation,
                buffer: dispBuffer
            )
            let (header, _) = try await self.session.sendRequest(
                command: SMB2Command.setInfo,
                body: body
            )
            guard header.isSuccess else {
                throw Self.mapNTStatus(header.status, path: normalized)
            }
        }
    }

    /// Delete a directory at the given path. The directory must be empty.
    public func deleteDirectory(atPath path: String) async throws {
        let normalized = Self.normalize(path)

        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.build(
                path: normalized,
                desiredAccess: SMB2AccessMask.delete | SMB2AccessMask.fileReadAttributes,
                shareAccess: SMB2ShareAccess.delete,
                createDisposition: SMB2CreateDisposition.open,
                createOptions: SMB2CreateOptions.directoryFile
            )
        ) { fileId in
            let dispBuffer = FileDispositionInfo.build(deleteOnClose: true)
            let body = SMB2SetInfoRequest.build(
                fileId: fileId,
                fileInfoClass: SMB2FileInformationClass.fileDispositionInformation,
                buffer: dispBuffer
            )
            let (header, _) = try await self.session.sendRequest(
                command: SMB2Command.setInfo,
                body: body
            )
            guard header.isSuccess else {
                throw Self.mapNTStatus(header.status, path: normalized)
            }
        }
    }

    // MARK: - Streaming URL

    /// Return an `http://127.0.0.1:<port>/...` URL that AVPlayer can read
    /// from to stream the given SMB file. The first call lazily starts a
    /// local HTTP proxy bound to loopback; subsequent calls reuse it.
    public func url(ofItem path: String) async throws -> URL {
        let normalized = Self.normalize(path)

        let proxy = try await ensureStreamingProxy()
        return try await proxy.url(forPath: normalized)
    }

    /// Returns the single shared streaming proxy, starting it exactly once even
    /// under concurrent callers (coalesced via `proxyStartTask`).
    private func ensureStreamingProxy() async throws -> SMBStreamingProxy {
        if let proxy = streamingProxy { return proxy }
        if let task = proxyStartTask { return try await task.value }

        let task = Task { () throws -> SMBStreamingProxy in
            let proxy = SMBStreamingProxy(client: self)
            try await proxy.start()
            return proxy
        }
        proxyStartTask = task
        do {
            let proxy = try await task.value
            streamingProxy = proxy
            proxyStartTask = nil
            return proxy
        } catch {
            proxyStartTask = nil
            throw error
        }
    }

    // MARK: - SMBFile convenience overloads

    /// Read the entire contents of a file described by an `SMBFile`.
    public func contents(of file: SMBFile) async throws -> Data {
        try await contents(atPath: file.path)
    }

    /// Read a byte range from a file described by an `SMBFile`.
    public func contents(
        of file: SMBFile,
        range: Range<UInt64>
    ) async throws -> Data {
        try await contents(atPath: file.path, range: range)
    }

    /// Return the size of a file described by an `SMBFile`.
    /// Uses the cached `size` from the directory listing when available,
    /// falling back to an on-the-wire QUERY_INFO if `size` is 0 and the
    /// file is not a directory (some servers return 0 for allocation-only files).
    public func fileSize(of file: SMBFile) async throws -> UInt64 {
        if file.size > 0 || file.isDirectory { return file.size }
        return try await fileSize(at: file.path)
    }

    /// Mint a streaming URL for AVPlayer from an `SMBFile`.
    public func url(of file: SMBFile) async throws -> URL {
        try await url(ofItem: file.path)
    }

    /// Write data to a file described by an SMBFile.
    public func writeData(_ data: Data, to file: SMBFile, offset: UInt64 = 0) async throws {
        try await writeData(data, toPath: file.path, offset: offset)
    }

    /// Upload data to a file described by an SMBFile (overwrites).
    public func uploadFile(_ data: Data, to file: SMBFile) async throws {
        try await uploadFile(data, toPath: file.path)
    }

    /// Rename a file described by an SMBFile.
    public func rename(_ file: SMBFile, toPath destinationPath: String, replaceIfExists: Bool = false) async throws {
        try await rename(atPath: file.path, toPath: destinationPath, replaceIfExists: replaceIfExists)
    }

    /// Delete a file described by an SMBFile.
    public func delete(_ file: SMBFile) async throws {
        if file.isDirectory {
            try await deleteDirectory(atPath: file.path)
        } else {
            try await deleteFile(atPath: file.path)
        }
    }

    // MARK: - Directory watching

    /// Create a directory watcher for the given path.
    /// The watcher uses SMB2 CHANGE_NOTIFY to receive real-time
    /// file system events without polling.
    public func watchDirectory(
        _ path: String,
        watchTree: Bool = true,
        filter: UInt32 = SMB2ChangeNotifyFilter.all,
        onChange: @escaping @Sendable ([SMBFileChange]) -> Void
    ) async throws -> SMBDirectoryWatcher {
        let watcher = SMBDirectoryWatcher(session: session)
        try await watcher.watch(path, watchTree: watchTree, filter: filter, onChange: onChange)
        return watcher
    }

    // MARK: - Package-internal helpers (used by SMBStreamingProxy)

    /// Expose file size (without needing to re-normalize). Used by the
    /// streaming proxy to satisfy HTTP HEAD / Content-Range responses.
    func internalFileSize(at path: String) async throws -> UInt64 {
        try await fileSize(at: path)
    }

    /// Expose ranged read for the streaming proxy.
    func internalContents(atPath path: String, range: Range<UInt64>) async throws -> Data {
        try await contents(atPath: path, range: range)
    }

    /// Preferred SMB2 READ size (bytes) for bulk streaming. Uses the full
    /// server-negotiated `maxReadSize` so a latency-bound link isn't throttled
    /// by tiny reads — the dominant throughput limiter when streaming video to
    /// AVPlayer. Clamped to `[512 KiB, 8 MiB]`: never smaller than the old
    /// 512 KiB behavior, never so large that one failed read wastes much
    /// bandwidth or that its credit charge (`ceil(size / 64 KiB)`) is
    /// unaffordable on a fresh session.
    func streamingReadSize() async -> Int {
        let negotiated = await session.negotiated
        let serverMax  = negotiated?.maxReadSize ?? (64 * 1024)
        let floor:   UInt32 = 512 * 1024
        let ceiling: UInt32 = 8 << 20
        return Int(min(max(serverMax, floor), ceiling))
    }

    /// Stream a byte range from a file, delivering it in order to `onSlice`.
    ///
    /// Unlike `contents(atPath:range:)` — which the proxy used to call once per
    /// chunk, paying a full CREATE + READ + CLOSE round-trip *per chunk* — this
    /// opens the SMB2 file handle **once** for the whole range, issues
    /// back-to-back READs against it, then closes. On a latency-bound path that
    /// removes ~2 of every ~3 round-trips (the per-chunk open/close), which is
    /// the single biggest lever for streaming throughput.
    ///
    /// Each READ is sized to ``streamingReadSize()`` (bigger reads → fewer
    /// round-trips) and capped to the credit-affordable length so we never
    /// exceed our SMB2 credit balance.
    ///
    /// `onSlice` receives each slice, in order, as it arrives; return `false`
    /// to stop early (e.g. the HTTP client hung up). The whole
    /// open→reads→close sequence holds the client's file-op lock, preserving
    /// the "one open handle per session at a time" invariant that some strict
    /// NAS servers enforce.
    func streamRange(
        atPath path: String,
        range: Range<UInt64>,
        onSlice: @Sendable (Data) async -> Bool
    ) async throws {
        guard !range.isEmpty else { return }
        let normalized = Self.normalize(path)

        // When pipelining is on we favour MANY 1 MiB reads in flight over a few
        // huge ones: 1 MiB costs 16 credits (comfortably affordable), and the
        // window width (not the read size) provides the throughput. When it's
        // off we fall back to the biggest single read the server allows.
        let pipelining = await session.isPipelining
        let width = pipelining ? await session.readWriteConcurrency() : 1
        let chunk = pipelining
            ? min(await streamingReadSize(), 1 << 20)
            : await streamingReadSize()

        try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.openFile(path: normalized)
        ) { fileId in
            try await self.windowedRead(
                fileId: fileId, path: normalized, range: range,
                chunk: chunk, width: width, onSlice: onSlice
            )
        }
    }

    /// Read `range` from an already-open handle and deliver each slice IN ORDER
    /// to `onSlice`. With pipelining on, up to `width` SMB2 READs are in flight
    /// at once (delivered in offset order via a sliding window); otherwise it's
    /// a single-in-flight loop identical to the serial behavior.
    private func windowedRead(
        fileId: SMB2FileId,
        path: String,
        range: Range<UInt64>,
        chunk: Int,
        width: Int,
        onSlice: (Data) async -> Bool
    ) async throws {
        let pipelining = await session.isPipelining

        // ── Serial path (pipelining off) ────────────────────────────────
        if !pipelining || width <= 1 {
            var offset = range.lowerBound
            while offset < range.upperBound {
                let remaining = range.upperBound - offset
                let desired   = min(UInt64(chunk), remaining)
                let affordable = await session.affordablePayloadLength(desired: Int(desired))
                let thisLen   = max(1, min(desired, UInt64(affordable)))
                let body = SMB2ReadRequest.build(fileId: fileId, offset: offset, length: UInt32(thisLen))
                let (header, respBody) = try await session.sendRequest(
                    command: SMB2Command.read, body: body, payloadSize: Int(thisLen)
                )
                if header.status == NTStatus.endOfFile { break }
                guard header.isSuccess else { throw Self.mapNTStatus(header.status, path: path) }
                let parsed = try SMB2ReadResponse.parse(respBody)
                if parsed.data.isEmpty { break }
                let keepGoing = await onSlice(parsed.data)
                offset += UInt64(parsed.data.count)
                if !keepGoing { break }
            }
            return
        }

        // ── Pipelined path: sliding window of concurrent reads ───────────
        // Offsets are pre-assigned assuming each window slot returns its FULL
        // `chunk` bytes. That holds because `pipelinedReadChunk` reads exactly
        // `want` bytes (looping internally when a single READ is credit-limited)
        // and only returns short at EOF — which can only be the final slot, so
        // no gaps appear between slots. SMB2 servers only short-read at EOF.
        var nextOffset = range.lowerBound
        var inflight: [Task<Data, Error>] = []
        inflight.reserveCapacity(width)

        func spawn() {
            guard nextOffset < range.upperBound else { return }
            let start = nextOffset
            let want  = min(UInt64(chunk), range.upperBound - start)
            nextOffset = start + want
            inflight.append(Task { [weak self] in
                guard let self = self else { return Data() }
                return try await self.pipelinedReadChunk(fileId: fileId, offset: start, want: want, path: path)
            })
        }

        func drain() async {
            for t in inflight { t.cancel() }
            for t in inflight { _ = try? await t.value }
            inflight.removeAll()
        }

        for _ in 0..<max(1, width) { spawn() }

        while !inflight.isEmpty {
            let data: Data
            do {
                data = try await inflight.removeFirst().value   // strictly in order
            } catch {
                await drain()
                throw error
            }
            if data.isEmpty { await drain(); break }             // EOF
            let keepGoing = await onSlice(data)
            if !keepGoing { await drain(); break }
            spawn()
        }
    }

    /// Read exactly `want` bytes (or fewer only at EOF) starting at `offset`
    /// from an open handle, issuing pipelined SMB2 READs sized to the credits
    /// currently affordable. Loops when a single read is credit-limited so the
    /// caller's window offsets stay aligned.
    private func pipelinedReadChunk(
        fileId: SMB2FileId,
        offset: UInt64,
        want: UInt64,
        path: String
    ) async throws -> Data {
        var collected = Data()
        collected.reserveCapacity(Int(want))
        var pos = offset
        let end = offset + want

        while pos < end {
            if Task.isCancelled { break }   // aborted window slot — stop pulling bytes
            let remaining = end - pos
            let desiredCharge = SMBSession.creditCharge(forPayloadLength: Int(remaining))
            let take = try await session.reserveCredits(upTo: desiredCharge)
            let len = min(remaining, UInt64(take) * 65536)
            let actualCharge = SMBSession.creditCharge(forPayloadLength: Int(len))
            if take > actualCharge { await session.releaseCredits(take - actualCharge) }

            let body = SMB2ReadRequest.build(fileId: fileId, offset: pos, length: UInt32(len))
            let (header, respBody) = try await session.sendPipelined(
                command: SMB2Command.read, body: body, charge: actualCharge
            )
            if header.status == NTStatus.endOfFile { break }
            guard header.isSuccess else { throw Self.mapNTStatus(header.status, path: path) }
            let parsed = try SMB2ReadResponse.parse(respBody)
            if parsed.data.isEmpty { break }
            collected.append(parsed.data)
            pos += UInt64(parsed.data.count)
        }
        return collected
    }

    // MARK: - Private helpers

    private func chunkReadSize() async -> UInt32 {
        let negotiated = await session.negotiated
        let serverMax  = negotiated?.maxReadSize ?? (64 * 1024)
        // Cap at 2 MiB — large enough to keep round-trips low on a
        // latency-bound link (this also feeds the MKV/transmux and
        // sample-buffer tiers via contents(range:)), small enough that any
        // single failed read doesn't waste much bandwidth. Never exceeds the
        // server-advertised maxReadSize.
        return min(serverMax, 2 << 20)
    }

    private func chunkWriteSize() async -> UInt32 {
        let negotiated = await session.negotiated
        let serverMax = negotiated?.maxWriteSize ?? (64 * 1024)
        return min(serverMax, 1 << 20)
    }

    // ── File-handle serialization ──────────────────────────────────────
    // Some servers (notably strict embedded/NAS SMB stacks) tolerate only ONE
    // open file handle per session at a time — opening a second CREATE handle
    // implicitly invalidates the first, so the next operation on it fails with
    // STATUS_FILE_CLOSED (0xC0000128). Per-request serialization in SMBSession
    // is not enough because open→work→close is a multi-request *sequence*. This
    // FIFO async mutex makes the whole sequence atomic: one handle at a time.
    private var fileOpBusy = false
    private var fileOpWaiters: [CheckedContinuation<Void, Never>] = []

    private func fileOpAcquire() async {
        if !fileOpBusy {
            fileOpBusy = true
            return
        }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            fileOpWaiters.append(c)
        }
    }

    private func fileOpRelease() {
        if fileOpWaiters.isEmpty {
            fileOpBusy = false
        } else {
            fileOpWaiters.removeFirst().resume()
        }
    }

    /// Run `work` with a freshly-opened file handle and always CLOSE the
    /// handle before returning, even on error. Replaces the
    /// `defer { Task { ... } }` pattern that couldn't guarantee the close
    /// ran before the function returned.
    ///
    /// The entire open→work→close sequence is serialized (see `fileOpAcquire`)
    /// so only one file handle is ever open at once.
    private func withFileHandle<T>(
        path: String,
        body: Data,
        _ work: (SMB2FileId) async throws -> T
    ) async throws -> T {
        await fileOpAcquire()
        defer { fileOpRelease() }

        let fileId = try await open(path: path, body: body)
        do {
            let result = try await work(fileId)
            try await close(fileId)
            return result
        } catch {
            // Best-effort close; swallow any secondary error.
            _ = try? await close(fileId)
            throw error
        }
    }

    private func open(path: String, body: Data) async throws -> SMB2FileId {
        let (header, respBody) = try await session.sendRequest(
            command: SMB2Command.create,
            body: body
        )
        guard header.isSuccess else {
            throw Self.mapNTStatus(header.status, path: path)
        }
        let parsed = try SMB2CreateResponse.parse(respBody)
        return parsed.fileId
    }

    private func close(_ fileId: SMB2FileId) async throws {
        let body = SMB2CloseRequest.build(fileId: fileId)
        let (header, _) = try await session.sendRequest(
            command: SMB2Command.close,
            body: body
        )
        if !header.isSuccess {
            throw Self.mapNTStatus(header.status, path: "")
        }
    }

    // MARK: - Static helpers

    /// Normalize a user-supplied path for SMB2:
    ///   * Trim leading and trailing slashes
    ///   * Convert '/' to '\'
    static func normalize(_ path: String) -> String {
        var p = path
        while p.hasPrefix("/") || p.hasPrefix("\\") { p.removeFirst() }
        while p.hasSuffix("/") || p.hasSuffix("\\") { p.removeLast() }
        return p.replacingOccurrences(of: "/", with: "\\")
    }

    /// Map an NT status code onto the most useful `SMBError` case.
    static func mapNTStatus(_ status: UInt32, path: String) -> SMBError {
        switch status {
        case NTStatus.objectNameNotFound,
             NTStatus.objectPathNotFound,
             NTStatus.noSuchFile,
             NTStatus.notFound:
            return .fileNotFound(path)
        case NTStatus.accessDenied:
            return .accessDenied(path)
        case NTStatus.objectNameCollision:
            return .fileAlreadyExists(path)
        case NTStatus.directoryNotEmpty:
            return .directoryNotEmpty(path)
        case NTStatus.logonFailure,
             NTStatus.wrongPassword,
             NTStatus.noSuchUser,
             NTStatus.accountRestriction,
             NTStatus.accountDisabled,
             NTStatus.passwordExpired:
            return .authenticationFailed
        case NTStatus.badNetworkName:
            return .fileNotFound(path)
        default:
            return .ntStatus(status)
        }
    }
}
