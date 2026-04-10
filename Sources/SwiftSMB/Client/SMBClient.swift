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
//   let bytes = try await client.contents(atPath: "Movies/film.mkv", range: 0..<1024)
//   let url   = try await client.url(ofItem: "Movies/film.mkv")   // streaming URL
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

    // MARK: Init

    public init(session: SMBSession) {
        self.session = session
    }

    public init(host: String, port: UInt16 = 445) {
        self.session = SMBSession(host: host, port: port)
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
            // Use an empty host in the UNC — TREE_CONNECT tolerates this
            // form and servers fall back to the already-connected host.
            fullPath = "\\\\\(host(for: session))\\\(share)"
        }
        try await session.connectShare(fullPath, credentials: credentials)
    }

    /// Close the tree, log off, and tear down the TCP connection.
    public func disconnect() async {
        await streamingProxy?.stop()
        streamingProxy = nil
        await session.disconnect()
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

                let body = SMB2QueryDirectoryRequest.build(
                    fileId:  fileId,
                    pattern: "*",
                    flags:   flags
                )
                let (header, respBody) = try await self.session.sendRequest(
                    command: SMB2Command.queryDirectory,
                    body: body
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

    // MARK: - Ranged reads (for streaming)

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
        let chunkSize = await chunkReadSize()

        return try await withFileHandle(
            path: normalized,
            body: SMB2CreateRequest.openFile(path: normalized)
        ) { fileId in
            var collected = Data()
            collected.reserveCapacity(Int(range.upperBound - range.lowerBound))

            var offset = range.lowerBound
            while offset < range.upperBound {
                let remaining = range.upperBound - offset
                let thisLen   = min(UInt64(chunkSize), remaining)

                let body = SMB2ReadRequest.build(
                    fileId: fileId,
                    offset: offset,
                    length: UInt32(thisLen)
                )
                let (header, respBody) = try await self.session.sendRequest(
                    command: SMB2Command.read,
                    body: body
                )

                if header.status == NTStatus.endOfFile { break }
                guard header.isSuccess else {
                    throw Self.mapNTStatus(header.status, path: normalized)
                }

                let parsed = try SMB2ReadResponse.parse(respBody)
                if parsed.data.isEmpty { break }
                collected.append(parsed.data)
                offset += UInt64(parsed.data.count)
            }

            return collected
        }
    }

    // MARK: - Streaming URL

    /// Return an `http://127.0.0.1:<port>/...` URL that AVPlayer can read
    /// from to stream the given SMB file. The first call lazily starts a
    /// local HTTP proxy bound to loopback; subsequent calls reuse it.
    public func url(ofItem path: String) async throws -> URL {
        let normalized = Self.normalize(path)

        if streamingProxy == nil {
            let proxy = SMBStreamingProxy(client: self)
            try await proxy.start()
            streamingProxy = proxy
        }

        guard let proxy = streamingProxy else {
            throw SMBError.connectionFailed("Failed to start streaming proxy")
        }
        return try await proxy.url(forPath: normalized)
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

    // MARK: - Private helpers

    private func chunkReadSize() async -> UInt32 {
        let negotiated = await session.negotiated
        let serverMax  = negotiated?.maxReadSize ?? (64 * 1024)
        // Cap at 1 MiB — large enough to be efficient, small enough that
        // any single failed read doesn't waste much bandwidth.
        return min(serverMax, 1 << 20)
    }

    /// Run `work` with a freshly-opened file handle and always CLOSE the
    /// handle before returning, even on error. Replaces the
    /// `defer { Task { ... } }` pattern that couldn't guarantee the close
    /// ran before the function returned.
    private func withFileHandle<T>(
        path: String,
        body: Data,
        _ work: (SMB2FileId) async throws -> T
    ) async throws -> T {
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

    /// Session doesn't expose its host directly; we only call this when
    /// the caller gave us a bare share name, in which case we fall back
    /// to the empty "\\\\\\" prefix which every known SMB server accepts.
    private func host(for session: SMBSession) -> String {
        ""
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
        case NTStatus.logonFailure,
             NTStatus.accountRestriction,
             NTStatus.passwordExpired:
            return .authenticationFailed
        default:
            return .ntStatus(status)
        }
    }
}
