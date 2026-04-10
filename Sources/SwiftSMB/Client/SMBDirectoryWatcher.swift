//
//  SMBDirectoryWatcher.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Watch a directory on an SMB share for real-time file system changes.
// Uses SMB2 CHANGE_NOTIFY to avoid polling.

import Foundation

/// A change event from the SMB server.
public struct SMBFileChange: Sendable {
    public enum Action: Sendable {
        case added
        case removed
        case modified
        case renamedOld
        case renamedNew
    }

    public let action: Action
    public let fileName: String

    /// Map the raw SMB2 action code.
    public init(action rawAction: UInt32, fileName: String) {
        switch rawAction {
        case SMB2FileAction.added:          self.action = .added
        case SMB2FileAction.removed:        self.action = .removed
        case SMB2FileAction.modified:       self.action = .modified
        case SMB2FileAction.renamedOldName: self.action = .renamedOld
        case SMB2FileAction.renamedNewName: self.action = .renamedNew
        default:                            self.action = .modified
        }
        self.fileName = fileName
    }
}

/// Watch a directory for changes using SMB2 CHANGE_NOTIFY.
///
/// Usage:
/// ```swift
/// let watcher = SMBDirectoryWatcher(session: session)
/// try await watcher.watch("Photos") { changes in
///     for change in changes {
///         print("\(change.action): \(change.fileName)")
///     }
/// }
/// // Later:
/// await watcher.stop()
/// ```
public actor SMBDirectoryWatcher {

    private let session: SMBSession
    private var watchTask: Task<Void, Never>?
    private var directoryFileId: SMB2FileId?
    private var isWatching: Bool = false

    public init(session: SMBSession) {
        self.session = session
    }

    /// Start watching a directory for changes.
    /// The `onChange` callback fires each time the server reports changes.
    /// Watches recursively (subtree) by default.
    public func watch(
        _ path: String,
        watchTree: Bool = true,
        filter: UInt32 = SMB2ChangeNotifyFilter.all,
        onChange: @escaping @Sendable ([SMBFileChange]) -> Void
    ) async throws {
        // Stop any existing watch.
        await stop()

        // Open the directory handle (keep it open for the lifetime of the watch).
        let normalizedPath = normalizePath(path)
        let createBody = SMB2CreateRequest.openDirectory(path: normalizedPath)
        let (createHeader, createRespBody) = try await session.sendRequest(
            command: SMB2Command.create,
            body: createBody
        )
        guard createHeader.isSuccess else {
            throw SMBError.fileNotFound(normalizedPath)
        }
        let createResp = try SMB2CreateResponse.parse(createRespBody)
        directoryFileId = createResp.fileId
        isWatching = true

        let fileId = createResp.fileId

        // Spawn a long-running task that loops CHANGE_NOTIFY requests.
        watchTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { break }
                let stillWatching = await self.isWatching
                guard stillWatching else { break }

                do {
                    let body = SMB2ChangeNotifyRequest.build(
                        fileId: fileId,
                        watchTree: watchTree,
                        completionFilter: filter
                    )
                    // CHANGE_NOTIFY is a long-lived request — the server holds it
                    // until something changes, then responds.
                    let (header, respBody) = try await self.session.sendRequest(
                        command: SMB2Command.changeNotify,
                        body: body
                    )

                    if header.isSuccess {
                        let parsed = try SMB2ChangeNotifyResponse.parse(respBody)
                        let entries = FileNotifyInfo.parseAll(from: parsed.outputBuffer)
                        let changes = entries.map { SMBFileChange(action: $0.action, fileName: $0.fileName) }
                        if !changes.isEmpty {
                            onChange(changes)
                        }
                    } else if header.status == NTStatus.cancelled {
                        // Watch was cancelled (we called stop).
                        break
                    } else {
                        // Some other error — stop watching.
                        break
                    }
                } catch {
                    // Connection lost or other error — stop watching.
                    break
                }
            }
        }
    }

    /// Stop watching. Closes the directory handle.
    public func stop() async {
        isWatching = false
        watchTask?.cancel()
        watchTask = nil

        if let fileId = directoryFileId {
            let closeBody = SMB2CloseRequest.build(fileId: fileId)
            _ = try? await session.sendRequest(
                command: SMB2Command.close,
                body: closeBody
            )
            directoryFileId = nil
        }
    }

    private func normalizePath(_ path: String) -> String {
        var p = path
        while p.hasPrefix("/") || p.hasPrefix("\\") { p.removeFirst() }
        while p.hasSuffix("/") || p.hasSuffix("\\") { p.removeLast() }
        return p.replacingOccurrences(of: "/", with: "\\")
    }
}
