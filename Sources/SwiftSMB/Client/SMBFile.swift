//
//  SMBFile.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// File metadata struct returned by `SMBClient.listDirectory`.
//
// This is the public-API view of a single directory entry. It hides the
// raw SMB2 fields behind nicer Swift types (Date, Bool, URL).

import Foundation

/// A single file or directory entry on an SMB share.
public struct SMBFile: Sendable, Hashable, Identifiable {

    /// Relative path from the share root, using forward slashes
    /// (e.g. "Movies/Inception.mkv").
    public let path: String

    /// The file or directory name, without any path components.
    public let name: String

    /// Size in bytes. For directories this is always 0.
    public let size: UInt64

    /// `true` if this entry is a directory.
    public let isDirectory: Bool

    /// `true` if the file has the hidden attribute.
    public let isHidden: Bool

    /// Raw SMB2 file attributes bitmask.
    public let attributes: UInt32

    /// Timestamps decoded from Windows FILETIME (100-ns ticks since 1601).
    public let createdAt:      Date?
    public let modifiedAt:     Date?
    public let lastAccessedAt: Date?

    /// Stable identity based on the full path.
    public var id: String { path }

    /// File extension in lowercase, without the dot (e.g. "mkv").
    /// Empty string if the name has no extension.
    public var fileExtension: String {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else {
            return ""
        }
        return String(name[name.index(after: dot)...]).lowercased()
    }

    public init(
        path: String,
        name: String,
        size: UInt64,
        isDirectory: Bool,
        isHidden: Bool,
        attributes: UInt32,
        createdAt: Date? = nil,
        modifiedAt: Date? = nil,
        lastAccessedAt: Date? = nil
    ) {
        self.path            = path
        self.name            = name
        self.size            = size
        self.isDirectory     = isDirectory
        self.isHidden        = isHidden
        self.attributes      = attributes
        self.createdAt       = createdAt
        self.modifiedAt      = modifiedAt
        self.lastAccessedAt  = lastAccessedAt
    }
}

// MARK: - Conversion from low-level SMB2 parse results

extension SMBFile {

    /// Build an `SMBFile` from a parsed FileBothDirectoryInfo plus a
    /// parent directory path. Parent should use forward slashes.
    static func from(
        _ info: FileBothDirectoryInfo,
        parentPath: String
    ) -> SMBFile {
        let joined: String
        if parentPath.isEmpty {
            joined = info.fileName
        } else {
            joined = parentPath + "/" + info.fileName
        }
        return SMBFile(
            path: joined,
            name: info.fileName,
            size: info.endOfFile,
            isDirectory: info.isDirectory,
            isHidden: info.isHidden,
            attributes: info.fileAttributes,
            createdAt:      Self.date(fromFileTime: info.creationTime),
            modifiedAt:     Self.date(fromFileTime: info.lastWriteTime),
            lastAccessedAt: Self.date(fromFileTime: info.lastAccessTime)
        )
    }

    /// Convert a Windows FILETIME (100-ns intervals since 1601-01-01 UTC)
    /// to a Swift `Date`. Returns nil for zero or obviously-invalid values.
    static func date(fromFileTime fileTime: UInt64) -> Date? {
        guard fileTime != 0 else { return nil }
        // 116444736000000000 = (1970-01-01 - 1601-01-01) in 100-ns ticks
        let unixEpochTicks: UInt64 = 116_444_736_000_000_000
        guard fileTime >= unixEpochTicks else { return nil }
        let ticksSinceUnix = fileTime - unixEpochTicks
        let seconds = Double(ticksSinceUnix) / 10_000_000.0
        return Date(timeIntervalSince1970: seconds)
    }
}
