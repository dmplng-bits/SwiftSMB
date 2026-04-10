//
//  SMB2Create.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 CREATE (open/create file) request and response ([MS-SMB2] §2.2.13–2.2.14).
//
// CREATE is how you open a file or directory on the share.
// Used to:
//   - Open a directory for listing (QUERY_DIRECTORY)
//   - Open a file for reading (READ)
//
// The response returns a FileId (16 bytes) used in all subsequent operations.

import Foundation

// MARK: - SMB2 FileId

/// The 16-byte persistent + volatile file handle returned by CREATE.
/// Used in READ, CLOSE, QUERY_DIRECTORY, QUERY_INFO, etc.
public struct SMB2FileId: Equatable {
    public let persistent: UInt64
    public let volatile:   UInt64

    public init(persistent: UInt64, volatile: UInt64) {
        self.persistent = persistent
        self.volatile = volatile
    }

    /// Write the 16-byte FileId into a ByteWriter.
    public func write(to w: inout ByteWriter) {
        w.uint64le(persistent)
        w.uint64le(volatile)
    }

    /// Read a 16-byte FileId from a ByteReader.
    public static func read(from r: inout ByteReader) throws -> SMB2FileId {
        let persistent = try r.uint64le()
        let volatile   = try r.uint64le()
        return SMB2FileId(persistent: persistent, volatile: volatile)
    }
}

// MARK: - CREATE Request Builder

public enum SMB2CreateRequest {

    /// StructureSize for CREATE request is always 57.
    public static let structureSize: UInt16 = 57

    /// Build a CREATE request body to open a file or directory.
    ///
    /// - `path`: Path relative to the share root (e.g. "Movies/movie.mkv").
    ///   Empty string opens the share root directory.
    /// - `desiredAccess`: Access mask (e.g. `SMB2AccessMask.genericRead`).
    /// - `fileAttributes`: Attributes for creation (default: 0).
    /// - `shareAccess`: Sharing mode (default: read sharing).
    /// - `createDisposition`: What to do if file exists/doesn't exist.
    /// - `createOptions`: Additional options (e.g. directoryFile).
    public static func build(
        path: String,
        desiredAccess: UInt32 = SMB2AccessMask.genericRead | SMB2AccessMask.fileReadAttributes,
        fileAttributes: UInt32 = 0,
        shareAccess: UInt32 = SMB2ShareAccess.read,
        createDisposition: UInt32 = SMB2CreateDisposition.open,
        createOptions: UInt32 = 0
    ) -> Data {
        let pathData = path.utf16leData

        // NameOffset is relative to header start.
        // Header (64) + fixed body before name (56 bytes of CREATE fixed fields) = 120
        let nameOffset: UInt16 = UInt16(smb2HeaderSize) + 56

        var w = ByteWriter()
        w.uint16le(structureSize)               // StructureSize (57)
        w.uint8(0)                              // SecurityFlags (must be 0)
        w.uint8(0)                              // RequestedOplockLevel (none)
        w.uint32le(0x0000_0002)                 // ImpersonationLevel (Impersonation)
        w.zeros(8)                              // SmbCreateFlags (reserved)
        w.zeros(8)                              // Reserved
        w.uint32le(desiredAccess)               // DesiredAccess
        w.uint32le(fileAttributes)              // FileAttributes
        w.uint32le(shareAccess)                 // ShareAccess
        w.uint32le(createDisposition)           // CreateDisposition
        w.uint32le(createOptions)               // CreateOptions
        w.uint16le(nameOffset)                  // NameOffset
        w.uint16le(UInt16(pathData.count))      // NameLength
        w.uint32le(0)                           // CreateContextsOffset (0 = none)
        w.uint32le(0)                           // CreateContextsLength (0 = none)
        w.bytes(pathData)                       // Buffer (UTF-16LE path)
        return w.data
    }

    /// Convenience: open a directory for listing.
    public static func openDirectory(path: String) -> Data {
        build(
            path: path,
            desiredAccess: SMB2AccessMask.fileReadData | SMB2AccessMask.fileReadAttributes,
            shareAccess: SMB2ShareAccess.read,
            createDisposition: SMB2CreateDisposition.open,
            createOptions: SMB2CreateOptions.directoryFile
        )
    }

    /// Convenience: open a file for reading (streaming).
    public static func openFile(path: String) -> Data {
        build(
            path: path,
            desiredAccess: SMB2AccessMask.genericRead,
            shareAccess: SMB2ShareAccess.read,
            createDisposition: SMB2CreateDisposition.open,
            createOptions: SMB2CreateOptions.nonDirectoryFile
        )
    }

    /// Build a CREATE request with a create context (e.g. lease request).
    public static func buildWithContext(
        path: String,
        desiredAccess: UInt32 = SMB2AccessMask.genericRead | SMB2AccessMask.fileReadAttributes,
        fileAttributes: UInt32 = 0,
        shareAccess: UInt32 = SMB2ShareAccess.read,
        createDisposition: UInt32 = SMB2CreateDisposition.open,
        createOptions: UInt32 = 0,
        oplockLevel: UInt8 = SMB2OplockLevel.none,
        createContext: Data
    ) -> Data {
        let pathData = path.utf16leData
        let nameOffset: UInt16 = UInt16(smb2HeaderSize) + 56

        // Create contexts start after the path data, padded to 8-byte alignment
        let pathEnd = Int(nameOffset) - smb2HeaderSize + pathData.count
        let contextPadding = (8 - (pathEnd % 8)) % 8
        let contextOffset = UInt32(smb2HeaderSize) + UInt32(pathEnd) + UInt32(contextPadding)

        var w = ByteWriter()
        w.uint16le(structureSize)               // StructureSize (57)
        w.uint8(0)                              // SecurityFlags
        w.uint8(oplockLevel)                    // RequestedOplockLevel
        w.uint32le(0x0000_0002)                 // ImpersonationLevel
        w.zeros(8)                              // SmbCreateFlags
        w.zeros(8)                              // Reserved
        w.uint32le(desiredAccess)               // DesiredAccess
        w.uint32le(fileAttributes)              // FileAttributes
        w.uint32le(shareAccess)                 // ShareAccess
        w.uint32le(createDisposition)           // CreateDisposition
        w.uint32le(createOptions)               // CreateOptions
        w.uint16le(nameOffset)                  // NameOffset
        w.uint16le(UInt16(pathData.count))      // NameLength
        w.uint32le(contextOffset)               // CreateContextsOffset
        w.uint32le(UInt32(createContext.count))  // CreateContextsLength
        w.bytes(pathData)                       // Buffer (path)
        w.zeros(contextPadding)                 // Padding to 8-byte alignment
        w.bytes(createContext)                   // Create contexts
        return w.data
    }

    /// Convenience: open a file for reading with an RH lease for caching.
    public static func openFileWithLease(path: String, leaseKey: Data) -> Data {
        let contextData = SMB2LeaseContext.buildV1(
            leaseKey: leaseKey,
            leaseState: SMB2LeaseState.readHandle
        )
        return buildWithContext(
            path: path,
            desiredAccess: SMB2AccessMask.genericRead,
            shareAccess: SMB2ShareAccess.read,
            createDisposition: SMB2CreateDisposition.open,
            createOptions: SMB2CreateOptions.nonDirectoryFile,
            oplockLevel: SMB2OplockLevel.lease,
            createContext: contextData
        )
    }
}

// MARK: - CREATE Response Parser

/// Parsed fields from a CREATE response body.
public struct SMB2CreateResponse {
    public let structureSize:    UInt16
    public let oplockLevel:      UInt8
    public let flags:            UInt8
    public let createAction:     UInt32
    public let creationTime:     UInt64   // Windows FILETIME
    public let lastAccessTime:   UInt64
    public let lastWriteTime:    UInt64
    public let changeTime:       UInt64
    public let allocationSize:   UInt64
    public let endOfFile:        UInt64   // actual file size in bytes
    public let fileAttributes:   UInt32
    public let fileId:           SMB2FileId
}

extension SMB2CreateResponse {

    /// Expected StructureSize for a CREATE response.
    public static let expectedStructureSize: UInt16 = 89

    /// Parse a CREATE response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2CreateResponse {
        var r = ByteReader(data)

        let structureSize  = try r.uint16le()
        let oplockLevel    = try r.uint8()
        let flags          = try r.uint8()
        let createAction   = try r.uint32le()
        let creationTime   = try r.uint64le()
        let lastAccessTime = try r.uint64le()
        let lastWriteTime  = try r.uint64le()
        let changeTime     = try r.uint64le()
        let allocationSize = try r.uint64le()
        let endOfFile      = try r.uint64le()
        let fileAttributes = try r.uint32le()
        let _              = try r.uint32le()  // Reserved2
        let fileId         = try SMB2FileId.read(from: &r)

        // CreateContextsOffset and Length follow but we skip them.

        return SMB2CreateResponse(
            structureSize:    structureSize,
            oplockLevel:      oplockLevel,
            flags:            flags,
            createAction:     createAction,
            creationTime:     creationTime,
            lastAccessTime:   lastAccessTime,
            lastWriteTime:    lastWriteTime,
            changeTime:       changeTime,
            allocationSize:   allocationSize,
            endOfFile:        endOfFile,
            fileAttributes:   fileAttributes,
            fileId:           fileId
        )
    }
}
