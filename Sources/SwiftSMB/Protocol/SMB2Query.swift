//
//  SMB2Query.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 QUERY_DIRECTORY and QUERY_INFO request/response
// ([MS-SMB2] §2.2.33–2.2.40).
//
// QUERY_DIRECTORY lists files in a directory.
// QUERY_INFO gets file metadata (size, timestamps, attributes).

import Foundation

// ============================================================================
// MARK: - QUERY_DIRECTORY
// ============================================================================

// MARK: - QUERY_DIRECTORY Request Builder

public enum SMB2QueryDirectoryRequest {

    /// StructureSize for QUERY_DIRECTORY request is always 33.
    public static let structureSize: UInt16 = 33

    /// QUERY_DIRECTORY flags.
    public enum Flags {
        public static let restart:      UInt8 = 0x01  // restart scan from beginning
        public static let returnSingle: UInt8 = 0x02  // return only one entry
        public static let indexSpecified: UInt8 = 0x04
        public static let reopen:       UInt8 = 0x10  // reopen the query
    }

    /// Build a QUERY_DIRECTORY request body.
    ///
    /// - `fileId`: The directory handle from CREATE (opened with directoryFile).
    /// - `pattern`: Search pattern, e.g. "*" for all files. UTF-16LE encoded.
    /// - `infoClass`: The info level. Default: FileBothDirectoryInformation.
    /// - `flags`: Query flags (default: 0).
    /// - `outputBufferLength`: Max bytes in the response (default: 64KB).
    public static func build(
        fileId: SMB2FileId,
        pattern: String = "*",
        infoClass: UInt8 = SMB2FileInfoClass.fileBothDirectoryInformation,
        flags: UInt8 = 0,
        outputBufferLength: UInt32 = 65536
    ) -> Data {
        let patternData = pattern.utf16leData

        // FileNameOffset is relative to the start of the SMB2 header.
        // Header (64) + fixed body before name (32 bytes) = 96
        let fileNameOffset: UInt16 = UInt16(smb2HeaderSize) + 32

        var w = ByteWriter()
        w.uint16le(structureSize)                // StructureSize (33)
        w.uint8(infoClass)                       // FileInformationClass
        w.uint8(flags)                           // Flags
        w.uint32le(0)                            // FileIndex
        fileId.write(to: &w)                     // FileId (16 bytes)
        w.uint16le(fileNameOffset)               // FileNameOffset
        w.uint16le(UInt16(patternData.count))    // FileNameLength
        w.uint32le(outputBufferLength)           // OutputBufferLength
        w.bytes(patternData)                     // Buffer (search pattern)
        return w.data
    }
}

// MARK: - QUERY_DIRECTORY Response Parser

/// Parsed QUERY_DIRECTORY response. Contains the raw output buffer
/// which holds one or more directory entries depending on the info class.
public struct SMB2QueryDirectoryResponse {
    public let structureSize:     UInt16
    public let outputBufferOffset: UInt16
    public let outputBufferLength: UInt32
    public let outputBuffer:      Data     // raw directory entries
}

extension SMB2QueryDirectoryResponse {

    /// Expected StructureSize for a QUERY_DIRECTORY response.
    public static let expectedStructureSize: UInt16 = 9

    /// Parse a QUERY_DIRECTORY response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2QueryDirectoryResponse {
        var r = ByteReader(data)

        let structureSize     = try r.uint16le()
        let outputBufferOffset = try r.uint16le()
        let outputBufferLength = try r.uint32le()

        let localOffset = Int(outputBufferOffset) - smb2HeaderSize
        let outputBuffer: Data
        if outputBufferLength > 0, localOffset >= 0, localOffset + Int(outputBufferLength) <= data.count {
            outputBuffer = Data(data[data.startIndex + localOffset ..< data.startIndex + localOffset + Int(outputBufferLength)])
        } else {
            outputBuffer = Data()
        }

        return SMB2QueryDirectoryResponse(
            structureSize:     structureSize,
            outputBufferOffset: outputBufferOffset,
            outputBufferLength: outputBufferLength,
            outputBuffer:      outputBuffer
        )
    }
}

// MARK: - FileBothDirectoryInformation parser

/// A single entry from FileBothDirectoryInformation results.
/// This is the default info class for directory listings — it includes
/// file name, size, timestamps, and the 8.3 short name.
public struct FileBothDirectoryInfo {
    public let fileName:       String
    public let shortName:      String
    public let fileAttributes: UInt32
    public let creationTime:   UInt64
    public let lastAccessTime: UInt64
    public let lastWriteTime:  UInt64
    public let changeTime:     UInt64
    public let endOfFile:      UInt64    // file size
    public let allocationSize: UInt64

    /// True if this entry is a directory.
    public var isDirectory: Bool {
        fileAttributes & SMB2FileAttributes.directory != 0
    }

    /// True if this entry is hidden.
    public var isHidden: Bool {
        fileAttributes & SMB2FileAttributes.hidden != 0
    }
}

extension FileBothDirectoryInfo {

    /// Parse all entries from a FileBothDirectoryInformation output buffer.
    ///
    /// The buffer contains a chain of variable-length records. Each record's
    /// first 4 bytes (NextEntryOffset) point to the next entry, or 0 if last.
    public static func parseAll(from buffer: Data) -> [FileBothDirectoryInfo] {
        var entries: [FileBothDirectoryInfo] = []
        var offset = 0

        while offset < buffer.count {
            let r = ByteReader(buffer)

            // NextEntryOffset (4 bytes) at current position
            let nextEntryOffset = r.uint32le(at: offset)

            // Fixed fields of FILE_BOTH_DIR_INFORMATION:
            //  0..3   NextEntryOffset
            //  4..7   FileIndex
            //  8..15  CreationTime
            // 16..23  LastAccessTime
            // 24..31  LastWriteTime
            // 32..39  ChangeTime
            // 40..47  EndOfFile
            // 48..55  AllocationSize
            // 56..59  FileAttributes
            // 60..63  FileNameLength
            // 64..67  EaSize
            // 68      ShortNameLength
            // 69      Reserved
            // 70..93  ShortName (24 bytes, UTF-16LE, padded)
            // 94..    FileName (variable length, UTF-16LE)

            guard offset + 94 <= buffer.count else { break }

            let creationTime   = r.uint64le(at: offset + 8)
            let lastAccessTime = r.uint64le(at: offset + 16)
            let lastWriteTime  = r.uint64le(at: offset + 24)
            let changeTime     = r.uint64le(at: offset + 32)
            let endOfFile      = r.uint64le(at: offset + 40)
            let allocationSize = r.uint64le(at: offset + 48)
            let fileAttributes = r.uint32le(at: offset + 56)
            let fileNameLength = r.uint32le(at: offset + 60)
            let shortNameLength = r.uint8(at: offset + 68)

            // Short name (up to 24 bytes, but only shortNameLength bytes are valid)
            let shortNameData = r.subdata(at: offset + 70, length: Int(shortNameLength))
            let shortName = shortNameData.utf16leString

            // File name
            let fileNameOffset = offset + 94
            guard fileNameOffset + Int(fileNameLength) <= buffer.count else { break }
            let fileNameData = r.subdata(at: fileNameOffset, length: Int(fileNameLength))
            let fileName = fileNameData.utf16leString

            entries.append(FileBothDirectoryInfo(
                fileName:       fileName,
                shortName:      shortName,
                fileAttributes: fileAttributes,
                creationTime:   creationTime,
                lastAccessTime: lastAccessTime,
                lastWriteTime:  lastWriteTime,
                changeTime:     changeTime,
                endOfFile:      endOfFile,
                allocationSize: allocationSize
            ))

            if nextEntryOffset == 0 { break }
            offset += Int(nextEntryOffset)
        }

        return entries
    }
}

// ============================================================================
// MARK: - QUERY_INFO
// ============================================================================

// MARK: - QUERY_INFO Request Builder

public enum SMB2QueryInfoRequest {

    /// StructureSize for QUERY_INFO request is always 41.
    public static let structureSize: UInt16 = 41

    /// Build a QUERY_INFO request body.
    ///
    /// - `fileId`: The file or directory handle.
    /// - `infoType`: What kind of info (file, filesystem, security, quota).
    /// - `fileInfoClass`: Specific info class within the type.
    /// - `outputBufferLength`: Max response size (default: 8KB).
    public static func build(
        fileId: SMB2FileId,
        infoType: UInt8 = SMB2InfoType.file,
        fileInfoClass: UInt8 = SMB2FileInformationClass.fileAllInformation,
        outputBufferLength: UInt32 = 8192
    ) -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)          // StructureSize (41)
        w.uint8(infoType)                  // InfoType
        w.uint8(fileInfoClass)             // FileInfoClass
        w.uint32le(outputBufferLength)     // OutputBufferLength
        w.uint32le(0)                      // InputBufferOffset (0 = none)
        w.zeros(2)                         // Reserved
        w.uint32le(0)                      // InputBufferLength (0 = none)
        w.uint32le(0)                      // AdditionalInformation
        w.uint32le(0)                      // Flags
        fileId.write(to: &w)               // FileId (16 bytes)
        return w.data
    }
}

// MARK: - QUERY_INFO Response Parser

/// Parsed QUERY_INFO response. Contains the raw output buffer
/// whose format depends on the requested InfoType + FileInfoClass.
public struct SMB2QueryInfoResponse {
    public let structureSize:     UInt16
    public let outputBufferOffset: UInt16
    public let outputBufferLength: UInt32
    public let outputBuffer:      Data
}

extension SMB2QueryInfoResponse {

    /// Expected StructureSize for a QUERY_INFO response.
    public static let expectedStructureSize: UInt16 = 9

    /// Parse a QUERY_INFO response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2QueryInfoResponse {
        var r = ByteReader(data)

        let structureSize     = try r.uint16le()
        let outputBufferOffset = try r.uint16le()
        let outputBufferLength = try r.uint32le()

        let localOffset = Int(outputBufferOffset) - smb2HeaderSize
        let outputBuffer: Data
        if outputBufferLength > 0, localOffset >= 0, localOffset + Int(outputBufferLength) <= data.count {
            outputBuffer = Data(data[data.startIndex + localOffset ..< data.startIndex + localOffset + Int(outputBufferLength)])
        } else {
            outputBuffer = Data()
        }

        return SMB2QueryInfoResponse(
            structureSize:     structureSize,
            outputBufferOffset: outputBufferOffset,
            outputBufferLength: outputBufferLength,
            outputBuffer:      outputBuffer
        )
    }
}

// MARK: - FileStandardInformation parser

/// Parsed FILE_STANDARD_INFORMATION — the quickest way to get file size.
public struct FileStandardInfo {
    public let allocationSize: UInt64
    public let endOfFile:      UInt64    // actual file size in bytes
    public let numberOfLinks:  UInt32
    public let deletePending:  Bool
    public let isDirectory:    Bool
}

extension FileStandardInfo {

    /// Parse FILE_STANDARD_INFORMATION from a QUERY_INFO output buffer.
    public static func parse(_ data: Data) throws -> FileStandardInfo {
        var r = ByteReader(data)
        let allocationSize = try r.uint64le()
        let endOfFile      = try r.uint64le()
        let numberOfLinks  = try r.uint32le()
        let deletePending  = try r.uint8() != 0
        let isDirectory    = try r.uint8() != 0
        return FileStandardInfo(
            allocationSize: allocationSize,
            endOfFile:      endOfFile,
            numberOfLinks:  numberOfLinks,
            deletePending:  deletePending,
            isDirectory:    isDirectory
        )
    }
}
