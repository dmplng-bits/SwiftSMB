//
//  SMB2ChangeNotify.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// SMB2 CHANGE_NOTIFY request and response ([MS-SMB2] §2.2.35–2.2.36).
//
// CHANGE_NOTIFY watches a directory for file system changes without polling.
// The server holds the request and responds only when something changes,
// or when a timeout expires.

import Foundation

// MARK: - CHANGE_NOTIFY Filters and Actions

/// Completion filter values for CHANGE_NOTIFY requests.
/// [MS-SMB2] §2.2.35: each bit specifies which types of changes to watch for.
public enum SMB2ChangeNotifyFilter {
    public static let fileName:       UInt32 = 0x0000_0001
    public static let dirName:        UInt32 = 0x0000_0002
    public static let attributes:     UInt32 = 0x0000_0004
    public static let size:           UInt32 = 0x0000_0008
    public static let lastWrite:      UInt32 = 0x0000_0010
    public static let lastAccess:     UInt32 = 0x0000_0020
    public static let creation:       UInt32 = 0x0000_0040
    public static let ea:             UInt32 = 0x0000_0080
    public static let security:       UInt32 = 0x0000_0100
    public static let streamName:     UInt32 = 0x0000_0200
    public static let streamSize:     UInt32 = 0x0000_0400
    public static let streamWrite:    UInt32 = 0x0000_0800

    /// Watch for file/dir additions, removals, renames, and size changes.
    public static let all: UInt32 = 0x0000_0FFF
}

/// File action codes in FILE_NOTIFY_INFORMATION entries.
/// [MS-SMB2] §2.2.35
public enum SMB2FileAction {
    public static let added:            UInt32 = 0x0000_0001
    public static let removed:          UInt32 = 0x0000_0002
    public static let modified:         UInt32 = 0x0000_0003
    public static let renamedOldName:   UInt32 = 0x0000_0004
    public static let renamedNewName:   UInt32 = 0x0000_0005
}

// MARK: - CHANGE_NOTIFY Request Builder

public enum SMB2ChangeNotifyRequest {

    /// StructureSize for CHANGE_NOTIFY request is always 32.
    public static let structureSize: UInt16 = 32

    /// Build a CHANGE_NOTIFY request body.
    ///
    /// - `fileId`: The directory handle (opened with CREATE).
    /// - `watchTree`: If true, watch the entire subtree recursively (0x0001).
    ///   If false, watch only the directory itself (0x0000).
    /// - `completionFilter`: Bitmask of changes to watch
    ///   (e.g. `SMB2ChangeNotifyFilter.all`).
    /// - `outputBufferLength`: Size of the output buffer (default 65536).
    ///   The server returns notification data up to this size.
    public static func build(
        fileId: SMB2FileId,
        watchTree: Bool = true,
        completionFilter: UInt32 = SMB2ChangeNotifyFilter.all,
        outputBufferLength: UInt32 = 65536
    ) -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)                    // StructureSize (32)
        w.uint16le(watchTree ? 0x0001 : 0x0000)      // Flags
        w.uint32le(outputBufferLength)               // OutputBufferLength
        fileId.write(to: &w)                         // FileId (16 bytes)
        w.uint32le(completionFilter)                 // CompletionFilter
        w.uint32le(0)                                // Reserved
        return w.data
    }
}

// MARK: - CHANGE_NOTIFY Response Parser

/// Parsed fields from a CHANGE_NOTIFY response body.
public struct SMB2ChangeNotifyResponse {
    public let structureSize:       UInt16
    public let outputBufferOffset:  UInt16
    public let outputBufferLength:  UInt32
    public let outputBuffer:        Data
}

extension SMB2ChangeNotifyResponse {

    /// Expected StructureSize for a CHANGE_NOTIFY response.
    public static let expectedStructureSize: UInt16 = 9

    /// Parse a CHANGE_NOTIFY response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2ChangeNotifyResponse {
        var r = ByteReader(data)

        let structureSize       = try r.uint16le()
        let outputBufferOffset  = try r.uint16le()
        let outputBufferLength  = try r.uint32le()

        // OutputBuffer is located at the offset specified by OutputBufferOffset,
        // relative to the start of the SMB2 header. Extract it from the response data.
        // The response body starts after the 64-byte header, so we need to account for that.
        let headerSize = smb2HeaderSize
        let bufferStartInResponse = Int(outputBufferOffset) - headerSize
        let outputBuffer = bufferStartInResponse >= 0 && bufferStartInResponse < data.count
            ? data.subdata(in: bufferStartInResponse ..< min(
                bufferStartInResponse + Int(outputBufferLength),
                data.count
              ))
            : Data()

        return SMB2ChangeNotifyResponse(
            structureSize:      structureSize,
            outputBufferOffset: outputBufferOffset,
            outputBufferLength: outputBufferLength,
            outputBuffer:       outputBuffer
        )
    }
}

// MARK: - FILE_NOTIFY_INFORMATION Entry

/// A single file change entry from the CHANGE_NOTIFY output buffer.
public struct FileNotifyInfo {
    public let action:    UInt32
    public let fileName:  String
}

extension FileNotifyInfo {

    /// Parse all FILE_NOTIFY_INFORMATION entries from the output buffer.
    /// Each entry contains NextEntryOffset (0 = last entry), Action, FileNameLength, and FileName.
    public static func parseAll(from buffer: Data) -> [FileNotifyInfo] {
        var results: [FileNotifyInfo] = []
        var offset: Int = 0

        while offset < buffer.count {
            // Read NextEntryOffset (4 bytes).
            guard offset + 4 <= buffer.count else { break }
            let nextOffsetBytes = buffer.subdata(in: offset ..< offset + 4)
            let nextOffset = UInt32(nextOffsetBytes[nextOffsetBytes.startIndex]) |
                           (UInt32(nextOffsetBytes[nextOffsetBytes.startIndex + 1]) << 8) |
                           (UInt32(nextOffsetBytes[nextOffsetBytes.startIndex + 2]) << 16) |
                           (UInt32(nextOffsetBytes[nextOffsetBytes.startIndex + 3]) << 24)

            // Read Action (4 bytes).
            guard offset + 8 <= buffer.count else { break }
            let actionBytes = buffer.subdata(in: (offset + 4) ..< (offset + 8))
            let action = UInt32(actionBytes[actionBytes.startIndex]) |
                        (UInt32(actionBytes[actionBytes.startIndex + 1]) << 8) |
                        (UInt32(actionBytes[actionBytes.startIndex + 2]) << 16) |
                        (UInt32(actionBytes[actionBytes.startIndex + 3]) << 24)

            // Read FileNameLength (4 bytes).
            guard offset + 12 <= buffer.count else { break }
            let lenBytes = buffer.subdata(in: (offset + 8) ..< (offset + 12))
            let fileNameLength = UInt32(lenBytes[lenBytes.startIndex]) |
                               (UInt32(lenBytes[lenBytes.startIndex + 1]) << 8) |
                               (UInt32(lenBytes[lenBytes.startIndex + 2]) << 16) |
                               (UInt32(lenBytes[lenBytes.startIndex + 3]) << 24)

            // Read FileName (UTF-16LE, length = fileNameLength bytes).
            let fileNameStart = offset + 12
            let fileNameEnd = fileNameStart + Int(fileNameLength)
            guard fileNameEnd <= buffer.count else { break }
            let fileNameData = buffer.subdata(in: fileNameStart ..< fileNameEnd)
            let fileName = fileNameData.utf16leString

            results.append(FileNotifyInfo(action: action, fileName: fileName))

            // Move to next entry (or break if NextEntryOffset is 0).
            if nextOffset == 0 { break }
            offset += Int(nextOffset)
        }

        return results
    }
}
