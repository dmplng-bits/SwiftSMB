//
//  SMB2SetInfo.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// SMB2 SET_INFO request and response ([MS-SMB2] §2.2.39–2.2.40).
//
// SET_INFO is used to modify file metadata:
//   - Rename a file or directory
//   - Delete a file on close
//   - Set basic attributes (timestamps, read-only, etc.)
//
// The request carries a "buffer" of class-specific data (e.g. new file name).
// The response is trivial — just a StructureSize field.

import Foundation

// MARK: - File Rename Information Helper

/// Build buffers for FileRenameInformation ([MS-FSCC] §2.4.34.2).
public enum FileRenameInfo {

    /// Build a FileRenameInformation buffer for use with SET_INFO.
    ///
    /// - `newName`: the new file name, relative to share root (using backslashes).
    /// - `replaceIfExists`: if true, overwrite the target if it exists.
    public static func build(newName: String, replaceIfExists: Bool = false) -> Data {
        let nameData = newName.utf16leData

        var w = ByteWriter()
        w.uint8(replaceIfExists ? 1 : 0)   // ReplaceIfExists
        w.zeros(7)                          // Reserved (7 bytes)
        w.uint64le(0)                       // RootDirectory (0 = relative to share)
        w.uint32le(UInt32(nameData.count))  // FileNameLength
        w.bytes(nameData)                   // FileName (UTF-16LE)
        return w.data
    }
}

// MARK: - File Disposition Information Helper

/// Build buffers for FileDispositionInformation ([MS-FSCC] §2.4.11).
public enum FileDispositionInfo {

    /// Build a FileDispositionInformation buffer to mark a file for deletion.
    ///
    /// - `deleteOnClose`: if true, the file will be deleted when the handle closes.
    public static func build(deleteOnClose: Bool = true) -> Data {
        var w = ByteWriter()
        w.uint8(deleteOnClose ? 1 : 0)  // DeletePending
        return w.data
    }
}

// MARK: - SET_INFO Request Builder

public enum SMB2SetInfoRequest {

    /// StructureSize for SET_INFO request is always 33.
    public static let structureSize: UInt16 = 33

    /// Build a SET_INFO request body.
    ///
    /// - `fileId`: The file/directory handle from a prior CREATE.
    /// - `infoType`: What kind of info (default: SMB2InfoType.file).
    /// - `fileInfoClass`: The specific info class (e.g. fileRenameInformation).
    /// - `buffer`: The class-specific data (e.g. FileRenameInfo.build(...)).
    public static func build(
        fileId: SMB2FileId,
        infoType: UInt8 = SMB2InfoType.file,
        fileInfoClass: UInt8,
        buffer: Data
    ) -> Data {
        // BufferOffset is relative to the start of the SMB2 header.
        // Header (64) + fixed body before buffer (32 bytes) = 96
        let bufferOffset: UInt16 = UInt16(smb2HeaderSize) + 32

        var w = ByteWriter()
        w.uint16le(structureSize)           // StructureSize (33)
        w.uint8(infoType)                   // InfoType
        w.uint8(fileInfoClass)              // FileInfoClass
        w.uint32le(UInt32(buffer.count))    // BufferLength
        w.uint16le(bufferOffset)            // BufferOffset
        w.zeros(2)                          // Reserved
        w.uint32le(0)                       // AdditionalInformation
        fileId.write(to: &w)                // FileId (16 bytes)
        w.bytes(buffer)                     // Buffer (variable data)
        return w.data
    }
}

// MARK: - SET_INFO Response Parser

/// Parsed SET_INFO response. The response is trivial — it only contains a StructureSize.
public struct SMB2SetInfoResponse {
    public let structureSize: UInt16

    /// Expected StructureSize for a SET_INFO response.
    public static let expectedStructureSize: UInt16 = 2

    /// Parse a SET_INFO response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2SetInfoResponse {
        var r = ByteReader(data)
        let structureSize = try r.uint16le()
        return SMB2SetInfoResponse(structureSize: structureSize)
    }
}
