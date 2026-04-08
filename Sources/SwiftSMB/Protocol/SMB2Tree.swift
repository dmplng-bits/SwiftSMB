//
//  SMB2Tree.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 TREE_CONNECT and TREE_DISCONNECT ([MS-SMB2] §2.2.9–2.2.12).
//
// TREE_CONNECT maps a UNC share path (e.g. \\server\share) to a TreeId.
// All subsequent file operations use that TreeId.

import Foundation

// MARK: - TREE_CONNECT Request Builder

public enum SMB2TreeConnectRequest {

    /// StructureSize for TREE_CONNECT request is always 9.
    public static let structureSize: UInt16 = 9

    /// Build a TREE_CONNECT request body.
    ///
    /// - `path`: The UNC share path, e.g. "\\\\192.168.1.100\\Videos".
    ///   Will be encoded as UTF-16LE.
    public static func build(path: String) -> Data {
        let pathData = path.utf16leData

        // PathOffset is relative to header start.
        // Header (64) + fixed body (8 bytes: structSize + reserved/flags + pathOffset + pathLength) = 72
        let pathOffset: UInt16 = UInt16(smb2HeaderSize) + 8

        var w = ByteWriter()
        w.uint16le(structureSize)            // StructureSize (9)
        w.uint16le(0)                        // Flags / Reserved
        w.uint16le(pathOffset)               // PathOffset
        w.uint16le(UInt16(pathData.count))   // PathLength
        w.bytes(pathData)                    // Buffer (UTF-16LE path)
        return w.data
    }
}

// MARK: - TREE_CONNECT Response Parser

/// Parsed fields from a TREE_CONNECT response body.
public struct SMB2TreeConnectResponse {
    public let structureSize:    UInt16
    public let shareType:        UInt8
    public let shareFlags:       UInt32
    public let capabilities:     UInt32
    public let maximalAccess:    UInt32
}

extension SMB2TreeConnectResponse {

    /// Expected StructureSize for a TREE_CONNECT response.
    public static let expectedStructureSize: UInt16 = 16

    /// Parse a TREE_CONNECT response body (data after the 64-byte header).
    public static func parse(_ data: Data) throws -> SMB2TreeConnectResponse {
        var r = ByteReader(data)

        let structureSize = try r.uint16le()
        let shareType     = try r.uint8()
        let _             = try r.uint8()      // Reserved
        let shareFlags    = try r.uint32le()
        let capabilities  = try r.uint32le()
        let maximalAccess = try r.uint32le()

        return SMB2TreeConnectResponse(
            structureSize:  structureSize,
            shareType:      shareType,
            shareFlags:     shareFlags,
            capabilities:   capabilities,
            maximalAccess:  maximalAccess
        )
    }
}

// MARK: - TREE_DISCONNECT Request Builder

public enum SMB2TreeDisconnectRequest {

    /// StructureSize for TREE_DISCONNECT request is always 4.
    public static let structureSize: UInt16 = 4

    /// Build a TREE_DISCONNECT request body.
    public static func build() -> Data {
        var w = ByteWriter()
        w.uint16le(structureSize)    // StructureSize (4)
        w.zeros(2)                   // Reserved
        return w.data
    }
}

// MARK: - TREE_DISCONNECT Response Parser

/// Parsed TREE_DISCONNECT response. Minimal — just the structure size.
public struct SMB2TreeDisconnectResponse {
    public let structureSize: UInt16
}

extension SMB2TreeDisconnectResponse {

    public static let expectedStructureSize: UInt16 = 4

    public static func parse(_ data: Data) throws -> SMB2TreeDisconnectResponse {
        var r = ByteReader(data)
        let structureSize = try r.uint16le()
        return SMB2TreeDisconnectResponse(structureSize: structureSize)
    }
}
