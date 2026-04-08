//
//  SMB2Header.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Every SMB2 packet begins with a 64-byte header.
// This file provides the builder (for requests) and parser (for responses).
//
// Layout (64 bytes):
//   0..3    ProtocolId          0xFE 'S' 'M' 'B'
//   4..5    StructureSize       Always 64
//   6..7    CreditCharge        Credits charged for this operation
//   8..11   Status / ChannelSeq NT status (response) or channel seq (request)
//  12..13   Command             SMB2 command code
//  14..15   CreditReq/Granted   Credits requested (req) or granted (resp)
//  16..19   Flags               SMB2_FLAGS_*
//  20..23   NextCommand         Offset to next command in compounded chain (0 if none)
//  24..31   MessageId           Sequence number
//  32..35   Reserved / TreeId   Process ID (request) or reserved
//  36..39   TreeId              Tree identifier (0 before TREE_CONNECT)
//  40..47   SessionId           Session identifier (0 before SESSION_SETUP)
//  48..63   Signature           16 bytes (zeroed if not signing)

import Foundation

// MARK: - SMB2Header (parsed response header)

/// Parsed fields from a 64-byte SMB2 response header.
public struct SMB2Header {
    public let protocolId:    UInt32
    public let structureSize: UInt16
    public let creditCharge:  UInt16
    public let status:        UInt32
    public let command:       UInt16
    public let creditGranted: UInt16
    public let flags:         UInt32
    public let nextCommand:   UInt32
    public let messageId:     UInt64
    public let treeId:        UInt32
    public let sessionId:     UInt64
    public let signature:     Data      // 16 bytes

    /// True if this is a response (server → client).
    public var isResponse: Bool {
        flags & SMB2Flags.serverToRedir != 0
    }

    /// True if the NT status indicates success.
    public var isSuccess: Bool {
        status == NTStatus.success
    }

    /// True if the server says "keep going" (used during SESSION_SETUP auth).
    public var isMoreProcessingRequired: Bool {
        status == NTStatus.moreProcessingRequired
    }
}

// MARK: - Parsing

extension SMB2Header {

    /// Parse a 64-byte SMB2 header from raw data.
    /// The data must contain at least 64 bytes.
    public static func parse(_ data: Data) throws -> SMB2Header {
        guard data.count >= smb2HeaderSize else {
            throw SMBError.truncatedPacket
        }

        var r = ByteReader(data)

        let protocolId    = try r.uint32le()
        guard protocolId == smb2ProtocolId else {
            throw SMBError.invalidProtocolId
        }

        let structureSize = try r.uint16le()
        let creditCharge  = try r.uint16le()
        let status        = try r.uint32le()
        let command       = try r.uint16le()
        let creditGranted = try r.uint16le()
        let flags         = try r.uint32le()
        let nextCommand   = try r.uint32le()
        let messageId     = try r.uint64le()
        let _             = try r.uint32le()   // reserved / processId
        let treeId        = try r.uint32le()
        let sessionId     = try r.uint64le()
        let signature     = try r.bytes(16)

        return SMB2Header(
            protocolId:    protocolId,
            structureSize: structureSize,
            creditCharge:  creditCharge,
            status:        status,
            command:       command,
            creditGranted: creditGranted,
            flags:         flags,
            nextCommand:   nextCommand,
            messageId:     messageId,
            treeId:        treeId,
            sessionId:     sessionId,
            signature:     signature
        )
    }
}

// MARK: - Building

/// Builds the 64-byte SMB2 request header.
///
/// Usage:
///   let header = SMB2HeaderBuilder.build(
///       command: SMB2Command.negotiate,
///       messageId: 0,
///       sessionId: 0,
///       treeId: 0
///   )
public enum SMB2HeaderBuilder {

    /// Build a 64-byte SMB2 request header.
    ///
    /// - `creditCharge`: credits this operation costs (default 1).
    /// - `creditRequest`: credits we want the server to grant (default 32).
    /// - `flags`: SMB2 header flags (default 0 for requests).
    public static func build(
        command: UInt16,
        creditCharge: UInt16 = 1,
        creditRequest: UInt16 = 32,
        flags: UInt32 = 0,
        nextCommand: UInt32 = 0,
        messageId: UInt64,
        sessionId: UInt64 = 0,
        treeId: UInt32 = 0
    ) -> Data {
        var w = ByteWriter()
        w.uint32le(smb2ProtocolId)          //  0..3   ProtocolId
        w.uint16le(smb2HeaderStructureSize) //  4..5   StructureSize (always 64)
        w.uint16le(creditCharge)            //  6..7   CreditCharge
        w.uint32le(0)                       //  8..11  Status (0 for requests)
        w.uint16le(command)                 // 12..13  Command
        w.uint16le(creditRequest)           // 14..15  CreditRequest
        w.uint32le(flags)                   // 16..19  Flags
        w.uint32le(nextCommand)             // 20..23  NextCommand
        w.uint64le(messageId)               // 24..31  MessageId
        w.uint32le(0)                       // 32..35  Reserved (ProcessId)
        w.uint32le(treeId)                  // 36..39  TreeId
        w.uint64le(sessionId)               // 40..47  SessionId
        w.zeros(16)                         // 48..63  Signature (zeroed)
        return w.data
    }
}
