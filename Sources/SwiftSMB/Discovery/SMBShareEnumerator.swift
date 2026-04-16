//
//  SMBShareEnumerator.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Lists the shares available on an SMB server using the SrvSvc RPC
// (NetShareEnumAll) over the IPC$ named pipe.
//
// Flow:
//   1. Connect to the server and authenticate (reuse existing session).
//   2. TREE_CONNECT to "IPC$".
//   3. CREATE (open) the named pipe "\srvsvc".
//   4. Write a DCE/RPC Bind request for the SrvSvc interface.
//   5. Write a NetShareEnumAll request.
//   6. Parse the NDR-encoded response to extract share names and types.
//   7. CLOSE the pipe, TREE_DISCONNECT from IPC$.
//
// This is intentionally minimal — only NetShareEnumAll (opnum 15) is
// implemented because it's all a media-player browser needs. The NDR
// and DCE/RPC encoding is done inline rather than through a generic
// codec, since we only have one operation.

import Foundation

/// A share advertised by the server.
public struct SMBShareInfo: Sendable, Hashable, Identifiable {
    /// Share name (e.g. "Videos", "IPC$", "ADMIN$").
    public let name: String
    /// Share type: disk (0), printer (1), device (2), IPC (3).
    public let type: UInt32
    /// Optional comment/description.
    public let comment: String

    public var id: String { name }

    /// True if this is a normal disk share (the kind a media player cares about).
    public var isDisk: Bool { type & 0x0FFF_FFFF == 0 }
    /// True if this is a special admin/IPC share (e.g. IPC$, ADMIN$, C$).
    public var isSpecial: Bool { type & 0x8000_0000 != 0 }
}

/// Lists shares on an SMB server.
///
/// Usage:
///   let shares = try await SMBShareEnumerator.listShares(
///       host: "192.168.1.100",
///       credentials: SMBCredentials(user: "me", password: "pw")
///   )
///   let diskShares = shares.filter { $0.isDisk && !$0.isSpecial }
public enum SMBShareEnumerator {

    // ── Well-known UUIDs ───────────────────────────────────────────────

    /// SrvSvc interface UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188
    private static let srvsvcUUID: [UInt8] = [
        0xC8, 0x4F, 0x32, 0x4B,   // TimeLow  (LE)
        0x70, 0x16,                 // TimeMid  (LE)
        0xD3, 0x01,                 // TimeHi   (LE)
        0x12, 0x78,                 // ClockSeq (BE)
        0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88  // Node
    ]

    /// NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
    private static let ndrUUID: [UInt8] = [
        0x04, 0x5D, 0x88, 0x8A,
        0xEB, 0x1C,
        0xC9, 0x11,
        0x9F, 0xE8,
        0x08, 0x00, 0x2B, 0x10, 0x48, 0x60
    ]

    // MARK: - Public API

    /// Connect, enumerate shares, and disconnect. Standalone convenience.
    public static func listShares(
        host: String,
        port: UInt16 = 445,
        credentials: SMBCredentials
    ) async throws -> [SMBShareInfo] {
        let session = SMBSession(host: host, port: port)
        let ipcPath = "\\\\\(host)\\IPC$"

        try await session.connectShare(ipcPath, credentials: credentials)

        let shares = try await enumerateShares(session: session, serverName: host)
        await session.disconnect()
        return shares
    }

    /// Enumerate shares using an already-connected session. The session
    /// must be tree-connected to "IPC$".
    ///
    /// - `serverName`: optional override for the NetShareEnumAll
    ///   `ServerName` field. If `nil`, the host stored on the session is
    ///   used. Strict Samba (4.x+, TrueNAS Scale) rejects an empty
    ///   ServerName with STATUS_INVALID_PARAMETER, so we always send
    ///   `\\<host>` here.
    public static func enumerateShares(
        session: SMBSession,
        serverName: String? = nil
    ) async throws -> [SMBShareInfo] {
        // `??` takes its RHS as a non-async @autoclosure, so we can't fold
        // `await session.currentHost` into it. Resolve the name explicitly.
        let resolvedName: String
        if let explicit = serverName {
            resolvedName = explicit
        } else {
            resolvedName = await session.currentHost
        }
        // Open the srvsvc named pipe.
        let pipeBody = SMB2CreateRequest.build(
            path: "srvsvc",
            desiredAccess: SMB2AccessMask.genericRead | SMB2AccessMask.genericWrite,
            shareAccess: SMB2ShareAccess.read | SMB2ShareAccess.write,
            createDisposition: SMB2CreateDisposition.openIf,
            createOptions: 0
        )
        let (createHeader, createResp) = try await session.sendRequest(
            command: SMB2Command.create,
            body: pipeBody
        )
        guard createHeader.isSuccess else {
            throw SMBError.shareEnumerationFailed("Failed to open srvsvc pipe: 0x\(String(createHeader.status, radix: 16))")
        }
        let fileId = try SMB2CreateResponse.parse(createResp).fileId

        do {
            // Step 1: DCE/RPC Bind to the SrvSvc interface.
            let bindData = buildRPCBind()
            try await writePipe(session: session, fileId: fileId, data: bindData)
            let bindResp = try await readPipe(session: session, fileId: fileId)
            // We don't parse Bind Ack in detail — just check we got something.
            guard bindResp.count >= 24 else {
                throw SMBError.shareEnumerationFailed("Invalid Bind Ack")
            }

            // Step 2: NetShareEnumAll (opnum 15).
            let enumData = buildNetShareEnumAll(serverName: resolvedName)
            try await writePipe(session: session, fileId: fileId, data: enumData)
            let enumResp = try await readPipe(session: session, fileId: fileId)

            let shares = try parseNetShareEnumAllResponse(enumResp)

            // Close the pipe handle.
            let closeBody = SMB2CloseRequest.build(fileId: fileId)
            _ = try? await session.sendRequest(command: SMB2Command.close, body: closeBody)

            return shares
        } catch {
            // Best-effort close on error.
            let closeBody = SMB2CloseRequest.build(fileId: fileId)
            _ = try? await session.sendRequest(command: SMB2Command.close, body: closeBody)
            throw error
        }
    }

    // MARK: - Pipe I/O helpers

    private static func writePipe(
        session: SMBSession,
        fileId: SMB2FileId,
        data: Data
    ) async throws {
        // SMB2 WRITE to the pipe.
        var w = ByteWriter()
        w.uint16le(49)                       // StructureSize
        w.uint16le(UInt16(smb2HeaderSize + 48)) // DataOffset (header + 48 bytes of fixed body)
        w.uint32le(UInt32(data.count))       // Length
        w.uint64le(0)                        // Offset (not used for pipes)
        fileId.write(to: &w)                 // FileId
        w.uint32le(0)                        // Channel
        w.uint32le(0)                        // RemainingBytes
        w.uint16le(0)                        // WriteChannelInfoOffset
        w.uint16le(0)                        // WriteChannelInfoLength
        w.uint32le(0)                        // Flags
        w.bytes(data)                        // Buffer

        let (header, _) = try await session.sendRequest(
            command: SMB2Command.write,
            body: w.data,
            payloadSize: data.count
        )
        guard header.isSuccess else {
            throw SMBError.shareEnumerationFailed("Write to pipe failed: 0x\(String(header.status, radix: 16))")
        }
    }

    private static func readPipe(
        session: SMBSession,
        fileId: SMB2FileId
    ) async throws -> Data {
        let body = SMB2ReadRequest.build(
            fileId: fileId,
            offset: 0,
            length: 65536
        )
        let (header, respBody) = try await session.sendRequest(
            command: SMB2Command.read,
            body: body,
            payloadSize: 65536
        )
        guard header.isSuccess else {
            throw SMBError.shareEnumerationFailed("Read from pipe failed: 0x\(String(header.status, radix: 16))")
        }
        let parsed = try SMB2ReadResponse.parse(respBody)
        return parsed.data
    }

    // MARK: - DCE/RPC Bind

    /// Build a minimal DCE/RPC Bind PDU for the SrvSvc interface.
    private static func buildRPCBind() -> Data {
        var w = ByteWriter()
        // RPC Header (common fields)
        w.uint8(5)             // rpc_vers (5)
        w.uint8(0)             // rpc_vers_minor
        w.uint8(0x0B)          // PTYPE = Bind (11)
        w.uint8(0x03)          // pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
        // Data representation (little-endian, ASCII, IEEE float)
        w.bytes(Data([0x10, 0x00, 0x00, 0x00]))
        // Frag length — we'll fix this at the end.
        let fragLenOffset = w.data.count
        w.uint16le(0)          // placeholder
        w.uint16le(0)          // auth_length
        w.uint32le(0)          // call_id

        // Bind-specific fields
        w.uint16le(4280)       // max_xmit_frag
        w.uint16le(4280)       // max_recv_frag
        w.uint32le(0)          // assoc_group

        // Context list: 1 context
        w.uint8(1)             // num_contexts
        w.zeros(3)             // padding

        // Context 0
        w.uint16le(0)          // context_id
        w.uint8(1)             // num_trans_syntaxes
        w.uint8(0)             // padding

        // Abstract syntax: SrvSvc UUID v3.0
        w.bytes(Data(srvsvcUUID))
        w.uint16le(3)          // if_version major
        w.uint16le(0)          // if_version minor

        // Transfer syntax: NDR v2.0
        w.bytes(Data(ndrUUID))
        w.uint16le(2)          // syntax_version major
        w.uint16le(0)          // syntax_version minor

        // Fix up frag length.
        let totalLen = UInt16(w.data.count)
        w.patchUint16le(totalLen, at: fragLenOffset)

        return w.data
    }

    // MARK: - NetShareEnumAll

    /// Build a DCE/RPC Request PDU for NetShareEnumAll (opnum 15).
    ///
    /// `serverName` is sent as the NDR `ServerName` parameter wrapped in
    /// `\\HOST` form — strict Samba rejects an empty server name with
    /// STATUS_INVALID_PARAMETER, and Windows happily accepts the UNC.
    private static func buildNetShareEnumAll(serverName: String) -> Data {
        var w = ByteWriter()
        // RPC Header
        w.uint8(5)             // rpc_vers
        w.uint8(0)             // rpc_vers_minor
        w.uint8(0x00)          // PTYPE = Request (0)
        w.uint8(0x03)          // pfc_flags
        w.bytes(Data([0x10, 0x00, 0x00, 0x00]))  // data rep
        let fragLenOffset = w.data.count
        w.uint16le(0)          // placeholder frag_length
        w.uint16le(0)          // auth_length
        w.uint32le(1)          // call_id

        // Request-specific
        w.uint32le(0)          // alloc_hint (0 = unknown)
        w.uint16le(0)          // context_id
        w.uint16le(15)         // opnum = NetShareEnumAll

        // ── Stub data (NDR-encoded NetShareEnumAll parameters) ─────────
        // ServerName: unique pointer to a conformant varying UTF-16LE
        // string. Per [MS-SRVS] §3.1.4.8 the string is a UNC of the form
        // `\\<server>\0` (NUL-terminated). Empty / NULL ServerName is
        // legal on Windows but rejected by Samba 4.x with
        // STATUS_INVALID_PARAMETER, so we always send a real name.
        let unc = serverName.hasPrefix("\\\\") ? serverName : "\\\\\(serverName)"
        let serverChars = Array(unc.utf16) + [0]            // UTF-16 + NUL
        let serverByteCount = serverChars.count * 2
        let charCount = UInt32(serverChars.count)

        w.uint32le(0x00020000)            // referent id (non-null)
        w.uint32le(charCount)             // max_count   (capacity in wchars)
        w.uint32le(0)                     // offset
        w.uint32le(charCount)             // actual_count (incl. NUL)
        for cu in serverChars {           // UTF-16LE characters
            w.uint16le(cu)
        }
        // Pad to 4-byte alignment for the next NDR primitive (Level).
        // Header so far:
        //   referent(4) + max(4) + offset(4) + actual(4) + chars(2*N)
        // = 16 + 2*N  — pad if N is odd.
        let stubBytesAfterServer = 16 + serverByteCount
        let pad = (4 - (stubBytesAfterServer % 4)) % 4
        if pad > 0 { w.zeros(pad) }

        // InfoStruct (SHARE_ENUM_STRUCT)
        w.uint32le(1)          // Level = 1 (SHARE_INFO_1)
        w.uint32le(1)          // Switch value = 1
        // SHARE_INFO_1_CONTAINER
        w.uint32le(0x00020004) // referent id for the container
        w.uint32le(0)          // EntriesRead (server fills this in on response)
        w.uint32le(0)          // NULL Buffer pointer (no input array)

        // PreferedMaximumLength
        w.uint32le(0xFFFFFFFF) // -1 = no limit

        // ResumeHandle (unique pointer to ULONG, value = 0)
        w.uint32le(0x00020008) // referent id (non-null per [MS-SRVS])
        w.uint32le(0)          // ResumeHandle value

        // Fix up frag length
        let totalLen = UInt16(w.data.count)
        w.patchUint16le(totalLen, at: fragLenOffset)

        return w.data
    }

    /// Parse the NDR-encoded NetShareEnumAll response from the DCE/RPC
    /// Response PDU. We extract share names, types, and comments.
    private static func parseNetShareEnumAllResponse(
        _ data: Data
    ) throws -> [SMBShareInfo] {
        // Skip the RPC response header (24 bytes) to get to the stub data.
        guard data.count > 24 else {
            throw SMBError.shareEnumerationFailed("Response too short")
        }
        let stub = Data(data.suffix(from: data.startIndex + 24))
        var r = ByteReader(stub)

        // InfoStruct response:
        //   Level (4)
        //   Switch (4)
        //   Referent ID (4) for container
        //   EntriesRead (4)
        //   Referent ID (4) for array
        //   MaxCount (4)
        //   Then: array of { Referent(name), Type, Referent(comment) }
        //   Then: conformant strings for names and comments
        _ = try r.uint32le()  // Level
        _ = try r.uint32le()  // Switch
        _ = try r.uint32le()  // Container referent
        let entriesRead = try r.uint32le()
        _ = try r.uint32le()  // Array referent
        let maxCount = try r.uint32le()

        guard entriesRead > 0, maxCount >= entriesRead else {
            return []
        }
        guard entriesRead < 10000 else {
            throw SMBError.shareEnumerationFailed("Unreasonable entry count: \(entriesRead)")
        }

        // Read the array of fixed-size entries (12 bytes each).
        struct RawEntry {
            var nameRef:    UInt32
            var shareType:  UInt32
            var commentRef: UInt32
        }
        var rawEntries: [RawEntry] = []
        for _ in 0..<entriesRead {
            let nameRef    = try r.uint32le()
            let shareType  = try r.uint32le()
            let commentRef = try r.uint32le()
            rawEntries.append(RawEntry(nameRef: nameRef, shareType: shareType, commentRef: commentRef))
        }

        // Now read the conformant + varying strings. Each string is:
        //   MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE data + padding
        func readNDRString() throws -> String {
            let _          = try r.uint32le()  // max_count
            let _          = try r.uint32le()  // offset
            let actualCount = try r.uint32le()
            guard actualCount < 10000 else {
                throw SMBError.shareEnumerationFailed("String too long")
            }
            let byteCount = Int(actualCount) * 2
            guard r.remaining >= byteCount else {
                throw SMBError.shareEnumerationFailed("Truncated string")
            }
            let strData = try r.bytes(byteCount)
            // Align to 4-byte boundary.
            let total = 12 + byteCount
            let padding = (4 - (total % 4)) % 4
            if padding > 0 && r.remaining >= padding {
                try r.skip(padding)
            }
            // Trim trailing null.
            var trimmed = strData
            while trimmed.count >= 2 &&
                  trimmed[trimmed.endIndex - 2] == 0 &&
                  trimmed[trimmed.endIndex - 1] == 0 {
                trimmed = trimmed.dropLast(2)
            }
            return trimmed.utf16leString
        }

        var shares: [SMBShareInfo] = []
        for entry in rawEntries {
            // In NDR a referent id of 0 means NULL — the string body is
            // simply omitted from the wire. Reading unconditionally would
            // consume 12 bytes of something else and desync the buffer.
            // [MS-SRVS] allows NULL for both NetName and Remark, so guard.
            let name:    String
            let comment: String
            do {
                name    = entry.nameRef    != 0 ? try readNDRString() : ""
                comment = entry.commentRef != 0 ? try readNDRString() : ""
            } catch {
                // If we can't parse the remaining strings, return what we have.
                break
            }
            shares.append(SMBShareInfo(
                name:    name,
                type:    entry.shareType,
                comment: comment
            ))
        }

        return shares
    }
}
