//
//  SMBWireFormatTests.swift
//  SwiftSMB
//
// Byte-exact wire-format tests for the two requests that started
// returning STATUS_INVALID_PARAMETER against modern Samba:
//
//  * SMB2 TREE_CONNECT Request     ([MS-SMB2] §2.2.9)
//  * DCE/RPC NetrShareEnum stub    ([MS-SRVS] §3.1.4.8, opnum 15)
//
// Each test builds the request with the real shipping code and then
// compares every byte against a hand-computed reference derived from
// the spec. If any byte differs, the failure message prints a full
// hex dump of both the expected and actual bytes so the mismatch is
// pinpointed instantly — no Wireshark round-trip needed.
//
// Reference cross-checked with:
//  1. An independent Python oracle (see scripts/oracle.py in the repo
//     history).
//  2. kishikawakatsumi/SMBClient — a widely-used open-source Swift
//     SMB library known to interop with Samba/TrueNAS.

import XCTest
@testable import SwiftSMB

final class SMBWireFormatTests: XCTestCase {

    // ════════════════════════════════════════════════════════════════════
    // MARK: - TREE_CONNECT Request
    // ════════════════════════════════════════════════════════════════════

    /// Build TREE_CONNECT for `\\192.168.1.100\Videos` and compare every
    /// byte against the spec.
    func testTreeConnectRequest_ipHost_VideosShare() {
        let path = #"\\192.168.1.100\Videos"#
        let body = SMB2TreeConnectRequest.build(path: path)

        // Hand-assembled reference per [MS-SMB2] §2.2.9:
        //   StructureSize  = 9      (2 bytes)
        //   Flags/Reserved = 0      (2 bytes)
        //   PathOffset     = 72     (2 bytes) — from start of SMB2 header
        //   PathLength     = 44     (2 bytes) — 22 wchars × 2
        //   Buffer         = UTF-16LE "\\192.168.1.100\Videos"  (44 bytes)
        var expected = Data()
        expected.append(contentsOf: [0x09, 0x00])           // StructureSize
        expected.append(contentsOf: [0x00, 0x00])           // Flags
        expected.append(contentsOf: [0x48, 0x00])           // PathOffset = 72
        expected.append(contentsOf: [0x2C, 0x00])           // PathLength = 44
        expected.append(path.utf16leData)

        assertEqualBytes(body, expected,
                         "TREE_CONNECT body for \(path)")
    }

    /// Build TREE_CONNECT for `\\HOST\IPC$` (what the share enumerator uses).
    func testTreeConnectRequest_namedHost_IPCShare() {
        let path = #"\\HOST\IPC$"#
        let body = SMB2TreeConnectRequest.build(path: path)

        var expected = Data()
        expected.append(contentsOf: [0x09, 0x00])           // StructureSize = 9
        expected.append(contentsOf: [0x00, 0x00])           // Flags/Reserved
        expected.append(contentsOf: [0x48, 0x00])           // PathOffset = 72
        expected.append(contentsOf: [0x16, 0x00])           // PathLength = 22
        expected.append(path.utf16leData)

        assertEqualBytes(body, expected,
                         "TREE_CONNECT body for \(path)")
    }

    /// Spot-check individual fields (StructureSize = 9, PathOffset = 72,
    /// no NUL, no BOM, pure UTF-16LE) against [MS-SMB2] §2.2.9 rules.
    func testTreeConnectRequest_fieldInvariants() throws {
        let path = #"\\server\share"#
        let body = SMB2TreeConnectRequest.build(path: path)

        var r = ByteReader(body)

        let structSize   = try r.uint16le()
        let flags        = try r.uint16le()
        let pathOffset   = try r.uint16le()
        let pathLength   = try r.uint16le()
        let bufferStart  = 8

        XCTAssertEqual(structSize, 9,
            "MS-SMB2 §2.2.9: StructureSize MUST be 9 for TREE_CONNECT request")
        XCTAssertEqual(flags, 0,
            "Flags/Reserved must be 0 unless SMB 3.1.1 cluster reconnect is set")
        XCTAssertEqual(pathOffset, UInt16(smb2HeaderSize + 8),
            "PathOffset MUST be offset from start of SMB2 header to Buffer " +
            "(header 64 + fixed body 8 = 72)")
        XCTAssertEqual(Int(pathLength), path.utf16leData.count,
            "PathLength MUST equal UTF-16LE byte count (no NUL, no BOM)")

        let bufferBytes = body.subdata(in: body.startIndex + bufferStart ..< body.endIndex)
        XCTAssertEqual(bufferBytes, path.utf16leData,
            "Buffer MUST be pure UTF-16LE path bytes, no trailing NUL, no BOM")
    }

    /// Make sure the path survives a UNC with dots, a share name with
    /// `$`, and mixed case — all legal per UNC rules.
    func testTreeConnectRequest_specialShareNames() throws {
        let cases = [
            #"\\nas.local\Media"#,
            #"\\10.0.0.42\ADMIN$"#,
            #"\\TrueNAS\Users Home"#,
        ]
        for path in cases {
            let body = SMB2TreeConnectRequest.build(path: path)
            var r = ByteReader(body)
            _ = try r.uint16le()       // structSize
            _ = try r.uint16le()       // flags
            _ = try r.uint16le()       // pathOffset
            let pathLength = try r.uint16le()
            let buf = body.subdata(in: body.startIndex + 8 ..< body.endIndex)
            XCTAssertEqual(buf.count, Int(pathLength),
                "PathLength must match buffer size for \(path)")
            XCTAssertEqual(buf.utf16leString, path,
                "Round-tripped UTF-16LE must match for \(path)")
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - NetrShareEnum Request Stub (NDR)
    // ════════════════════════════════════════════════════════════════════

    /// Build NetrShareEnum request for `192.168.1.100` and compare the
    /// full PDU against a hand-computed reference per [MS-SRVS] §3.1.4.8.
    func testNetShareEnumAll_ipHost_fullPdu() {
        let host = "192.168.1.100"
        let pdu = SMBShareEnumerator.buildNetShareEnumAll(serverName: host)

        // RPC request header (24 bytes).
        //  00: rpc_vers        = 5
        //  01: rpc_vers_minor  = 0
        //  02: PTYPE           = 0 (Request)
        //  03: pfc_flags       = 0x03 (FIRST|LAST)
        //  04..07: data rep    = 10 00 00 00
        //  08..09: frag_length = filled in last, total size
        //  0A..0B: auth_length = 0
        //  0C..0F: call_id     = 1
        //  10..13: alloc_hint  = 0
        //  14..15: ctx_id      = 0
        //  16..17: opnum       = 15 (NetrShareEnum)
        var expected = Data()
        expected.append(contentsOf: [0x05, 0x00, 0x00, 0x03])        // vers, ptype, flags
        expected.append(contentsOf: [0x10, 0x00, 0x00, 0x00])        // data rep
        // frag_length placeholder — will fix up after counting stub
        let fragLenIndex = expected.count
        expected.append(contentsOf: [0x00, 0x00])
        expected.append(contentsOf: [0x00, 0x00])                    // auth_length
        expected.append(contentsOf: [0x01, 0x00, 0x00, 0x00])        // call_id
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])        // alloc_hint
        expected.append(contentsOf: [0x00, 0x00])                    // context_id
        expected.append(contentsOf: [0x0F, 0x00])                    // opnum = 15

        // NDR stub.
        //   ServerName: [unique, string] SRVSVC_HANDLE
        //     referent (4)   = 00 00 02 00
        //     max_count (4)  = char count incl. NUL = 16
        //     offset (4)     = 0
        //     actual (4)     = 16
        //     UTF-16LE chars = "\\192.168.1.100\0"  = 32 bytes
        //     pad to 4-byte  = 0 bytes (16*2 = 32 already aligned)
        //   SHARE_ENUM_STRUCT
        //     Level (4)      = 1
        //     Switch (4)     = 1
        //     Container* referent (4) = 04 00 02 00
        //     EntriesRead (4) = 0
        //     Buffer referent (4) = 0 (NULL)
        //   PreferedMaximumLength (4) = 0xFFFFFFFF
        //   ResumeHandle: [unique] DWORD*
        //     referent (4)   = 08 00 02 00
        //     value (4)      = 0
        let unc = #"\\"# + host                             // "\\192.168.1.100"
        let chars = Array(unc.utf16) + [0]                  // + NUL
        let charCount = UInt32(chars.count)                 // 16

        expected.append(contentsOf: [0x00, 0x00, 0x02, 0x00])   // referent
        expected.append(leUInt32(charCount))                    // max_count
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])   // offset
        expected.append(leUInt32(charCount))                    // actual_count
        for cu in chars { expected.append(leUInt16(cu)) }       // UTF-16LE chars

        // Alignment pad: chars section is charCount*2 bytes. With 16 chars
        // that's 32 bytes → already 4-byte aligned → no pad.
        let serverPad = (4 - ((16 + Int(charCount) * 2) % 4)) % 4
        expected.append(Data(count: serverPad))

        expected.append(contentsOf: [0x01, 0x00, 0x00, 0x00])   // Level = 1
        expected.append(contentsOf: [0x01, 0x00, 0x00, 0x00])   // Switch = 1
        expected.append(contentsOf: [0x04, 0x00, 0x02, 0x00])   // Container referent
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])   // EntriesRead
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])   // NULL Buffer
        expected.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])   // PreferedMax
        expected.append(contentsOf: [0x08, 0x00, 0x02, 0x00])   // ResumeHandle referent
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])   // ResumeHandle value

        // Fix up frag_length in expected.
        let fragLen = UInt16(expected.count)
        expected.replaceSubrange(fragLenIndex ..< fragLenIndex + 2,
                                 with: leUInt16(fragLen))

        assertEqualBytes(pdu, expected,
                         "NetrShareEnum PDU for host=\(host)")
    }

    /// Short hostname case — forces the 4-byte-alignment pad to be
    /// non-zero. With host "HOST", we get UNC "\\HOST\0" = 7 wchars =
    /// 14 bytes of chars → 16+14 = 30, pad = 2.
    func testNetShareEnumAll_shortHost_paddingCorrect() throws {
        let host = "HOST"
        let pdu = SMBShareEnumerator.buildNetShareEnumAll(serverName: host)

        // Walk the PDU and verify the padding byte count lands the
        // next field (Level) on a 4-byte boundary.
        //   24 bytes RPC header
        // + 4  referent
        // + 12 max/offset/actual
        // + 14 chars (\\HOST\0)
        // = 54 → pad 2 → Level sits at offset 56.
        var r = ByteReader(pdu)
        try r.skip(24)                                     // RPC header
        _ = try r.uint32le()                               // referent
        let maxCount = try r.uint32le()
        _ = try r.uint32le()                               // offset
        let actualCount = try r.uint32le()
        try r.skip(Int(actualCount) * 2)                   // chars

        XCTAssertEqual(maxCount,    7, "max_count should be 7 wchars (\\\\HOST\\0)")
        XCTAssertEqual(actualCount, 7, "actual_count should be 7 wchars")

        // Now the two pad bytes must be zero and the very next 4 bytes
        // must be Level = 1 (0x01 0x00 0x00 0x00).
        let padByte1 = try r.uint8()
        let padByte2 = try r.uint8()
        XCTAssertEqual(padByte1, 0, "First NDR alignment pad byte must be 0")
        XCTAssertEqual(padByte2, 0, "Second NDR alignment pad byte must be 0")

        let level = try r.uint32le()
        XCTAssertEqual(level, 1, "Level must land on a 4-byte boundary and equal 1")
    }

    /// Confirm the DCE/RPC Bind PDU is a valid SrvSvc bind:
    /// abstract-syntax = SrvSvc v3.0, transfer-syntax = NDR v2.0.
    func testRPCBind_abstractAndTransferSyntax() throws {
        let pdu = SMBShareEnumerator.buildRPCBind()

        // Layout: 16 B common header + 8 B bind-specific + 4 B context list
        // header + 4 B context0 preamble = 32 B, then abstract syntax UUID
        // at offset 32.
        XCTAssertGreaterThanOrEqual(pdu.count, 32 + 20 + 20,
            "Bind PDU must be at least large enough for one context")

        var r = ByteReader(pdu)
        try r.skip(32)                          // header + context list preamble

        // Abstract syntax
        let absUUID = try r.bytes(16)
        let absVerMajor = try r.uint16le()
        let absVerMinor = try r.uint16le()
        let expectedSrvSvc: [UInt8] = [
            0xC8, 0x4F, 0x32, 0x4B,
            0x70, 0x16,
            0xD3, 0x01,
            0x12, 0x78,
            0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88,
        ]
        XCTAssertEqual(Array(absUUID), expectedSrvSvc,
            "Abstract syntax must be SrvSvc UUID 4b324fc8-1670-01d3-1278-5a47bf6ee188")
        XCTAssertEqual(absVerMajor, 3, "SrvSvc major version must be 3")
        XCTAssertEqual(absVerMinor, 0, "SrvSvc minor version must be 0")

        // Transfer syntax
        let xferUUID = try r.bytes(16)
        let xferVerMajor = try r.uint16le()
        let xferVerMinor = try r.uint16le()
        let expectedNDR: [UInt8] = [
            0x04, 0x5D, 0x88, 0x8A,
            0xEB, 0x1C,
            0xC9, 0x11,
            0x9F, 0xE8,
            0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
        ]
        XCTAssertEqual(Array(xferUUID), expectedNDR,
            "Transfer syntax must be NDR UUID 8a885d04-1ceb-11c9-9fe8-08002b104860")
        XCTAssertEqual(xferVerMajor, 2, "NDR major version must be 2")
        XCTAssertEqual(xferVerMinor, 0, "NDR minor version must be 0")
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - Helpers
    // ════════════════════════════════════════════════════════════════════

    private func leUInt16(_ v: UInt16) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)])
    }

    private func leUInt32(_ v: UInt32) -> Data {
        Data([
            UInt8( v        & 0xFF),
            UInt8((v >>  8) & 0xFF),
            UInt8((v >> 16) & 0xFF),
            UInt8((v >> 24) & 0xFF),
        ])
    }

    /// Assert two byte blobs are identical, with a hex-dump diff on
    /// failure so the first differing offset is obvious.
    private func assertEqualBytes(
        _ actual: Data,
        _ expected: Data,
        _ label: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        if actual == expected { return }

        var message = "\(label): wire bytes differ.\n"
        message += "expected (\(expected.count) B):\n"
        message += hexDump(expected)
        message += "\n\nactual   (\(actual.count) B):\n"
        message += hexDump(actual)

        if let firstDiff = zip(expected, actual).enumerated().first(where: { $0.element.0 != $0.element.1 }) {
            message += "\n\nfirst diff at offset \(firstDiff.offset): " +
                       "expected=0x\(String(firstDiff.element.0, radix: 16)) " +
                       "actual=0x\(String(firstDiff.element.1, radix: 16))"
        }
        if actual.count != expected.count {
            message += "\nlength differs: expected=\(expected.count) actual=\(actual.count)"
        }
        XCTFail(message, file: file, line: line)
    }

    private func hexDump(_ data: Data) -> String {
        var out = ""
        let bytes = Array(data)
        let width = 16
        for i in stride(from: 0, to: bytes.count, by: width) {
            let chunk = bytes[i ..< min(i + width, bytes.count)]
            let hexColumns = chunk.map { String(format: "%02x", $0) }
                                  .joined(separator: " ")
                                  .padding(toLength: width * 3 - 1,
                                           withPad: " ",
                                           startingAt: 0)
            let ascii = chunk.map { (32 ..< 127).contains($0) ? String(UnicodeScalar($0)) : "." }
                             .joined()
            let offset = String(format: "%04x", i)
            out += "\(offset)  \(hexColumns)  \(ascii)\n"
        }
        return out
    }
}
