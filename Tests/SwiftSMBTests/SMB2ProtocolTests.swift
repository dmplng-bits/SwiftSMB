//
//  SMB2ProtocolTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//

import XCTest
@testable import SwiftSMB

final class SMB2ProtocolTests: XCTestCase {

    // ════════════════════════════════════════════════════════════════════
    // MARK: - Header
    // ════════════════════════════════════════════════════════════════════

    func testHeaderBuildSize() {
        let header = SMB2HeaderBuilder.build(
            command: SMB2Command.negotiate,
            messageId: 0
        )
        XCTAssertEqual(header.count, 64, "SMB2 header must be exactly 64 bytes")
    }

    func testHeaderProtocolId() {
        let header = SMB2HeaderBuilder.build(
            command: SMB2Command.negotiate,
            messageId: 0
        )
        var r = ByteReader(header)
        let protocolId = try! r.uint32le()
        XCTAssertEqual(protocolId, smb2ProtocolId, "First 4 bytes must be 0xFE 'S' 'M' 'B'")
    }

    func testHeaderRoundTrip() throws {
        let built = SMB2HeaderBuilder.build(
            command: SMB2Command.read,
            creditCharge: 2,
            creditRequest: 64,
            messageId: 42,
            sessionId: 0xDEAD_BEEF,
            treeId: 7
        )

        let parsed = try SMB2Header.parse(built)
        XCTAssertEqual(parsed.protocolId, smb2ProtocolId)
        XCTAssertEqual(parsed.structureSize, 64)
        XCTAssertEqual(parsed.command, SMB2Command.read)
        XCTAssertEqual(parsed.creditCharge, 2)
        XCTAssertEqual(parsed.creditGranted, 64) // in request this field is creditRequest
        XCTAssertEqual(parsed.messageId, 42)
        XCTAssertEqual(parsed.sessionId, 0xDEAD_BEEF)
        XCTAssertEqual(parsed.treeId, 7)
        XCTAssertFalse(parsed.isResponse)
    }

    func testHeaderParseRejectsInvalidProtocolId() {
        var bad = SMB2HeaderBuilder.build(command: SMB2Command.negotiate, messageId: 0)
        bad[0] = 0xFF  // corrupt magic
        XCTAssertThrowsError(try SMB2Header.parse(bad)) { error in
            XCTAssertEqual(error as? SMBError, .invalidProtocolId)
        }
    }

    func testHeaderParseTruncated() {
        let short = Data(count: 32)
        XCTAssertThrowsError(try SMB2Header.parse(short)) { error in
            XCTAssertEqual(error as? SMBError, .truncatedPacket)
        }
    }

    func testHeaderResponseFlags() throws {
        var data = SMB2HeaderBuilder.build(
            command: SMB2Command.negotiate,
            flags: SMB2Flags.serverToRedir,
            messageId: 0
        )
        // Set a success status
        data[8] = 0; data[9] = 0; data[10] = 0; data[11] = 0

        let parsed = try SMB2Header.parse(data)
        XCTAssertTrue(parsed.isResponse)
        XCTAssertTrue(parsed.isSuccess)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - NEGOTIATE
    // ════════════════════════════════════════════════════════════════════

    func testNegotiateRequestStructure() {
        let body = SMB2NegotiateRequest.build()
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 36)

        let dialectCount = try! r.uint16le()
        XCTAssertEqual(dialectCount, 4)  // default 4 dialects

        let securityMode = try! r.uint16le()
        XCTAssertTrue(securityMode & SMB2SecurityMode.signingEnabled != 0)
    }

    func testNegotiateRequestCustomDialects() {
        let body = SMB2NegotiateRequest.build(dialects: [SMB2Dialect.smb302])
        var r = ByteReader(body)

        _ = try! r.uint16le() // structureSize
        let dialectCount = try! r.uint16le()
        XCTAssertEqual(dialectCount, 1)

        try! r.skip(24) // skip to dialects array (securityMode + reserved + capabilities + guid + startTime)
        let dialect = try! r.uint16le()
        XCTAssertEqual(dialect, SMB2Dialect.smb302)
    }

    func testNegotiateResponseParse() throws {
        // Build a synthetic NEGOTIATE response body
        let body = buildSyntheticNegotiateResponse()
        let resp = try SMB2NegotiateResponse.parse(body)

        XCTAssertEqual(resp.dialectRevision, SMB2Dialect.smb302)
        XCTAssertEqual(resp.maxReadSize, 1048576)
        XCTAssertEqual(resp.serverGuid.count, 16)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - SESSION_SETUP
    // ════════════════════════════════════════════════════════════════════

    func testSessionSetupRequestContainsSecurityBuffer() {
        let fakeToken = Data(repeating: 0xAA, count: 32)
        let body = SMB2SessionSetupRequest.build(securityBuffer: fakeToken)
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 25)

        // The security buffer should be embedded at the end of the body
        XCTAssertTrue(body.count > 24 + fakeToken.count - 1)
    }

    func testSessionSetupResponseParse() throws {
        let body = buildSyntheticSessionSetupResponse()
        let resp = try SMB2SessionSetupResponse.parse(body)

        XCTAssertEqual(resp.structureSize, SMB2SessionSetupResponse.expectedStructureSize)
        XCTAssertEqual(resp.sessionFlags, 0)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - LOGOFF
    // ════════════════════════════════════════════════════════════════════

    func testLogoffRequestSize() {
        let body = SMB2LogoffRequest.build()
        XCTAssertEqual(body.count, 4)
        var r = ByteReader(body)
        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 4)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - TREE_CONNECT
    // ════════════════════════════════════════════════════════════════════

    func testTreeConnectRequestContainsPath() {
        let path = "\\\\192.168.1.1\\Videos"
        let body = SMB2TreeConnectRequest.build(path: path)
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 9)

        // Path data should be at the end, UTF-16LE encoded
        let pathData = path.utf16leData
        XCTAssertTrue(body.count >= 8 + pathData.count)
    }

    func testTreeConnectResponseParse() throws {
        let body = buildSyntheticTreeConnectResponse()
        let resp = try SMB2TreeConnectResponse.parse(body)

        XCTAssertEqual(resp.structureSize, SMB2TreeConnectResponse.expectedStructureSize)
        XCTAssertEqual(resp.shareType, SMB2ShareType.disk)
    }

    func testTreeDisconnectRequestSize() {
        let body = SMB2TreeDisconnectRequest.build()
        XCTAssertEqual(body.count, 4)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - CREATE
    // ════════════════════════════════════════════════════════════════════

    func testCreateRequestContainsPath() {
        let body = SMB2CreateRequest.build(path: "Movies/test.mkv")
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 57)
    }

    func testCreateOpenDirectory() {
        let body = SMB2CreateRequest.openDirectory(path: "Photos")
        // Should contain directoryFile option flag
        var r = ByteReader(body)
        try! r.skip(44) // skip to CreateOptions (offset 44 in body)
        let createOptions = try! r.uint32le()
        XCTAssertTrue(createOptions & SMB2CreateOptions.directoryFile != 0)
    }

    func testCreateOpenFile() {
        let body = SMB2CreateRequest.openFile(path: "video.mp4")
        var r = ByteReader(body)
        try! r.skip(44)
        let createOptions = try! r.uint32le()
        XCTAssertTrue(createOptions & SMB2CreateOptions.nonDirectoryFile != 0)
    }

    func testCreateResponseParse() throws {
        let body = buildSyntheticCreateResponse()
        let resp = try SMB2CreateResponse.parse(body)

        XCTAssertEqual(resp.structureSize, SMB2CreateResponse.expectedStructureSize)
        XCTAssertEqual(resp.endOfFile, 1_048_576)
        XCTAssertEqual(resp.fileId.persistent, 0x1111_2222_3333_4444)
        XCTAssertEqual(resp.fileId.volatile, 0x5555_6666_7777_8888)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - CLOSE
    // ════════════════════════════════════════════════════════════════════

    func testCloseRequestSize() {
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let body = SMB2CloseRequest.build(fileId: fileId)
        XCTAssertEqual(body.count, 24)
    }

    func testCloseRequestContainsFileId() {
        let fileId = SMB2FileId(persistent: 0xAAAA, volatile: 0xBBBB)
        let body = SMB2CloseRequest.build(fileId: fileId)
        var r = ByteReader(body)

        try! r.skip(8) // structureSize + flags + reserved
        let readId = try! SMB2FileId.read(from: &r)
        XCTAssertEqual(readId, fileId)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - READ
    // ════════════════════════════════════════════════════════════════════

    func testReadRequestStructure() {
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let body = SMB2ReadRequest.build(
            fileId: fileId,
            offset: 4096,
            length: 65536
        )
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 49)

        try! r.skip(2) // padding + flags
        let length = try! r.uint32le()
        XCTAssertEqual(length, 65536)

        let offset = try! r.uint64le()
        XCTAssertEqual(offset, 4096)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - QUERY_DIRECTORY
    // ════════════════════════════════════════════════════════════════════

    func testQueryDirectoryRequestStructure() {
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let body = SMB2QueryDirectoryRequest.build(fileId: fileId, pattern: "*")
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 33)

        let infoClass = try! r.uint8()
        XCTAssertEqual(infoClass, SMB2FileInfoClass.fileBothDirectoryInformation)
    }

    func testFileBothDirectoryInfoParse() {
        // Build a synthetic single-entry buffer
        let buffer = buildSyntheticDirectoryEntry(name: "test.mp4", size: 12345)
        let entries = FileBothDirectoryInfo.parseAll(from: buffer)

        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].fileName, "test.mp4")
        XCTAssertEqual(entries[0].endOfFile, 12345)
        XCTAssertFalse(entries[0].isDirectory)
    }

    func testFileBothDirectoryInfoDirectory() {
        let buffer = buildSyntheticDirectoryEntry(
            name: "Photos",
            size: 0,
            attributes: SMB2FileAttributes.directory
        )
        let entries = FileBothDirectoryInfo.parseAll(from: buffer)

        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].fileName, "Photos")
        XCTAssertTrue(entries[0].isDirectory)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - QUERY_INFO
    // ════════════════════════════════════════════════════════════════════

    func testQueryInfoRequestStructure() {
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let body = SMB2QueryInfoRequest.build(fileId: fileId)
        var r = ByteReader(body)

        let structureSize = try! r.uint16le()
        XCTAssertEqual(structureSize, 41)
    }

    func testFileStandardInfoParse() throws {
        // Build synthetic FILE_STANDARD_INFORMATION (24 bytes)
        var w = ByteWriter()
        w.uint64le(1_048_576)    // AllocationSize
        w.uint64le(999_999)      // EndOfFile
        w.uint32le(1)            // NumberOfLinks
        w.uint8(0)               // DeletePending
        w.uint8(0)               // Directory

        let info = try FileStandardInfo.parse(w.data)
        XCTAssertEqual(info.allocationSize, 1_048_576)
        XCTAssertEqual(info.endOfFile, 999_999)
        XCTAssertEqual(info.numberOfLinks, 1)
        XCTAssertFalse(info.deletePending)
        XCTAssertFalse(info.isDirectory)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - FileId
    // ════════════════════════════════════════════════════════════════════

    func testFileIdRoundTrip() throws {
        let original = SMB2FileId(persistent: 0x1234_5678_9ABC_DEF0, volatile: 0xFEDC_BA98_7654_3210)
        var w = ByteWriter()
        original.write(to: &w)

        var r = ByteReader(w.data)
        let parsed = try SMB2FileId.read(from: &r)
        XCTAssertEqual(parsed, original)
    }

    // ════════════════════════════════════════════════════════════════════
    // MARK: - Synthetic Response Builders (test helpers)
    // ════════════════════════════════════════════════════════════════════

    private func buildSyntheticNegotiateResponse() -> Data {
        let securityBuffer = Data(repeating: 0xBB, count: 16)
        // SecurityBufferOffset relative to header start
        let secBufferOffset: UInt16 = UInt16(smb2HeaderSize) + 64

        var w = ByteWriter()
        w.uint16le(65)                              // StructureSize
        w.uint16le(SMB2SecurityMode.signingEnabled)  // SecurityMode
        w.uint16le(SMB2Dialect.smb302)               // DialectRevision
        w.uint16le(0)                                // NegotiateContextCount
        w.bytes(Data(count: 16))                     // ServerGuid
        w.uint32le(SMB2Capabilities.largeMTU)         // Capabilities
        w.uint32le(65536)                            // MaxTransactSize
        w.uint32le(1048576)                          // MaxReadSize
        w.uint32le(1048576)                          // MaxWriteSize
        w.uint64le(0)                                // SystemTime
        w.uint64le(0)                                // ServerStartTime
        w.uint16le(secBufferOffset)                  // SecurityBufferOffset
        w.uint16le(UInt16(securityBuffer.count))     // SecurityBufferLength
        w.uint32le(0)                                // NegotiateContextOffset
        w.bytes(securityBuffer)
        return w.data
    }

    private func buildSyntheticSessionSetupResponse() -> Data {
        let securityBuffer = Data(repeating: 0xCC, count: 8)
        let secBufferOffset: UInt16 = UInt16(smb2HeaderSize) + 8

        var w = ByteWriter()
        w.uint16le(SMB2SessionSetupResponse.expectedStructureSize)
        w.uint16le(0)                                // SessionFlags
        w.uint16le(secBufferOffset)                  // SecurityBufferOffset
        w.uint16le(UInt16(securityBuffer.count))     // SecurityBufferLength
        w.bytes(securityBuffer)
        return w.data
    }

    private func buildSyntheticTreeConnectResponse() -> Data {
        var w = ByteWriter()
        w.uint16le(SMB2TreeConnectResponse.expectedStructureSize)
        w.uint8(SMB2ShareType.disk)      // ShareType
        w.uint8(0)                       // Reserved
        w.uint32le(0)                    // ShareFlags
        w.uint32le(0)                    // Capabilities
        w.uint32le(SMB2AccessMask.genericRead) // MaximalAccess
        return w.data
    }

    private func buildSyntheticCreateResponse() -> Data {
        var w = ByteWriter()
        w.uint16le(SMB2CreateResponse.expectedStructureSize)
        w.uint8(0)                       // OplockLevel
        w.uint8(0)                       // Flags
        w.uint32le(1)                    // CreateAction (FILE_OPENED)
        w.uint64le(0)                    // CreationTime
        w.uint64le(0)                    // LastAccessTime
        w.uint64le(0)                    // LastWriteTime
        w.uint64le(0)                    // ChangeTime
        w.uint64le(2_097_152)            // AllocationSize
        w.uint64le(1_048_576)            // EndOfFile (1 MB)
        w.uint32le(SMB2FileAttributes.archive) // FileAttributes
        w.uint32le(0)                    // Reserved2
        w.uint64le(0x1111_2222_3333_4444) // FileId.Persistent
        w.uint64le(0x5555_6666_7777_8888) // FileId.Volatile
        w.uint32le(0)                    // CreateContextsOffset
        w.uint32le(0)                    // CreateContextsLength
        return w.data
    }

    private func buildSyntheticDirectoryEntry(
        name: String,
        size: UInt64,
        attributes: UInt32 = SMB2FileAttributes.archive
    ) -> Data {
        let nameData = name.utf16leData

        var w = ByteWriter()
        w.uint32le(0)                    // NextEntryOffset (0 = last entry)
        w.uint32le(0)                    // FileIndex
        w.uint64le(0)                    // CreationTime
        w.uint64le(0)                    // LastAccessTime
        w.uint64le(0)                    // LastWriteTime
        w.uint64le(0)                    // ChangeTime
        w.uint64le(size)                 // EndOfFile
        w.uint64le(size)                 // AllocationSize
        w.uint32le(attributes)           // FileAttributes
        w.uint32le(UInt32(nameData.count)) // FileNameLength
        w.uint32le(0)                    // EaSize
        w.uint8(0)                       // ShortNameLength
        w.uint8(0)                       // Reserved
        w.zeros(24)                      // ShortName (24 bytes, padded)
        w.bytes(nameData)                // FileName
        return w.data
    }
}
