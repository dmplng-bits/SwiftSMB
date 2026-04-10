//
//  SMBWriteTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//

import XCTest
@testable import SwiftSMB

final class SMBWriteTests: XCTestCase {

    // MARK: - SMB2WriteRequest Builder Tests

    func testWriteRequestStructureSize() {
        let data = Data([1, 2, 3, 4, 5])
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let request = SMB2WriteRequest.build(fileId: fileId, offset: 100, data: data)

        // First 2 bytes should be StructureSize = 49
        XCTAssertEqual(request.count >= 2, true)
        let structureSize = UInt16(request[0]) | (UInt16(request[1]) << 8)
        XCTAssertEqual(structureSize, 49)
    }

    func testWriteRequestDataOffset() {
        let data = Data([1, 2, 3])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2WriteRequest.build(fileId: fileId, offset: 0, data: data)

        // DataOffset at bytes 2-3. Expected: smb2HeaderSize (64) + 48 = 112
        let dataOffset = UInt16(request[2]) | (UInt16(request[3]) << 8)
        XCTAssertEqual(dataOffset, UInt16(smb2HeaderSize) + 48)
    }

    func testWriteRequestDataLengthField() {
        let data = Data([0xAA, 0xBB, 0xCC, 0xDD])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2WriteRequest.build(fileId: fileId, offset: 0, data: data)

        // Length field at bytes 4-7 (4 bytes LE).
        let length = UInt32(request[4]) |
                    (UInt32(request[5]) << 8) |
                    (UInt32(request[6]) << 16) |
                    (UInt32(request[7]) << 24)
        XCTAssertEqual(length, 4)
    }

    func testWriteRequestOffsetField() {
        let data = Data()
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let testOffset: UInt64 = 0x0102030405060708
        let request = SMB2WriteRequest.build(fileId: fileId, offset: testOffset, data: data)

        // Offset field at bytes 8-15 (8 bytes LE).
        var offset: UInt64 = 0
        for i in 0..<8 {
            offset |= UInt64(request[8 + i]) << (i * 8)
        }
        XCTAssertEqual(offset, testOffset)
    }

    func testWriteRequestIncludesData() {
        let testData = Data([0x11, 0x22, 0x33, 0x44, 0x55])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2WriteRequest.build(fileId: fileId, offset: 0, data: testData)

        // Data should be appended after the fixed structure.
        // Fixed structure is: StructureSize(2) + DataOffset(2) + Length(4) + Offset(8) +
        // FileId(16) + Channel(4) + RemainingBytes(4) + WriteChannelInfoOffset(2) +
        // WriteChannelInfoLength(2) + Flags(4) = 48 bytes.
        let dataStart = 48
        XCTAssertEqual(request.count >= dataStart + testData.count, true)
        let extractedData = request.subdata(in: dataStart..<dataStart + testData.count)
        XCTAssertEqual(extractedData, testData)
    }

    // MARK: - SMB2WriteResponse Parser Tests

    func testWriteResponseParseStructureSize() throws {
        var w = ByteWriter()
        w.uint16le(17)              // StructureSize
        w.uint16le(0)               // Reserved
        w.uint32le(100)             // Count (bytes written)
        w.uint32le(0)               // Remaining
        w.uint16le(0)               // WriteChannelInfoOffset
        w.uint16le(0)               // WriteChannelInfoLength
        let response = try SMB2WriteResponse.parse(w.data)

        XCTAssertEqual(response.structureSize, 17)
    }

    func testWriteResponseParseCount() throws {
        var w = ByteWriter()
        w.uint16le(17)
        w.uint16le(0)
        w.uint32le(12345)           // Count
        w.uint32le(0)
        w.uint16le(0)
        w.uint16le(0)
        let response = try SMB2WriteResponse.parse(w.data)

        XCTAssertEqual(response.count, 12345)
    }

    func testWriteResponseParseRemaining() throws {
        var w = ByteWriter()
        w.uint16le(17)
        w.uint16le(0)
        w.uint32le(100)
        w.uint32le(5000)            // Remaining
        w.uint16le(0)
        w.uint16le(0)
        let response = try SMB2WriteResponse.parse(w.data)

        XCTAssertEqual(response.remaining, 5000)
    }

    // MARK: - FileRenameInfo Builder Tests

    func testFileRenameInfoSimpleName() {
        let buffer = FileRenameInfo.build(newName: "newfile.txt")

        // Structure:
        // ReplaceIfExists (1) + Reserved (7) + RootDirectory (8) + FileNameLength (4) + FileName
        // Expected: ReplaceIfExists=0, RootDirectory=0, FileNameLength = byte length of UTF-16LE "newfile.txt"
        var r = ByteReader(buffer)
        let replaceIfExists = try! r.uint8()
        XCTAssertEqual(replaceIfExists, 0)

        let _reserved = try! r.bytes(7)  // Skip reserved
        let _rootDir = try! r.uint64le() // Should be 0
        let fileNameLength = try! r.uint32le()

        let expectedNameBytes = "newfile.txt".utf16leData.count
        XCTAssertEqual(fileNameLength, UInt32(expectedNameBytes))
    }

    func testFileRenameInfoReplaceIfExists() {
        let buffer = FileRenameInfo.build(newName: "test", replaceIfExists: true)

        var r = ByteReader(buffer)
        let replaceIfExists = try! r.uint8()
        XCTAssertEqual(replaceIfExists, 1)
    }

    func testFileRenameInfoUtf16LEEncoding() {
        let testName = "café"
        let buffer = FileRenameInfo.build(newName: testName)

        // Extract the name from buffer (skip header).
        // Header is 1 + 7 + 8 + 4 = 20 bytes.
        let headerSize = 20
        let nameData = buffer.subdata(in: headerSize..<buffer.count)
        let extractedName = nameData.utf16leString

        XCTAssertEqual(extractedName, testName)
    }

    func testFileRenameInfoBackslashPaths() {
        let buffer = FileRenameInfo.build(newName: "Photos\\Vacation\\2024")

        var r = ByteReader(buffer)
        let _replaceIfExists = try! r.uint8()
        let _reserved = try! r.bytes(7)
        let _rootDir = try! r.uint64le()
        let fileNameLength = try! r.uint32le()

        let expectedNameBytes = "Photos\\Vacation\\2024".utf16leData.count
        XCTAssertEqual(fileNameLength, UInt32(expectedNameBytes))
    }

    // MARK: - FileDispositionInfo Builder Tests

    func testFileDispositionInfoDeleteFalse() {
        let buffer = FileDispositionInfo.build(deleteOnClose: false)

        XCTAssertEqual(buffer.count, 1)
        XCTAssertEqual(buffer[0], 0)
    }

    func testFileDispositionInfoDeleteTrue() {
        let buffer = FileDispositionInfo.build(deleteOnClose: true)

        XCTAssertEqual(buffer.count, 1)
        XCTAssertEqual(buffer[0], 1)
    }

    func testFileDispositionInfoDefaultIsTrue() {
        let buffer = FileDispositionInfo.build()

        XCTAssertEqual(buffer[0], 1)
    }

    // MARK: - SMB2SetInfoRequest Builder Tests

    func testSetInfoRequestStructureSize() {
        let buffer = Data()
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            fileInfoClass: SMB2FileInfoClass.fileRenameInformation,
            buffer: buffer
        )

        // First 2 bytes should be StructureSize = 33
        let structureSize = UInt16(request[0]) | (UInt16(request[1]) << 8)
        XCTAssertEqual(structureSize, 33)
    }

    func testSetInfoRequestBufferOffset() {
        let buffer = Data([0xAA, 0xBB])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            fileInfoClass: 0,
            buffer: buffer
        )

        // BufferOffset at bytes 12-13 (relative to SMB2 header start).
        // Expected: smb2HeaderSize (64) + 32 = 96
        let bufferOffset = UInt16(request[12]) | (UInt16(request[13]) << 8)
        XCTAssertEqual(bufferOffset, UInt16(smb2HeaderSize) + 32)
    }

    func testSetInfoRequestBufferLength() {
        let testBuffer = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            fileInfoClass: 0,
            buffer: testBuffer
        )

        // BufferLength at bytes 4-7 (4 bytes LE).
        let bufferLength = UInt32(request[4]) |
                          (UInt32(request[5]) << 8) |
                          (UInt32(request[6]) << 16) |
                          (UInt32(request[7]) << 24)
        XCTAssertEqual(bufferLength, 5)
    }

    func testSetInfoRequestInfoType() {
        let buffer = Data()
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let customInfoType: UInt8 = 42
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            infoType: customInfoType,
            fileInfoClass: 0,
            buffer: buffer
        )

        // InfoType at byte 2
        XCTAssertEqual(request[2], customInfoType)
    }

    func testSetInfoRequestFileInfoClass() {
        let buffer = Data()
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let customClass: UInt8 = 17
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            infoType: SMB2InfoType.file,
            fileInfoClass: customClass,
            buffer: buffer
        )

        // FileInfoClass at byte 3
        XCTAssertEqual(request[3], customClass)
    }

    func testSetInfoRequestIncludesBuffer() {
        let testBuffer = Data([0xCC, 0xDD, 0xEE])
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2SetInfoRequest.build(
            fileId: fileId,
            fileInfoClass: 0,
            buffer: testBuffer
        )

        // Buffer should be appended after fixed structure (32 bytes).
        let bufferStart = 32
        XCTAssertEqual(request.count >= bufferStart + testBuffer.count, true)
        let extractedBuffer = request.subdata(in: bufferStart..<bufferStart + testBuffer.count)
        XCTAssertEqual(extractedBuffer, testBuffer)
    }

    // MARK: - SMB2SetInfoResponse Parser Tests

    func testSetInfoResponseParseStructureSize() throws {
        var w = ByteWriter()
        w.uint16le(2)  // StructureSize
        let response = try SMB2SetInfoResponse.parse(w.data)

        XCTAssertEqual(response.structureSize, 2)
    }

    func testSetInfoResponseExpectedStructureSize() {
        XCTAssertEqual(SMB2SetInfoResponse.expectedStructureSize, 2)
    }
}

// MARK: - SMB2FileInfoClass Constants

/// File information class constants used in SET_INFO requests.
public enum SMB2FileInfoClass {
    public static let fileRenameInformation: UInt8 = 10
    public static let fileDispositionInformation: UInt8 = 13
}
