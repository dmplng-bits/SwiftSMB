//
//  SMBChangeNotifyTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//

import XCTest
@testable import SwiftSMB

final class SMBChangeNotifyTests: XCTestCase {

    // MARK: - SMB2ChangeNotifyRequest Builder Tests

    func testChangeNotifyRequestStructureSize() {
        let fileId = SMB2FileId(persistent: 1, volatile: 2)
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId)

        // First 2 bytes should be StructureSize = 32
        let structureSize = UInt16(request[0]) | (UInt16(request[1]) << 8)
        XCTAssertEqual(structureSize, 32)
    }

    func testChangeNotifyRequestWatchTreeTrue() {
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId, watchTree: true)

        // Flags at bytes 2-3. watchTree=true => 0x0001
        let flags = UInt16(request[2]) | (UInt16(request[3]) << 8)
        XCTAssertEqual(flags, 0x0001)
    }

    func testChangeNotifyRequestWatchTreeFalse() {
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId, watchTree: false)

        // Flags at bytes 2-3. watchTree=false => 0x0000
        let flags = UInt16(request[2]) | (UInt16(request[3]) << 8)
        XCTAssertEqual(flags, 0x0000)
    }

    func testChangeNotifyRequestOutputBufferLength() {
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let customLength: UInt32 = 12345
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId, outputBufferLength: customLength)

        // OutputBufferLength at bytes 4-7 (4 bytes LE).
        let length = UInt32(request[4]) |
                    (UInt32(request[5]) << 8) |
                    (UInt32(request[6]) << 16) |
                    (UInt32(request[7]) << 24)
        XCTAssertEqual(length, customLength)
    }

    func testChangeNotifyRequestDefaultOutputBufferLength() {
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId)

        // Default should be 65536
        let length = UInt32(request[4]) |
                    (UInt32(request[5]) << 8) |
                    (UInt32(request[6]) << 16) |
                    (UInt32(request[7]) << 24)
        XCTAssertEqual(length, 65536)
    }

    func testChangeNotifyRequestCompletionFilter() {
        let fileId = SMB2FileId(persistent: 0, volatile: 0)
        let customFilter: UInt32 = 0x0000_0015
        let request = SMB2ChangeNotifyRequest.build(fileId: fileId, completionFilter: customFilter)

        // CompletionFilter at bytes 24-27 (after FileId which is 16 bytes at offset 8).
        // Offset to CompletionFilter = 2 + 2 + 4 + 16 = 24
        let filter = UInt32(request[24]) |
                    (UInt32(request[25]) << 8) |
                    (UInt32(request[26]) << 16) |
                    (UInt32(request[27]) << 24)
        XCTAssertEqual(filter, customFilter)
    }

    // MARK: - SMB2ChangeNotifyFilter Tests

    func testChangeNotifyFilterAll() {
        // all should be the bitwise OR of all individual flags
        let expected = SMB2ChangeNotifyFilter.fileName |
                      SMB2ChangeNotifyFilter.dirName |
                      SMB2ChangeNotifyFilter.attributes |
                      SMB2ChangeNotifyFilter.size |
                      SMB2ChangeNotifyFilter.lastWrite |
                      SMB2ChangeNotifyFilter.lastAccess |
                      SMB2ChangeNotifyFilter.creation |
                      SMB2ChangeNotifyFilter.ea |
                      SMB2ChangeNotifyFilter.security |
                      SMB2ChangeNotifyFilter.streamName |
                      SMB2ChangeNotifyFilter.streamSize |
                      SMB2ChangeNotifyFilter.streamWrite

        XCTAssertEqual(SMB2ChangeNotifyFilter.all, expected)
        XCTAssertEqual(SMB2ChangeNotifyFilter.all, 0x0000_0FFF)
    }

    func testChangeNotifyFilterIndividualFlags() {
        XCTAssertEqual(SMB2ChangeNotifyFilter.fileName, 0x0000_0001)
        XCTAssertEqual(SMB2ChangeNotifyFilter.dirName, 0x0000_0002)
        XCTAssertEqual(SMB2ChangeNotifyFilter.attributes, 0x0000_0004)
        XCTAssertEqual(SMB2ChangeNotifyFilter.size, 0x0000_0008)
        XCTAssertEqual(SMB2ChangeNotifyFilter.lastWrite, 0x0000_0010)
        XCTAssertEqual(SMB2ChangeNotifyFilter.lastAccess, 0x0000_0020)
        XCTAssertEqual(SMB2ChangeNotifyFilter.creation, 0x0000_0040)
        XCTAssertEqual(SMB2ChangeNotifyFilter.ea, 0x0000_0080)
        XCTAssertEqual(SMB2ChangeNotifyFilter.security, 0x0000_0100)
        XCTAssertEqual(SMB2ChangeNotifyFilter.streamName, 0x0000_0200)
        XCTAssertEqual(SMB2ChangeNotifyFilter.streamSize, 0x0000_0400)
        XCTAssertEqual(SMB2ChangeNotifyFilter.streamWrite, 0x0000_0800)
    }

    // MARK: - FileNotifyInfo ParseAll Tests

    func testFileNotifyInfoParseAllEmpty() {
        let buffer = Data()
        let results = FileNotifyInfo.parseAll(from: buffer)
        XCTAssertEqual(results.count, 0)
    }

    func testFileNotifyInfoParseAllSingleEntry() {
        // Build a single FILE_NOTIFY_INFORMATION entry:
        // NextEntryOffset(4) + Action(4) + FileNameLength(4) + FileName(variable)
        var w = ByteWriter()
        let fileName = "test.txt"
        let fileNameData = fileName.utf16leData
        w.uint32le(0)                            // NextEntryOffset (0 = last entry)
        w.uint32le(SMB2FileAction.added)         // Action
        w.uint32le(UInt32(fileNameData.count))   // FileNameLength
        w.bytes(fileNameData)                    // FileName
        let buffer = w.data

        let results = FileNotifyInfo.parseAll(from: buffer)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].action, SMB2FileAction.added)
        XCTAssertEqual(results[0].fileName, "test.txt")
    }

    func testFileNotifyInfoParseAllTwoEntries() {
        // Build two FILE_NOTIFY_INFORMATION entries
        var w = ByteWriter()

        // First entry:
        let fileName1 = "file1.doc"
        let fileNameData1 = fileName1.utf16leData
        let entry1Size = 12 + fileNameData1.count
        // Pad to 4-byte alignment for NextEntryOffset
        let paddedEntry1Size = ((entry1Size + 3) / 4) * 4

        w.uint32le(UInt32(paddedEntry1Size))     // NextEntryOffset
        w.uint32le(SMB2FileAction.added)
        w.uint32le(UInt32(fileNameData1.count))
        w.bytes(fileNameData1)
        w.zeros(paddedEntry1Size - entry1Size)   // Padding

        // Second entry:
        let fileName2 = "image.png"
        let fileNameData2 = fileName2.utf16leData
        w.uint32le(0)                             // NextEntryOffset (last entry)
        w.uint32le(SMB2FileAction.modified)
        w.uint32le(UInt32(fileNameData2.count))
        w.bytes(fileNameData2)

        let buffer = w.data
        let results = FileNotifyInfo.parseAll(from: buffer)

        XCTAssertEqual(results.count, 2)
        XCTAssertEqual(results[0].fileName, "file1.doc")
        XCTAssertEqual(results[0].action, SMB2FileAction.added)
        XCTAssertEqual(results[1].fileName, "image.png")
        XCTAssertEqual(results[1].action, SMB2FileAction.modified)
    }

    func testFileNotifyInfoParseAllUtf16LEFilename() {
        // Test with non-ASCII filename
        var w = ByteWriter()
        let fileName = "Éclair"
        let fileNameData = fileName.utf16leData
        w.uint32le(0)
        w.uint32le(SMB2FileAction.modified)
        w.uint32le(UInt32(fileNameData.count))
        w.bytes(fileNameData)
        let buffer = w.data

        let results = FileNotifyInfo.parseAll(from: buffer)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].fileName, "Éclair")
    }

    // MARK: - SMBFileChange Action Mapping Tests

    func testFileChangeActionAdded() {
        let change = SMBFileChange(action: SMB2FileAction.added, fileName: "new.txt")
        if case .added = change.action { } else {
            XCTFail("Expected .added, got \(change.action)")
        }
    }

    func testFileChangeActionRemoved() {
        let change = SMBFileChange(action: SMB2FileAction.removed, fileName: "deleted.txt")
        if case .removed = change.action { } else {
            XCTFail("Expected .removed, got \(change.action)")
        }
    }

    func testFileChangeActionModified() {
        let change = SMBFileChange(action: SMB2FileAction.modified, fileName: "modified.txt")
        if case .modified = change.action { } else {
            XCTFail("Expected .modified, got \(change.action)")
        }
    }

    func testFileChangeActionRenamedOld() {
        let change = SMBFileChange(action: SMB2FileAction.renamedOldName, fileName: "old.txt")
        if case .renamedOld = change.action { } else {
            XCTFail("Expected .renamedOld, got \(change.action)")
        }
    }

    func testFileChangeActionRenamedNew() {
        let change = SMBFileChange(action: SMB2FileAction.renamedNewName, fileName: "new.txt")
        if case .renamedNew = change.action { } else {
            XCTFail("Expected .renamedNew, got \(change.action)")
        }
    }

    func testFileChangeActionUnknownDefaultsToModified() {
        let unknownAction: UInt32 = 9999
        let change = SMBFileChange(action: unknownAction, fileName: "file.txt")
        if case .modified = change.action { } else {
            XCTFail("Expected .modified for unknown action, got \(change.action)")
        }
    }

    func testFileChangeFileName() {
        let change = SMBFileChange(action: SMB2FileAction.added, fileName: "photos.zip")
        XCTAssertEqual(change.fileName, "photos.zip")
    }

    // MARK: - AVPlayer bytes=0-1 Probe Test

    func testParseRangeHeaderBytesZeroOne() {
        // AVPlayer sends "bytes=0-1" to probe file size.
        // parseRangeHeader should return 0..<2
        let result = SMBStreamingProxy.parseRangeHeader("bytes=0-1", fileSize: 1_000_000)
        XCTAssertEqual(result, 0..<2)
    }

    func testParseRangeHeaderWithLargeFileSize() {
        let result = SMBStreamingProxy.parseRangeHeader("bytes=0-1", fileSize: 10_000_000)
        XCTAssertEqual(result, 0..<2)
    }

    func testParseRangeHeaderWithSmallFileSize() {
        let result = SMBStreamingProxy.parseRangeHeader("bytes=0-1", fileSize: 2)
        XCTAssertEqual(result, 0..<2)
    }

    func testParseRangeHeaderBytesZeroOneExceedsFileSize() {
        // File is only 1 byte; bytes=0-1 should be clamped to 0..<1
        let result = SMBStreamingProxy.parseRangeHeader("bytes=0-1", fileSize: 1)
        XCTAssertEqual(result, 0..<1)
    }
}
