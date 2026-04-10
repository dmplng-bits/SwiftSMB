//
//  SMBClientTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Unit tests for SMBClient. These focus on the pure helpers: path
// normalization, NT status mapping, and SMBFile conversion. The wire
// parts of SMBClient require a real server and are not covered here.

import XCTest
@testable import SwiftSMB

final class SMBClientTests: XCTestCase {

    // MARK: - Path normalization

    func testNormalizeStripsLeadingSlashes() {
        XCTAssertEqual(SMBClient.normalize("/Movies"), "Movies")
        XCTAssertEqual(SMBClient.normalize("\\Movies"), "Movies")
        XCTAssertEqual(SMBClient.normalize("///Movies"), "Movies")
    }

    func testNormalizeStripsTrailingSlashes() {
        XCTAssertEqual(SMBClient.normalize("Movies/"), "Movies")
        XCTAssertEqual(SMBClient.normalize("Movies\\"), "Movies")
        XCTAssertEqual(SMBClient.normalize("Movies///"), "Movies")
    }

    func testNormalizeConvertsForwardSlashesToBackslashes() {
        XCTAssertEqual(
            SMBClient.normalize("Movies/Drama/2020"),
            "Movies\\Drama\\2020"
        )
    }

    func testNormalizeEmptyStringStaysEmpty() {
        XCTAssertEqual(SMBClient.normalize(""), "")
        XCTAssertEqual(SMBClient.normalize("/"), "")
        XCTAssertEqual(SMBClient.normalize("\\"), "")
    }

    func testNormalizeNestedPathWithSingleSlash() {
        XCTAssertEqual(
            SMBClient.normalize("/Movies/Inception.mkv"),
            "Movies\\Inception.mkv"
        )
    }

    // MARK: - NT status mapping

    func testMapNTStatusFileNotFound() {
        let err = SMBClient.mapNTStatus(NTStatus.objectNameNotFound, path: "foo.txt")
        if case .fileNotFound(let p) = err {
            XCTAssertEqual(p, "foo.txt")
        } else {
            XCTFail("Expected .fileNotFound, got \(err)")
        }
    }

    func testMapNTStatusPathNotFound() {
        let err = SMBClient.mapNTStatus(NTStatus.objectPathNotFound, path: "a/b/c")
        if case .fileNotFound = err { } else {
            XCTFail("Expected .fileNotFound, got \(err)")
        }
    }

    func testMapNTStatusAccessDenied() {
        let err = SMBClient.mapNTStatus(NTStatus.accessDenied, path: "secret")
        if case .accessDenied(let p) = err {
            XCTAssertEqual(p, "secret")
        } else {
            XCTFail("Expected .accessDenied, got \(err)")
        }
    }

    func testMapNTStatusLogonFailureMapsToAuthFailed() {
        let err = SMBClient.mapNTStatus(NTStatus.logonFailure, path: "")
        if case .authenticationFailed = err { } else {
            XCTFail("Expected .authenticationFailed, got \(err)")
        }
    }

    func testMapNTStatusUnknownFallsThrough() {
        let err = SMBClient.mapNTStatus(0xC000_1234, path: "")
        if case .ntStatus(let code) = err {
            XCTAssertEqual(code, 0xC000_1234)
        } else {
            XCTFail("Expected .ntStatus, got \(err)")
        }
    }

    // MARK: - SMBFile conversion

    func testSMBFileFileExtension() {
        let f = SMBFile(
            path: "Movies/Inception.mkv",
            name: "Inception.mkv",
            size: 1000,
            isDirectory: false,
            isHidden: false,
            attributes: 0
        )
        XCTAssertEqual(f.fileExtension, "mkv")
    }

    func testSMBFileFileExtensionUppercaseIsNormalized() {
        let f = SMBFile(
            path: "a.MP4",
            name: "a.MP4",
            size: 0,
            isDirectory: false,
            isHidden: false,
            attributes: 0
        )
        XCTAssertEqual(f.fileExtension, "mp4")
    }

    func testSMBFileFileExtensionWithNoDot() {
        let f = SMBFile(
            path: "readme",
            name: "readme",
            size: 0,
            isDirectory: false,
            isHidden: false,
            attributes: 0
        )
        XCTAssertEqual(f.fileExtension, "")
    }

    func testSMBFileFileExtensionLeadingDotIsNotAnExtension() {
        let f = SMBFile(
            path: ".hidden",
            name: ".hidden",
            size: 0,
            isDirectory: false,
            isHidden: true,
            attributes: 0
        )
        XCTAssertEqual(f.fileExtension, "")
    }

    func testSMBFileDateFromZeroFileTimeIsNil() {
        XCTAssertNil(SMBFile.date(fromFileTime: 0))
    }

    func testSMBFileDateFromPreUnixEpochIsNil() {
        // Any value below the 1970 Unix epoch delta should be clamped to nil.
        XCTAssertNil(SMBFile.date(fromFileTime: 100))
    }

    func testSMBFileDateFromUnixEpochTickIsJan1_1970() {
        // Exactly 116444736000000000 = 1970-01-01 00:00:00 UTC.
        let d = SMBFile.date(fromFileTime: 116_444_736_000_000_000)
        XCTAssertNotNil(d)
        XCTAssertEqual(d!.timeIntervalSince1970, 0, accuracy: 0.001)
    }

    func testSMBFileFromFileBothDirectoryInfoBuildsNestedPath() {
        let info = FileBothDirectoryInfo(
            fileName:       "movie.mkv",
            shortName:      "MOVIE~1.MKV",
            fileAttributes: 0,
            creationTime:   0,
            lastAccessTime: 0,
            lastWriteTime:  0,
            changeTime:     0,
            endOfFile:      12345,
            allocationSize: 16384
        )
        let smbFile = SMBFile.from(info, parentPath: "Movies/Drama")
        XCTAssertEqual(smbFile.path, "Movies/Drama/movie.mkv")
        XCTAssertEqual(smbFile.name, "movie.mkv")
        XCTAssertEqual(smbFile.size, 12345)
        XCTAssertFalse(smbFile.isDirectory)
    }

    func testSMBFileFromFileBothDirectoryInfoUsesBareNameAtRoot() {
        let info = FileBothDirectoryInfo(
            fileName:       "root.txt",
            shortName:      "",
            fileAttributes: 0,
            creationTime:   0,
            lastAccessTime: 0,
            lastWriteTime:  0,
            changeTime:     0,
            endOfFile:      42,
            allocationSize: 42
        )
        let smbFile = SMBFile.from(info, parentPath: "")
        XCTAssertEqual(smbFile.path, "root.txt")
    }

    // MARK: - SMBFile convenience helpers

    func testSMBFileConvenienceFileSizeUsesCache() async throws {
        // When size > 0, fileSize(of:) should return the cached value
        // without hitting the wire. We can't call the actor method directly
        // without a real server, but we verify the SMBFile itself holds the value.
        let f = SMBFile(
            path: "Photos/sunset.jpg",
            name: "sunset.jpg",
            size: 4_200_000,
            isDirectory: false,
            isHidden: false,
            attributes: 0
        )
        // The cached size should be exactly what was set.
        XCTAssertEqual(f.size, 4_200_000)
        XCTAssertFalse(f.isDirectory)
    }

    func testSMBFileDirectorySizeIsAlwaysZero() {
        let dir = SMBFile(
            path: "Photos",
            name: "Photos",
            size: 0,
            isDirectory: true,
            isHidden: false,
            attributes: SMB2FileAttributes.directory
        )
        XCTAssertEqual(dir.size, 0)
        XCTAssertTrue(dir.isDirectory)
    }

    // MARK: - Photo/media file extension tests

    func testSMBFileCommonPhotoExtensions() {
        let cases: [(name: String, expected: String)] = [
            ("sunset.JPG", "jpg"),
            ("portrait.HEIC", "heic"),
            ("raw.DNG", "dng"),
            ("scan.PNG", "png"),
            ("photo.CR3", "cr3"),
            ("image.ARW", "arw"),
            ("pic.TIFF", "tiff"),
        ]
        for (name, expected) in cases {
            let f = SMBFile(path: name, name: name, size: 0,
                            isDirectory: false, isHidden: false, attributes: 0)
            XCTAssertEqual(f.fileExtension, expected,
                           "Expected \(expected) for \(name)")
        }
    }

    func testSMBFileCommonVideoExtensions() {
        let cases: [(name: String, expected: String)] = [
            ("movie.MKV", "mkv"),
            ("clip.MP4", "mp4"),
            ("video.AVI", "avi"),
            ("film.MOV", "mov"),
        ]
        for (name, expected) in cases {
            let f = SMBFile(path: name, name: name, size: 0,
                            isDirectory: false, isHidden: false, attributes: 0)
            XCTAssertEqual(f.fileExtension, expected,
                           "Expected \(expected) for \(name)")
        }
    }

    func testSMBFileMultiDotExtension() {
        let f = SMBFile(
            path: "backup.2024.01.tar.gz",
            name: "backup.2024.01.tar.gz",
            size: 0, isDirectory: false, isHidden: false, attributes: 0
        )
        XCTAssertEqual(f.fileExtension, "gz")
    }

    func testSMBFileIsDirectoryIsForwardedCorrectly() {
        let info = FileBothDirectoryInfo(
            fileName:       "subdir",
            shortName:      "",
            fileAttributes: SMB2FileAttributes.directory,
            creationTime:   0,
            lastAccessTime: 0,
            lastWriteTime:  0,
            changeTime:     0,
            endOfFile:      0,
            allocationSize: 0
        )
        let smbFile = SMBFile.from(info, parentPath: "Movies")
        XCTAssertTrue(smbFile.isDirectory)
        XCTAssertEqual(smbFile.path, "Movies/subdir")
    }
}
