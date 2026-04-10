//
//  SMBStreamingProxyTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// Unit tests for SMBStreamingProxy. These focus on the pure parsers:
// HTTP request parsing, Range header handling, token extraction, and
// content-type guessing. The full end-to-end flow (which requires a
// real SMB server) is out of scope for unit tests.

import XCTest
@testable import SwiftSMB

final class SMBStreamingProxyTests: XCTestCase {

    // MARK: - Request parsing

    func testParseSimpleGET() {
        let raw = "GET /stream/abc HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        let req = SMBStreamingProxy.ParsedRequest.parse(raw)
        XCTAssertNotNil(req)
        XCTAssertEqual(req?.method, "GET")
        XCTAssertEqual(req?.path, "/stream/abc")
        XCTAssertEqual(req?.version, "HTTP/1.1")
        XCTAssertEqual(req?.headers["host"], "127.0.0.1")
    }

    func testParseHEADRequest() {
        let raw = "HEAD /stream/xyz HTTP/1.1\r\nAccept: */*\r\n\r\n"
        let req = SMBStreamingProxy.ParsedRequest.parse(raw)
        XCTAssertEqual(req?.method, "HEAD")
        XCTAssertEqual(req?.path, "/stream/xyz")
    }

    func testParseLowercasesHeaderNames() {
        let raw = "GET / HTTP/1.1\r\nRANGE: bytes=0-100\r\n\r\n"
        let req = SMBStreamingProxy.ParsedRequest.parse(raw)
        XCTAssertEqual(req?.headers["range"], "bytes=0-100")
    }

    func testParseMultipleHeaders() {
        let raw = """
        GET /stream/tok HTTP/1.1\r
        Host: localhost\r
        Range: bytes=500-999\r
        User-Agent: AVPlayer/1\r
        \r

        """
        let req = SMBStreamingProxy.ParsedRequest.parse(raw)
        XCTAssertEqual(req?.headers.count, 3)
        XCTAssertEqual(req?.headers["host"], "localhost")
        XCTAssertEqual(req?.headers["range"], "bytes=500-999")
        XCTAssertEqual(req?.headers["user-agent"], "AVPlayer/1")
    }

    func testParseMalformedRequestLineReturnsNil() {
        let raw = "NOTAREQUEST\r\n\r\n"
        XCTAssertNil(SMBStreamingProxy.ParsedRequest.parse(raw))
    }

    // MARK: - Token extraction

    func testExtractTokenFromValidPath() {
        XCTAssertEqual(
            SMBStreamingProxy.extractToken(from: "/stream/abc123"),
            "abc123"
        )
    }

    func testExtractTokenStripsQueryString() {
        XCTAssertEqual(
            SMBStreamingProxy.extractToken(from: "/stream/abc?foo=bar"),
            "abc"
        )
    }

    func testExtractTokenEmptyAfterPrefixIsNil() {
        XCTAssertNil(SMBStreamingProxy.extractToken(from: "/stream/"))
    }

    func testExtractTokenWrongPrefixIsNil() {
        XCTAssertNil(SMBStreamingProxy.extractToken(from: "/wrong/abc"))
        XCTAssertNil(SMBStreamingProxy.extractToken(from: "/"))
        XCTAssertNil(SMBStreamingProxy.extractToken(from: ""))
    }

    // MARK: - Range header parsing

    func testParseOpenRange() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes=0-", fileSize: 1000)
        XCTAssertEqual(r, 0..<1000)
    }

    func testParseFullRange() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes=100-499", fileSize: 1000)
        XCTAssertEqual(r, 100..<500)
    }

    func testParseSuffixRange() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes=-200", fileSize: 1000)
        XCTAssertEqual(r, 800..<1000)
    }

    func testParseSuffixRangeLargerThanFileClampsToStart() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes=-5000", fileSize: 1000)
        XCTAssertEqual(r, 0..<1000)
    }

    func testParseRangeWithLastBeyondFileIsTruncated() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes=500-9999", fileSize: 1000)
        XCTAssertEqual(r, 500..<1000)
    }

    func testParseRangeStartBeyondFileReturnsNil() {
        XCTAssertNil(SMBStreamingProxy.parseRangeHeader("bytes=2000-3000", fileSize: 1000))
    }

    func testParseRangeOpenEndedBeyondFileReturnsNil() {
        XCTAssertNil(SMBStreamingProxy.parseRangeHeader("bytes=1000-", fileSize: 1000))
    }

    func testParseRangeReversedReturnsNil() {
        XCTAssertNil(SMBStreamingProxy.parseRangeHeader("bytes=500-100", fileSize: 1000))
    }

    func testParseRangeWithoutBytesPrefixIsNil() {
        XCTAssertNil(SMBStreamingProxy.parseRangeHeader("0-100", fileSize: 1000))
    }

    func testParseRangeIgnoresExtraRangesBeyondFirst() {
        // We only honor the first range in a multi-range request.
        let r = SMBStreamingProxy.parseRangeHeader("bytes=0-99,200-299", fileSize: 1000)
        XCTAssertEqual(r, 0..<100)
    }

    func testParseRangeWithWhitespaceTolerated() {
        let r = SMBStreamingProxy.parseRangeHeader("bytes= 100 - 200 ", fileSize: 1000)
        XCTAssertEqual(r, 100..<201)
    }

    // MARK: - Content-Type guessing

    func testContentTypeForMp4() {
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "Movies/film.mp4"), "video/mp4")
    }

    func testContentTypeForMkv() {
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "movie.mkv"), "video/x-matroska")
    }

    func testContentTypeForMovIsQuickTime() {
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "clip.MOV"), "video/quicktime")
    }

    func testContentTypeForJpeg() {
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "Photos/vacation.jpg"), "image/jpeg")
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "x.jpeg"), "image/jpeg")
    }

    func testContentTypeForUnknownExtensionFallsBack() {
        XCTAssertEqual(
            SMBStreamingProxy.guessContentType(for: "file.xyz"),
            "application/octet-stream"
        )
        XCTAssertEqual(
            SMBStreamingProxy.guessContentType(for: "noextension"),
            "application/octet-stream"
        )
    }

    func testContentTypeForSubtitles() {
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "a.srt"), "application/x-subrip")
        XCTAssertEqual(SMBStreamingProxy.guessContentType(for: "a.vtt"), "text/vtt")
    }
}
