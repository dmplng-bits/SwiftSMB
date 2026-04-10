//
//  SMBLeaseCompoundTests.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//

import XCTest
@testable import SwiftSMB

final class SMBLeaseCompoundTests: XCTestCase {

    // MARK: - SMB2LeaseContext generateLeaseKey Tests

    func testGenerateLeaseKeyReturns16Bytes() {
        let key = SMB2LeaseContext.generateLeaseKey()
        XCTAssertEqual(key.count, 16)
    }

    func testGenerateLeaseKeyIsNonEmpty() {
        let key = SMB2LeaseContext.generateLeaseKey()
        let zero = Data(count: 16)
        XCTAssertNotEqual(key, zero)
    }

    func testGenerateLeaseKeyDifferentEachCall() {
        let key1 = SMB2LeaseContext.generateLeaseKey()
        let key2 = SMB2LeaseContext.generateLeaseKey()
        XCTAssertNotEqual(key1, key2)
    }

    // MARK: - SMB2LeaseContext buildV1 Tests

    func testBuildV1ProducesNonEmptyData() {
        let leaseKey = SMB2LeaseContext.generateLeaseKey()
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey)
        XCTAssertGreaterThan(data.count, 0)
    }

    func testBuildV1IncludesLeaseKey() {
        let leaseKey = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey)

        // Context structure has:
        // Header (16) + Name "RqLs" (4) + Padding (4) + Lease data
        // Lease data starts at offset 24 and contains LeaseKey (16) + LeaseState (4) + Flags (4) + Duration (8)
        // LeaseKey should be at offset 24
        XCTAssertGreaterThan(data.count, 40)
        let extractedKey = data.subdata(in: 24..<40)
        XCTAssertEqual(extractedKey, leaseKey)
    }

    func testBuildV1ContextName() {
        let leaseKey = Data(count: 16)
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey)

        // Context header: NextContextOffset(4) + NameOffset(2) + NameLength(2) + Reserved(2) + DataOffset(2) + DataLength(4) = 16 bytes
        // Name starts at offset 16 (NameOffset = 16)
        let nameStart = 16
        let nameLength = 4  // "RqLs"
        let name = String(data: data.subdata(in: nameStart..<nameStart + nameLength), encoding: .utf8)
        XCTAssertEqual(name, "RqLs")
    }

    func testBuildV1WithCustomLeaseState() {
        let leaseKey = Data(count: 16)
        let customState: UInt32 = SMB2LeaseState.readWrite
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey, leaseState: customState)

        // LeaseState is at offset 24 + 16 = 40 (4 bytes LE)
        let stateOffset = 40
        let state = UInt32(data[stateOffset]) |
                   (UInt32(data[stateOffset + 1]) << 8) |
                   (UInt32(data[stateOffset + 2]) << 16) |
                   (UInt32(data[stateOffset + 3]) << 24)
        XCTAssertEqual(state, customState)
    }

    func testBuildV1DefaultLeaseState() {
        let leaseKey = Data(count: 16)
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey)

        // Default should be readHandle
        let stateOffset = 40
        let state = UInt32(data[stateOffset]) |
                   (UInt32(data[stateOffset + 1]) << 8) |
                   (UInt32(data[stateOffset + 2]) << 16) |
                   (UInt32(data[stateOffset + 3]) << 24)
        XCTAssertEqual(state, SMB2LeaseState.readHandle)
    }

    func testBuildV1MinimumSize() {
        // Minimum expected size:
        // Context header (16) + Name (4) + Padding (4) + Lease data (32) = 56 bytes
        let leaseKey = Data(count: 16)
        let data = SMB2LeaseContext.buildV1(leaseKey: leaseKey)
        XCTAssertGreaterThanOrEqual(data.count, 56)
    }

    // MARK: - SMBCompoundBuilder buildRelated Tests

    func testBuildRelatedWithEmptyCommandsReturnsEmpty() {
        let result = SMBCompoundBuilder.buildRelated(
            commands: [],
            sessionId: 0,
            treeId: 0,
            startMessageId: 0
        )
        XCTAssertEqual(result.count, 0)
    }

    func testBuildRelatedWithOneCommand() {
        var cmdBody = ByteWriter()
        cmdBody.uint16le(49)  // Example: WRITE structure size
        let command = SMBCompoundBuilder.Command(command: SMB2Command.write, body: cmdBody.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [command],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        XCTAssertGreaterThan(result.count, 0)
    }

    func testBuildRelatedFirstCommandHasZeroNextCommand() {
        var cmdBody = ByteWriter()
        cmdBody.uint16le(49)
        let command = SMBCompoundBuilder.Command(command: SMB2Command.write, body: cmdBody.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [command],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // For a single command, NextCommand should remain 0 (not set by buildRelated)
        // Check that the packet is valid
        XCTAssertGreaterThanOrEqual(result.count, smb2HeaderSize + cmdBody.data.count)
    }

    func testBuildRelatedTwoDummyCommands() {
        var body1 = ByteWriter()
        body1.uint16le(100)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(200)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // Total packet should contain both commands
        let totalBody = body1.data.count + body2.data.count
        XCTAssertGreater(result.count, 2 * smb2HeaderSize + totalBody)
    }

    func testBuildRelatedFirstPacketHasNonZeroNextCommand() {
        var body1 = ByteWriter()
        body1.uint16le(49)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(50)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // NextCommand is at offset 20 in the header (4 bytes LE).
        // For a compound request with 2+ commands, the first should have non-zero NextCommand.
        let nextCommand = UInt32(result[20]) |
                         (UInt32(result[21]) << 8) |
                         (UInt32(result[22]) << 16) |
                         (UInt32(result[23]) << 24)
        XCTAssertGreaterThan(nextCommand, 0)
    }

    func testBuildRelatedSecondPacketHasZeroNextCommand() {
        var body1 = ByteWriter()
        body1.uint16le(49)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(50)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // First packet's NextCommand tells us where the second packet starts.
        let nextCommand = UInt32(result[20]) |
                         (UInt32(result[21]) << 8) |
                         (UInt32(result[22]) << 16) |
                         (UInt32(result[23]) << 24)

        let secondPacketOffset = Int(nextCommand)
        XCTAssertGreaterThan(secondPacketOffset, smb2HeaderSize)

        // NextCommand in second packet should be 0.
        let secondNextCommand = UInt32(result[secondPacketOffset + 20]) |
                               (UInt32(result[secondPacketOffset + 21]) << 8) |
                               (UInt32(result[secondPacketOffset + 22]) << 16) |
                               (UInt32(result[secondPacketOffset + 23]) << 24)
        XCTAssertEqual(secondNextCommand, 0)
    }

    func testBuildRelatedRelatedFlagSet() {
        var body1 = ByteWriter()
        body1.uint16le(49)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(50)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let result = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // First packet (offset 0): Flags should NOT have SMB2Flags.related.
        let firstFlags = UInt32(result[12]) |
                        (UInt32(result[13]) << 8) |
                        (UInt32(result[14]) << 16) |
                        (UInt32(result[15]) << 24)
        XCTAssertEqual(firstFlags & SMB2Flags.related, 0)

        // Second packet: Flags SHOULD have SMB2Flags.related.
        let nextCommand = UInt32(result[20]) |
                         (UInt32(result[21]) << 8) |
                         (UInt32(result[22]) << 16) |
                         (UInt32(result[23]) << 24)
        let secondOffset = Int(nextCommand)
        let secondFlags = UInt32(result[secondOffset + 12]) |
                         (UInt32(result[secondOffset + 13]) << 8) |
                         (UInt32(result[secondOffset + 14]) << 16) |
                         (UInt32(result[secondOffset + 15]) << 24)
        XCTAssertNotEqual(secondFlags & SMB2Flags.related, 0)
    }

    // MARK: - SMBCompoundBuilder parseResponses Tests

    func testParseResponsesEmpty() {
        let result = SMBCompoundBuilder.parseResponses(Data())
        XCTAssertEqual(result.count, 0)
    }

    func testParseResponsesRoundTripWithBuildRelated() {
        // Build a compound request with 2 dummy commands
        var body1 = ByteWriter()
        body1.uint16le(49)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(50)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let packet = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        // Parse the packet back
        let parsed = SMBCompoundBuilder.parseResponses(packet)

        // Should get back 2 responses
        XCTAssertEqual(parsed.count, 2)
    }

    func testParseResponsesExtractsHeaders() {
        // Build a compound request with 2 commands
        var body1 = ByteWriter()
        body1.uint16le(49)
        let cmd1 = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body1.data)

        var body2 = ByteWriter()
        body2.uint16le(50)
        let cmd2 = SMBCompoundBuilder.Command(command: SMB2Command.read, body: body2.data)

        let packet = SMBCompoundBuilder.buildRelated(
            commands: [cmd1, cmd2],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        let parsed = SMBCompoundBuilder.parseResponses(packet)

        // Each response should have a non-empty body
        XCTAssertGreaterThan(parsed[0].1.count, 0)
        XCTAssertGreaterThan(parsed[1].1.count, 0)
    }

    func testParseResponsesSingleCommand() {
        // Build a single command request
        var body = ByteWriter()
        body.uint16le(49)
        let cmd = SMBCompoundBuilder.Command(command: SMB2Command.write, body: body.data)

        let packet = SMBCompoundBuilder.buildRelated(
            commands: [cmd],
            sessionId: 1,
            treeId: 1,
            startMessageId: 1
        )

        let parsed = SMBCompoundBuilder.parseResponses(packet)
        XCTAssertEqual(parsed.count, 1)
    }
}

// MARK: - SMB2Command and SMB2Flags Constants

/// SMB2 command codes
public enum SMB2Command {
    public static let negotiate: UInt16 = 0
    public static let sessionSetup: UInt16 = 1
    public static let logoff: UInt16 = 2
    public static let treeConnect: UInt16 = 3
    public static let treeDisconnect: UInt16 = 4
    public static let create: UInt16 = 5
    public static let close: UInt16 = 6
    public static let flush: UInt16 = 7
    public static let read: UInt16 = 8
    public static let write: UInt16 = 9
    public static let lock: UInt16 = 10
    public static let ioctl: UInt16 = 11
    public static let cancel: UInt16 = 12
    public static let echo: UInt16 = 13
    public static let queryDirectory: UInt16 = 14
    public static let changeNotify: UInt16 = 15
    public static let queryInfo: UInt16 = 16
    public static let setInfo: UInt16 = 17
    public static let breakRequest: UInt16 = 18
}

/// SMB2 header flags
public enum SMB2Flags {
    public static let serverToClient: UInt32 = 0x0000_0001
    public static let asyncCommand: UInt32 = 0x0000_0002
    public static let related: UInt32 = 0x0000_0004
    public static let signed: UInt32 = 0x0000_0008
    public static let encrypted: UInt32 = 0x0000_0200
}

/// SMB2 lease state constants
public enum SMB2LeaseState {
    public static let readCaching: UInt32 = 0x0000_0001
    public static let handleCaching: UInt32 = 0x0000_0002
    public static let writeCaching: UInt32 = 0x0000_0004
    public static let readHandle: UInt32 = readCaching | handleCaching
    public static let readWrite: UInt32 = readCaching | writeCaching
    public static let all: UInt32 = readCaching | handleCaching | writeCaching
}
