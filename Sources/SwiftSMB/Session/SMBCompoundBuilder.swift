//
//  SMBCompoundBuilder.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Build compounded (chained) SMB2 requests that the server processes
// as a single atomic sequence, saving network round trips.

import Foundation

/// Builds a compounded SMB2 request from multiple individual packets.
///
/// Example: CREATE + READ + CLOSE in one round trip for small file reads.
public enum SMBCompoundBuilder {

    /// A single command in a compound chain.
    public struct Command {
        public let command: UInt16
        public let body: Data
        public let payloadSize: Int

        public init(command: UInt16, body: Data, payloadSize: Int = 0) {
            self.command = command
            self.body = body
            self.payloadSize = payloadSize
        }
    }

    /// Build a related compound request.
    ///
    /// "Related" means each command after the first inherits the FileId
    /// from the previous response. The server processes them sequentially.
    ///
    /// - `commands`: ordered list of commands to chain.
    /// - `sessionId`: the current session ID.
    /// - `treeId`: the current tree ID.
    /// - `startMessageId`: the first message ID; each subsequent command
    ///   gets startMessageId + index.
    ///
    /// Returns the raw compound packet (all commands concatenated with
    /// NextCommand offsets and 8-byte padding).
    public static func buildRelated(
        commands: [Command],
        creditCharge: UInt16 = 1,
        creditRequest: UInt16 = 32,
        sessionId: UInt64,
        treeId: UInt32,
        startMessageId: UInt64
    ) -> Data {
        guard !commands.isEmpty else { return Data() }

        var packets: [Data] = []

        for (index, cmd) in commands.enumerated() {
            let isFirst = index == 0
            let isLast  = index == commands.count - 1

            var flags: UInt32 = 0
            if !isFirst {
                flags |= SMB2Flags.related
            }

            let header = SMB2HeaderBuilder.build(
                command: cmd.command,
                creditCharge: creditCharge,
                creditRequest: creditRequest,
                flags: flags,
                messageId: startMessageId + UInt64(index),
                sessionId: sessionId,
                treeId: treeId
            )

            var packet = Data()
            packet.append(header)
            packet.append(cmd.body)

            // Pad to 8-byte alignment (except the last command).
            if !isLast {
                let remainder = packet.count % 8
                if remainder != 0 {
                    packet.append(Data(count: 8 - remainder))
                }

                // Set NextCommand to the padded packet size.
                let nextCommand = UInt32(packet.count)
                // NextCommand is at offset 20 in the header.
                packet[packet.startIndex + 20] = UInt8( nextCommand        & 0xFF)
                packet[packet.startIndex + 21] = UInt8((nextCommand >> 8)  & 0xFF)
                packet[packet.startIndex + 22] = UInt8((nextCommand >> 16) & 0xFF)
                packet[packet.startIndex + 23] = UInt8((nextCommand >> 24) & 0xFF)
            }

            packets.append(packet)
        }

        // Concatenate all packets into one compound message.
        var result = Data()
        for p in packets {
            result.append(p)
        }
        return result
    }

    /// Parse a compound response into individual (header, body) pairs.
    /// The server responds with chained responses matching the request order.
    public static func parseResponses(_ data: Data) -> [(SMB2Header, Data)] {
        var results: [(SMB2Header, Data)] = []
        var offset = 0

        while offset < data.count {
            guard offset + smb2HeaderSize <= data.count else { break }

            let headerData = data[data.startIndex + offset ..< data.startIndex + offset + smb2HeaderSize]
            guard let header = try? SMB2Header.parse(Data(headerData)) else { break }

            let nextCommand = Int(header.nextCommand)
            let commandEnd: Int
            if nextCommand > 0 {
                commandEnd = offset + nextCommand
            } else {
                commandEnd = data.count
            }

            let bodyStart = offset + smb2HeaderSize
            let body = data[data.startIndex + bodyStart ..< data.startIndex + commandEnd]
            results.append((header, Data(body)))

            if nextCommand == 0 { break }
            offset += nextCommand
        }

        return results
    }
}
