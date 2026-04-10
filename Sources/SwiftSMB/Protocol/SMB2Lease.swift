//
//  SMB2Lease.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// SMB2 Lease Create Context for requesting client-side caching.
// Leases allow the client to cache file data locally, reducing
// network round trips for repeated reads of the same file.

import Foundation

/// Builds SMB2_CREATE_REQUEST_LEASE create context.
public enum SMB2LeaseContext {

    /// The create context name for lease request.
    public static let name = "RqLs"

    /// Generate a random 16-byte lease key.
    public static func generateLeaseKey() -> Data {
        let uuid = UUID()
        return withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }

    /// Build a CREATE_REQUEST_LEASE (V1) create context.
    /// - `leaseKey`: 16-byte unique key for this lease.
    /// - `leaseState`: requested lease state (R, RH, RWH).
    public static func buildV1(
        leaseKey: Data,
        leaseState: UInt32 = SMB2LeaseState.readHandle
    ) -> Data {
        // Context structure:
        // NextContextOffset(4) + NameOffset(2) + NameLength(2) + Reserved(2) + DataOffset(2) + DataLength(4) = 16 bytes header
        // Name: "RqLs" (4 bytes) + padding to align data to 8-byte boundary = 4 bytes + 4 padding = 8 bytes
        // Data: LeaseKey(16) + LeaseState(4) + LeaseFlags(4) + LeaseDuration(8) = 32 bytes

        let nameData = Data(name.utf8)
        let nameOffset: UInt16 = 16  // from start of context
        let dataOffset: UInt16 = 24  // 16 (header) + 4 (name) + 4 (padding) = 24
        let dataLength: UInt32 = 32

        var w = ByteWriter()
        // Context header
        w.uint32le(0)                   // NextContextOffset (0 = last/only context)
        w.uint16le(nameOffset)          // NameOffset
        w.uint16le(UInt16(nameData.count))  // NameLength
        w.zeros(2)                      // Reserved
        w.uint16le(dataOffset)          // DataOffset
        w.uint32le(dataLength)          // DataLength

        // Name
        w.bytes(nameData)               // "RqLs"
        w.zeros(4)                      // padding to 8-byte alignment

        // Lease data (V1)
        w.bytes(leaseKey.prefix(16))    // LeaseKey (16 bytes)
        w.uint32le(leaseState)          // LeaseState
        w.uint32le(0)                   // LeaseFlags
        w.uint64le(0)                   // LeaseDuration (0 = default)

        return w.data
    }

    /// Parse a lease response from a CREATE response's create contexts.
    /// Returns the granted lease state, or nil if no lease context found.
    public static func parseLeaseResponse(_ contextData: Data) -> UInt32? {
        // Walk the create context chain looking for "RqLs"
        var offset = 0
        while offset < contextData.count {
            guard offset + 16 <= contextData.count else { return nil }
            let r = ByteReader(contextData)

            let nextOffset = r.uint32le(at: offset)
            let nameOff = Int(r.uint16le(at: offset + 4))
            let nameLen = Int(r.uint16le(at: offset + 6))
            let dataOff = Int(r.uint16le(at: offset + 10))
            let dataLen = Int(r.uint32le(at: offset + 12))

            // Read name
            let absNameOff = offset + nameOff
            if absNameOff + nameLen <= contextData.count {
                let nameBytes = contextData[contextData.startIndex + absNameOff ..< contextData.startIndex + absNameOff + nameLen]
                if String(data: Data(nameBytes), encoding: .utf8) == name {
                    // Found lease context — read the lease state
                    let absDataOff = offset + dataOff
                    if absDataOff + 20 <= contextData.count {
                        // LeaseKey is 16 bytes, then LeaseState is UInt32
                        let stateOffset = absDataOff + 16
                        let state = r.uint32le(at: stateOffset)
                        return state
                    }
                }
            }

            if nextOffset == 0 { break }
            offset += Int(nextOffset)
        }
        return nil
    }
}
