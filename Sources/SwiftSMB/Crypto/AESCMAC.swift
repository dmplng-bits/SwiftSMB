//
//  AESCMAC.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/15/26.
//
// AES-CMAC-128 per RFC 4493, used as the signature algorithm for
// SMB 3.0 / 3.0.2 / 3.1.1 ([MS-SMB2] §3.1.4.1). CryptoKit doesn't
// expose CMAC, so this is a standalone implementation built on top
// of a single AES-128 block-encrypt primitive from CommonCrypto.

import Foundation
import CommonCrypto

// MARK: - AES-128 single-block encryption (ECB, no padding)

/// Encrypt one 16-byte block under a 16-byte AES-128 key.
private func aesEncryptBlock(key: Data, block: Data) -> Data {
    precondition(key.count == 16, "AES-128 requires a 16-byte key")
    precondition(block.count == 16, "AES block size is 16 bytes")

    var out = [UInt8](repeating: 0, count: 16)
    var numBytesEncrypted: size_t = 0

    let status = key.withUnsafeBytes { keyPtr -> CCCryptorStatus in
        block.withUnsafeBytes { inPtr -> CCCryptorStatus in
            CCCrypt(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPtr.baseAddress, 16,
                nil,
                inPtr.baseAddress, 16,
                &out, 16,
                &numBytesEncrypted
            )
        }
    }
    precondition(status == kCCSuccess, "AES block encrypt failed")
    return Data(out)
}

// MARK: - AES-CMAC-128

/// Compute AES-CMAC-128 of `data` under a 16-byte key.
/// Returns the full 16-byte tag. SMB2 uses the first 16 bytes verbatim.
public func aesCMAC(key: Data, data: Data) -> Data {
    // ── Subkey generation (RFC 4493 §2.3) ──────────────────────────
    let zero = Data(count: 16)
    let L = aesEncryptBlock(key: key, block: zero)

    let Rb: UInt8 = 0x87
    let K1 = subkey(from: L, Rb: Rb)
    let K2 = subkey(from: K1, Rb: Rb)

    // ── Block split (RFC 4493 §2.4) ────────────────────────────────
    let n: Int
    let lastIsComplete: Bool
    if data.isEmpty {
        n = 1
        lastIsComplete = false
    } else {
        n = (data.count + 15) / 16
        lastIsComplete = (data.count % 16 == 0)
    }

    // Prepare Mn* — the XORed final block.
    var mLast: Data
    if lastIsComplete {
        let start = data.startIndex + (n - 1) * 16
        mLast = Data(data[start ..< start + 16])
        mLast = xor(mLast, K1)
    } else {
        let lastStart = data.startIndex + (n - 1) * 16
        let lastLen = data.count - (n - 1) * 16
        var padded = Data(count: 16)
        if lastLen > 0 {
            for i in 0..<lastLen {
                padded[i] = data[lastStart + i]
            }
        }
        padded[lastLen] = 0x80
        // Remaining bytes already zero.
        mLast = xor(padded, K2)
    }

    // ── CBC-MAC chain (RFC 4493 §2.4) ──────────────────────────────
    var X = Data(count: 16)
    if n > 1 {
        for i in 0..<(n - 1) {
            let start = data.startIndex + i * 16
            let block = Data(data[start ..< start + 16])
            X = aesEncryptBlock(key: key, block: xor(block, X))
        }
    }
    return aesEncryptBlock(key: key, block: xor(mLast, X))
}

// MARK: - Helpers

/// One subkey iteration: `(input << 1) XOR (Rb if MSB==1 else 0)`.
private func subkey(from input: Data, Rb: UInt8) -> Data {
    let shifted = leftShift(input)
    let msb = (input[input.startIndex] >> 7) & 1
    guard msb == 1 else { return shifted }
    var out = shifted
    out[out.index(before: out.endIndex)] ^= Rb
    return out
}

/// Logical left shift of a 16-byte big-endian value by one bit.
private func leftShift(_ input: Data) -> Data {
    var out = Data(count: input.count)
    var carry: UInt8 = 0
    for i in (0..<input.count).reversed() {
        let byte = input[input.startIndex + i]
        out[i] = (byte << 1) | carry
        carry = (byte >> 7) & 1
    }
    return out
}

private func xor(_ a: Data, _ b: Data) -> Data {
    precondition(a.count == b.count)
    var out = Data(count: a.count)
    for i in 0..<a.count {
        out[i] = a[a.startIndex + i] ^ b[b.startIndex + i]
    }
    return out
}
