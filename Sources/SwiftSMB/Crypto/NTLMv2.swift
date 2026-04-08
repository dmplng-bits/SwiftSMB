//
//  NTLMv2.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// NTLMv2 authentication for SMB2.
//
// Flow:
//   1. Client sends NEGOTIATE (Type 1) → server returns CHALLENGE (Type 2).
//   2. Client computes NTLMv2 response using password + server challenge.
//   3. Client sends AUTHENTICATE (Type 3) → server grants or denies.
//
// The NT password hash uses our pure-Swift MD4.
// HMAC-MD5 uses Apple's CryptoKit (hardware-accelerated).

import Foundation
import CryptoKit

// MARK: - Public API

public enum NTLMv2 {

    /// The 8-byte NTLMSSP signature at the start of every NTLM message.
    public static let signature = Data("NTLMSSP\0".utf8)

    // NTLM message type codes.
    public static let typeNegotiate:    UInt32 = 1
    public static let typeChallenge:    UInt32 = 2
    public static let typeAuthenticate: UInt32 = 3

    // ── Key derivation ──────────────────────────────────────────────────

    /// NT Hash: MD4(UTF-16LE(password)).
    /// This is the starting point of NTLMv2 key derivation.
    public static func ntHash(password: String) -> Data {
        MD4.hash(data: password.utf16leData)
    }

    /// NTLMv2 Hash: HMAC-MD5(ntHash, UTF-16LE(UPPER(user) + domain)).
    /// The `domain` should be the NetBIOS domain or target name.
    public static func ntlmv2Hash(ntHash: Data, user: String, domain: String) -> Data {
        let identity = (user.uppercased() + domain).utf16leData
        return hmacMD5(key: ntHash, data: identity)
    }

    // ── Challenge-response computation ──────────────────────────────────

    /// Compute the NTLMv2 response given the NTLMv2 hash, server challenge,
    /// and a client blob (which includes timestamp, client challenge, and
    /// target info from the server).
    ///
    /// Returns `(ntProofStr, ntChallengeResponse, sessionBaseKey)`.
    public static func computeResponse(
        ntlmv2Hash: Data,
        serverChallenge: Data,
        clientBlob: Data
    ) -> (ntProofStr: Data, ntChallengeResponse: Data, sessionBaseKey: Data) {
        // NTProofStr = HMAC-MD5(ntlmv2Hash, serverChallenge + blob)
        let ntProofStr = hmacMD5(key: ntlmv2Hash, data: serverChallenge + clientBlob)
        // Full response = NTProofStr + clientBlob
        let ntChallengeResponse = ntProofStr + clientBlob
        // Session base key = HMAC-MD5(ntlmv2Hash, NTProofStr)
        let sessionBaseKey = hmacMD5(key: ntlmv2Hash, data: ntProofStr)
        return (ntProofStr, ntChallengeResponse, sessionBaseKey)
    }

    // ── Client blob construction ────────────────────────────────────────

    /// Build the NTLMv2 client blob (a.k.a. temp structure).
    ///
    /// - `timestamp`: Windows FILETIME (100-ns intervals since 1601-01-01).
    ///   Use `NTLMv2.currentFileTime()` for the current time.
    /// - `clientChallenge`: 8 random bytes.
    /// - `targetInfo`: raw AV_PAIR list from the server's CHALLENGE message.
    public static func buildClientBlob(
        timestamp: UInt64,
        clientChallenge: Data,
        targetInfo: Data
    ) -> Data {
        var w = ByteWriter()
        w.uint8(0x01)                // RespType
        w.uint8(0x01)                // HiRespType
        w.zeros(2)                   // Reserved1
        w.zeros(4)                   // Reserved2
        w.uint64le(timestamp)        // TimeStamp
        w.bytes(clientChallenge)     // ChallengeFromClient (8 bytes)
        w.zeros(4)                   // Reserved3
        w.bytes(targetInfo)          // AvPairs from server
        w.zeros(4)                   // End-of-list sentinel (MsvAvEOL)
        return w.data
    }

    /// Current time as a Windows FILETIME value.
    /// (100-nanosecond intervals since January 1, 1601 UTC.)
    public static func currentFileTime() -> UInt64 {
        // Unix epoch (1970-01-01) minus Windows epoch (1601-01-01) in 100-ns ticks.
        let epochDelta: UInt64 = 116_444_736_000_000_000
        let unixSeconds = UInt64(Date().timeIntervalSince1970)
        return unixSeconds * 10_000_000 + epochDelta
    }

    /// Generate 8 cryptographically random bytes for the client challenge.
    public static func randomChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, 8, &bytes)
        return Data(bytes)
    }

    // ── NTLM message builders ───────────────────────────────────────────

    /// Build a Type 1 (NEGOTIATE) message.
    ///
    /// We request NTLMv2, Unicode, and request-target flags.
    /// No domain/workstation strings needed for anonymous negotiate.
    public static func negotiate() -> Data {
        var w = ByteWriter()
        w.bytes(signature)
        w.uint32le(typeNegotiate)

        // NegotiateFlags:
        //   NTLMSSP_NEGOTIATE_UNICODE       (0x01)
        //   NTLMSSP_NEGOTIATE_NTLM          (0x200)
        //   NTLMSSP_REQUEST_TARGET           (0x04)
        //   NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x80000)
        //   NTLMSSP_NEGOTIATE_ALWAYS_SIGN    (0x8000)
        let flags: UInt32 = 0x00088207
        w.uint32le(flags)

        // DomainNameFields (offset/length = 0, we don't send one)
        w.zeros(8)
        // WorkstationFields (offset/length = 0)
        w.zeros(8)

        return w.data
    }

    /// Parse a Type 2 (CHALLENGE) message from the server.
    ///
    /// Returns the server challenge (8 bytes) and the target info AV_PAIR blob.
    public static func parseChallenge(_ data: Data) throws -> ChallengeMessage {
        var r = ByteReader(data)

        // Validate signature.
        let sig = try r.bytes(8)
        guard sig == signature else { throw SMBError.invalidNTLMMessage }

        // Validate type.
        let msgType = try r.uint32le()
        guard msgType == typeChallenge else { throw SMBError.invalidNTLMMessage }

        // TargetNameFields (2+2+4 = 8 bytes)
        let targetNameLen    = try r.uint16le()
        let _                = try r.uint16le()   // maxLen
        let targetNameOffset = try r.uint32le()

        // NegotiateFlags
        let flags = try r.uint32le()

        // ServerChallenge (8 bytes)
        let serverChallenge = try r.bytes(8)

        // Reserved (8 bytes)
        try r.skip(8)

        // TargetInfoFields (2+2+4 = 8 bytes)
        let targetInfoLen    = try r.uint16le()
        let _                = try r.uint16le()   // maxLen
        let targetInfoOffset = try r.uint32le()

        // Extract target name using offset.
        let targetName: String
        if targetNameLen > 0 {
            let nameData = ByteReader(data).subdata(at: Int(targetNameOffset), length: Int(targetNameLen))
            targetName = nameData.utf16leString
        } else {
            targetName = ""
        }

        // Extract target info blob using offset.
        let targetInfo: Data
        if targetInfoLen > 0 {
            targetInfo = ByteReader(data).subdata(at: Int(targetInfoOffset), length: Int(targetInfoLen))
        } else {
            targetInfo = Data()
        }

        return ChallengeMessage(
            flags: flags,
            serverChallenge: serverChallenge,
            targetName: targetName,
            targetInfo: targetInfo
        )
    }

    /// Build a Type 3 (AUTHENTICATE) message.
    public static func authenticate(
        flags: UInt32,
        ntChallengeResponse: Data,
        domain: String,
        user: String,
        workstation: String = "",
        sessionBaseKey: Data? = nil
    ) -> Data {
        // Encode strings as UTF-16LE.
        let domainBytes = domain.utf16leData
        let userBytes   = user.utf16leData
        let wsBytes     = workstation.utf16leData
        let lmResponse  = Data(count: 24)  // empty LM response (NTLMv2 doesn't use it)

        // The payload starts right after the fixed header.
        // Fixed header = 8 (sig) + 4 (type) + 6*8 (six SecurityBuffer fields) + 4 (flags) = 88 bytes
        let headerSize = 88
        var offset = headerSize

        func advance(_ count: Int) -> (offset: UInt32, length: UInt16) {
            let o = offset
            offset += count
            return (UInt32(o), UInt16(count))
        }

        let lmField     = advance(lmResponse.count)
        let ntField     = advance(ntChallengeResponse.count)
        let domainField = advance(domainBytes.count)
        let userField   = advance(userBytes.count)
        let wsField     = advance(wsBytes.count)
        let sessionKeyData = sessionBaseKey ?? Data()
        let skField     = advance(sessionKeyData.count)

        var w = ByteWriter()
        w.bytes(signature)
        w.uint32le(typeAuthenticate)

        // SecurityBuffer: Length(2) + MaxLength(2) + Offset(4) = 8 bytes each
        func writeBuf(_ field: (offset: UInt32, length: UInt16)) {
            w.uint16le(field.length)
            w.uint16le(field.length)
            w.uint32le(field.offset)
        }

        writeBuf(lmField)      // LmChallengeResponseFields
        writeBuf(ntField)       // NtChallengeResponseFields
        writeBuf(domainField)   // DomainNameFields
        writeBuf(userField)     // UserNameFields
        writeBuf(wsField)       // WorkstationFields
        writeBuf(skField)       // EncryptedRandomSessionKeyFields
        w.uint32le(flags)       // NegotiateFlags

        // Payload
        w.bytes(lmResponse)
        w.bytes(ntChallengeResponse)
        w.bytes(domainBytes)
        w.bytes(userBytes)
        w.bytes(wsBytes)
        if !sessionKeyData.isEmpty {
            w.bytes(sessionKeyData)
        }

        return w.data
    }

    // ── AV_PAIR helpers ─────────────────────────────────────────────────

    /// Parse the AV_PAIR list from target info into a dictionary.
    /// Keys are AvId values (UInt16), values are the raw Data.
    public static func parseAvPairs(_ data: Data) -> [UInt16: Data] {
        var pairs: [UInt16: Data] = [:]
        var r = ByteReader(data)
        while !r.atEnd {
            guard let avId = try? r.uint16le(),
                  let avLen = try? r.uint16le() else { break }
            if avId == 0 { break }  // MsvAvEOL
            guard let value = try? r.bytes(Int(avLen)) else { break }
            pairs[avId] = value
        }
        return pairs
    }

    /// Well-known AV_PAIR identifiers.
    public enum AvId {
        public static let eol:              UInt16 = 0x0000
        public static let nbComputerName:   UInt16 = 0x0001
        public static let nbDomainName:     UInt16 = 0x0002
        public static let dnsComputerName:  UInt16 = 0x0003
        public static let dnsDomainName:    UInt16 = 0x0004
        public static let dnsTreeName:      UInt16 = 0x0005
        public static let flags:            UInt16 = 0x0006
        public static let timestamp:        UInt16 = 0x0007
        public static let targetName:       UInt16 = 0x0009
    }
}

// MARK: - Challenge message

extension NTLMv2 {

    /// Parsed fields from a Type 2 (CHALLENGE) message.
    public struct ChallengeMessage {
        public let flags: UInt32
        public let serverChallenge: Data   // 8 bytes
        public let targetName: String
        public let targetInfo: Data        // raw AV_PAIR blob
    }
}

// MARK: - HMAC-MD5 (via CryptoKit)

/// HMAC-MD5 using Apple's CryptoKit.
/// CryptoKit provides `HMAC<Insecure.MD5>` which is exactly what NTLMv2 needs.
func hmacMD5(key: Data, data: Data) -> Data {
    let symmetricKey = SymmetricKey(data: key)
    let mac = HMAC<Insecure.MD5>.authenticationCode(for: data, using: symmetricKey)
    return Data(mac)
}
