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

    // NTLMSSP Negotiate flags ([MS-NLMP] §2.2.2.5). We keep the ones we
    // actually set or test named; the rest stay as raw bit patterns.
    public enum Flag {
        public static let unicode:                   UInt32 = 0x0000_0001
        public static let requestTarget:             UInt32 = 0x0000_0004
        public static let sign:                      UInt32 = 0x0000_0010
        public static let seal:                      UInt32 = 0x0000_0020
        public static let ntlm:                      UInt32 = 0x0000_0200
        public static let anonymous:                 UInt32 = 0x0000_0800
        public static let alwaysSign:                UInt32 = 0x0000_8000
        public static let extendedSessionSecurity:   UInt32 = 0x0008_0000
        public static let targetTypeServer:          UInt32 = 0x0002_0000
        public static let targetInfo:                UInt32 = 0x0080_0000
        public static let version:                   UInt32 = 0x0200_0000
        public static let key128:                    UInt32 = 0x2000_0000
        public static let keyExch:                   UInt32 = 0x4000_0000
        public static let key56:                     UInt32 = 0x8000_0000
    }

    // ── Key derivation ──────────────────────────────────────────────────

    /// NT Hash: MD4(UTF-16LE(password)).
    /// This is the starting point of NTLMv2 key derivation.
    public static func ntHash(password: String) -> Data {
        MD4.hash(data: password.utf16leData)
    }

    /// NTLMv2 Hash: HMAC-MD5(ntHash, UTF-16LE(UPPER(user) + domain)).
    /// The `domain` should be the NetBIOS domain or target name.
    ///
    /// Use a locale-independent uppercase — `String.uppercased()` without
    /// a locale argument uses the user's current locale, which on Turkish
    /// systems maps "i" → "İ" (U+0130) and breaks auth against servers
    /// that uppercase with en_US_POSIX.
    public static func ntlmv2Hash(ntHash: Data, user: String, domain: String) -> Data {
        let upperUser = user.uppercased(with: Locale(identifier: "en_US_POSIX"))
        let identity = (upperUser + domain).utf16leData
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

    /// Default flag set for the Type 1 (NEGOTIATE) message.
    ///
    /// Includes SIGN + KEY_EXCH so servers that mandate SMB signing
    /// (TrueNAS Scale, Windows Server with "RequireSecuritySignature",
    /// Samba with `server signing = mandatory`) don't reject the
    /// SessionSetup. Also includes TARGET_INFO and 128-bit key
    /// capabilities so the server emits a proper AV_PAIR blob.
    public static let defaultNegotiateFlags: UInt32 =
        Flag.unicode |
        Flag.requestTarget |
        Flag.sign |
        Flag.ntlm |
        Flag.alwaysSign |
        Flag.extendedSessionSecurity |
        Flag.targetInfo |
        Flag.version |
        Flag.key128 |
        Flag.keyExch |
        Flag.key56

    /// Build a Type 1 (NEGOTIATE) message.
    ///
    /// `additionalFlags` is OR'd into the default flag set — set
    /// `Flag.anonymous` for a null session.
    public static func negotiate(additionalFlags: UInt32 = 0) -> Data {
        var w = ByteWriter()
        w.bytes(signature)
        w.uint32le(typeNegotiate)

        let flags: UInt32 = defaultNegotiateFlags | additionalFlags
        w.uint32le(flags)

        // DomainNameFields (offset/length = 0, we don't send one)
        w.zeros(8)
        // WorkstationFields (offset/length = 0)
        w.zeros(8)

        // Version (8 bytes) — required by [MS-NLMP] §2.2.1.1 when we
        // advertise NTLMSSP_NEGOTIATE_VERSION (we always do). Strict
        // servers (modern Samba) parse this field unconditionally based
        // on the negotiate-version flag, so omitting it shifts every
        // subsequent payload offset by 8 bytes and desyncs the server.
        w.bytes(ntlmVersionStruct())

        return w.data
    }

    /// Standard NTLM VERSION structure ([MS-NLMP] §2.2.2.10).
    /// We claim Windows 10 build 19041, NTLM revision 15 — matching what
    /// impacket and modern Windows ship. Servers only look at the
    /// revision byte.
    private static func ntlmVersionStruct() -> Data {
        var v = ByteWriter()
        v.uint8(10)       // ProductMajorVersion
        v.uint8(0)        // ProductMinorVersion
        v.uint16le(19041) // ProductBuild
        v.zeros(3)        // Reserved (must be zero)
        v.uint8(15)       // NTLMRevisionCurrent = 0x0F (NTLMSSP_REVISION_W2K3)
        return v.data
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

    /// Build an anonymous Type 3 (AUTHENTICATE) message.
    ///
    /// Per [MS-NLMP] §3.2.5.1.2, an anonymous NTLMSSP_AUTHENTICATE
    /// carries empty LM/NT responses, empty user/domain/workstation,
    /// and sets `NTLMSSP_NEGOTIATE_ANONYMOUS` in the flag word. The
    /// LmChallengeResponse is a single zero byte; the NtChallengeResponse
    /// is empty. Servers reply with `SMB2_SESSION_FLAG_IS_NULL`.
    public static func authenticateAnonymous(
        challengeFlags: UInt32,
        workstation: String = ""
    ) -> Data {
        let wsBytes    = workstation.utf16leData
        // Anonymous marker: 1-byte LM response, 0-byte NT response.
        let lmResponse = Data([0x00])
        let ntResponse = Data()

        // Fixed header layout ([MS-NLMP] §2.2.1.3):
        //   Signature(8) + MessageType(4) + 6×SecurityBufferFields(8)
        //   + NegotiateFlags(4) + Version(8) = 72 bytes
        // We always include Version because we always set
        // NTLMSSP_NEGOTIATE_VERSION. No MIC — see note in `authenticate`.
        let headerSize = 72
        var offset = headerSize

        func advance(_ count: Int) -> (offset: UInt32, length: UInt16) {
            let o = offset
            offset += count
            return (UInt32(o), UInt16(count))
        }

        let lmField     = advance(lmResponse.count)
        let ntField     = advance(ntResponse.count)
        let domainField = advance(0)
        let userField   = advance(0)
        let wsField     = advance(wsBytes.count)
        let skField     = advance(0)

        // Strip the KEY_EXCH bit (no session key to exchange) and add
        // the ANONYMOUS marker. Keep VERSION since we write the struct.
        let flags = (challengeFlags & ~Flag.keyExch) | Flag.anonymous

        var w = ByteWriter()
        w.bytes(signature)
        w.uint32le(typeAuthenticate)

        func writeBuf(_ field: (offset: UInt32, length: UInt16)) {
            w.uint16le(field.length)
            w.uint16le(field.length)
            w.uint32le(field.offset)
        }
        writeBuf(lmField)
        writeBuf(ntField)
        writeBuf(domainField)
        writeBuf(userField)
        writeBuf(wsField)
        writeBuf(skField)
        w.uint32le(flags)
        // Version — must be present because NTLMSSP_NEGOTIATE_VERSION
        // is still set in `flags` above. Without this, every payload
        // offset we computed would be 8 bytes too high → garbage reads
        // on the server → STATUS_INVALID_PARAMETER.
        w.bytes(ntlmVersionStruct())

        w.bytes(lmResponse)
        w.bytes(ntResponse)
        // domain, user empty
        w.bytes(wsBytes)

        return w.data
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

        // If we're not providing an EncryptedRandomSessionKey, we MUST
        // clear the KEY_EXCH flag — otherwise modern Samba parses an
        // empty key-exchange field and returns STATUS_INVALID_PARAMETER.
        // Server-supported key exchange would require we RC4-encrypt a
        // random session key with KeyExchangeKey; we don't implement
        // that yet, so just tell the server not to expect one.
        let sessionKeyData = sessionBaseKey ?? Data()
        let adjustedFlags = sessionKeyData.isEmpty
            ? (flags & ~Flag.keyExch)
            : flags

        // Fixed header layout ([MS-NLMP] §2.2.1.3):
        //   Signature(8) + MessageType(4) + 6×SecurityBufferFields(8)
        //   + NegotiateFlags(4) + Version(8) = 72 bytes
        //
        // Version is required whenever NTLMSSP_NEGOTIATE_VERSION is set
        // in `flags`. We always set it in the Type-1 message so the
        // server typically keeps it in the challenge and expects it
        // back here. The previous code claimed headerSize = 88 but only
        // actually wrote 64 bytes of header, so every payload offset in
        // the security-buffer descriptors pointed 24 bytes past where
        // the bytes actually were — which is the root cause of the
        // STATUS_INVALID_PARAMETER we were seeing from Samba.
        //
        // MIC is NOT included here. [MS-NLMP] §3.1.5.1.2 says the
        // client MUST compute MIC only if the server's CHALLENGE
        // TargetInfo AV_PAIR list contained MsvAvFlags with the MIC
        // bit set. We'd rather omit it and accept a slightly weaker
        // handshake than send an incorrect MIC.
        let headerSize = 72
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
        w.uint32le(adjustedFlags) // NegotiateFlags
        // Version (8 bytes) — required because NTLMSSP_NEGOTIATE_VERSION
        // is set. See comment on headerSize above.
        w.bytes(ntlmVersionStruct())

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

// MARK: - SP800-108 KDF (Counter Mode) for SMB 3.x key derivation

/// NIST SP 800-108 §5.1 HMAC-SHA256 counter-mode KDF, as used by
/// SMB 3.x for signing/encryption key derivation ([MS-SMB2] §3.1.4.2).
///
/// One iteration is enough for SMB's L=128 case (16-byte output)
/// because HMAC-SHA256 already produces 32 bytes.
///
/// Format of each block's input:
///     [i]₄ || Label || 0x00 || Context || [L]₄
/// where [i] and [L] are big-endian 32-bit integers.
public func smbKDF(
    key: Data,
    label: Data,
    context: Data,
    outputLength: Int = 16
) -> Data {
    // L is the *bit length* of the desired output, big-endian.
    let L = UInt32(outputLength * 8)

    var input = Data()
    // Counter i = 1 (big-endian).
    input.append(0x00)
    input.append(0x00)
    input.append(0x00)
    input.append(0x01)
    input.append(label)
    input.append(0x00)           // null separator
    input.append(context)
    // [L]₄ big-endian
    input.append(UInt8((L >> 24) & 0xFF))
    input.append(UInt8((L >> 16) & 0xFF))
    input.append(UInt8((L >>  8) & 0xFF))
    input.append(UInt8( L        & 0xFF))

    let mac = HMAC<SHA256>.authenticationCode(
        for: input,
        using: SymmetricKey(data: key)
    )
    return Data(mac).prefix(outputLength)
}

/// Helper: string with appended NUL terminator, matching how [MS-SMB2]
/// defines Label and Context values for the SP800-108 KDF.
/// Windows/Samba/impacket all include the trailing NUL in the input.
private func asciiZ(_ s: String) -> Data {
    var d = Data(s.utf8)
    d.append(0x00)
    return d
}

/// Derive the SMB signing key per [MS-SMB2] §3.1.4.2.
///
/// - `sessionBaseKey`: the 16-byte NTLMv2 session base key.
/// - `dialect`: negotiated SMB2 dialect (`SMB2Dialect.*`).
/// - `preauthIntegrityHash`: 64-byte SHA-512 hash of NEGOTIATE +
///   SESSION_SETUP messages. Required for SMB 3.1.1. Ignored otherwise.
public func smbDeriveSigningKey(
    sessionBaseKey: Data,
    dialect: UInt16,
    preauthIntegrityHash: Data
) -> Data {
    switch dialect {
    case SMB2Dialect.smb300, SMB2Dialect.smb302:
        return smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMB2AESCMAC"),
            context: asciiZ("SmbSign")
        )
    case SMB2Dialect.smb311:
        return smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMBSigningKey"),
            context: preauthIntegrityHash
        )
    default:
        // SMB 2.0.2 / 2.1.x: signing key IS the session base key.
        return sessionBaseKey
    }
}

/// Derive the SMB 3.x encryption key pair per [MS-SMB2] §3.1.4.2.
///
/// Returns `(encryption, decryption)` where:
/// * `encryption` is used to seal client-to-server traffic.
/// * `decryption` is used to open server-to-client traffic.
///
/// Returns `nil` for dialects that don't support encryption (2.x).
public func smbDeriveEncryptionKeys(
    sessionBaseKey: Data,
    dialect: UInt16,
    preauthIntegrityHash: Data
) -> (encryption: Data, decryption: Data)? {
    switch dialect {
    case SMB2Dialect.smb300, SMB2Dialect.smb302:
        // SMB 3.0 / 3.0.2 use the CCM label for both keys; the context
        // byte-string ("ServerIn " / "ServerOut") selects direction.
        // Note the trailing space in "ServerIn " — it's 9 characters
        // plus the NUL terminator, matching "ServerOut\0" length.
        let enc = smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMB2AESCCM"),
            context: asciiZ("ServerIn ")
        )
        let dec = smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMB2AESCCM"),
            context: asciiZ("ServerOut")
        )
        return (enc, dec)

    case SMB2Dialect.smb311:
        // 3.1.1 uses separate labels per direction; the context is the
        // preauth integrity hash (already captured in the session).
        let enc = smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMBC2SCipherKey"),
            context: preauthIntegrityHash
        )
        let dec = smbKDF(
            key:     sessionBaseKey,
            label:   asciiZ("SMBS2CCipherKey"),
            context: preauthIntegrityHash
        )
        return (enc, dec)

    default:
        return nil
    }
}
