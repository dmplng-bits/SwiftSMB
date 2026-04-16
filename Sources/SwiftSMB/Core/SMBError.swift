//
//  SMBError.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// Every error SwiftSMB can throw, in one place.
// New cases will be added in future steps as we build each layer.

import Foundation

public enum SMBError: LocalizedError {

    // ── Step 1: Foundation ───────────────────────────────────────────────
    case truncatedPacket               // tried to read past end of buffer
    case invalidProtocolId             // magic bytes didn't match SMB2

    // ── Step 2: Crypto (placeholders, implemented in v0.2.0) ────────────
    case authenticationFailed
    case invalidNTLMMessage
    case spnegoDecodeFailed

    // ── Step 4: Transport (placeholders, implemented in v0.4.0) ─────────
    case connectionFailed(String)
    case connectionLost
    case notConnected
    case timeout

    // ── Step 5: Session (placeholders, implemented in v0.5.0) ───────────
    case ntStatus(UInt32)              // raw NT status code from server
    case negotiationFailed(String)
    case unexpectedCommand(expected: UInt16, got: UInt16)

    // ── Step 6: Client (placeholders, implemented in v0.6.0) ────────────
    case fileNotFound(String)
    case accessDenied(String)
    case invalidPath
    case directoryNotEmpty(String)
    case fileAlreadyExists(String)

    // ── Credit management ──────────────────────────────────────────────
    case insufficientCredits(needed: UInt16, available: UInt16)

    // ── Signing ────────────────────────────────────────────────────────
    case signingRequired                // server requires signing but we can't
    case signatureVerificationFailed    // inbound packet signature mismatch

    // ── Discovery ──────────────────────────────────────────────────────
    case discoveryFailed(String)
    case shareEnumerationFailed(String)

    // ── Reconnect ──────────────────────────────────────────────────────
    case reconnectFailed(String)

    public var errorDescription: String? {
        switch self {
        case .truncatedPacket:
            return "Tried to read past the end of an SMB2 packet."
        case .invalidProtocolId:
            return "Packet does not start with the SMB2 magic bytes (0xFE 'S' 'M' 'B')."
        case .authenticationFailed:
            return "SMB authentication failed — check your username and password."
        case .invalidNTLMMessage:
            return "Received an invalid NTLM message from the server."
        case .spnegoDecodeFailed:
            return "Failed to decode the SPNEGO/GSSAPI token from the server."
        case .connectionFailed(let detail):
            return "SMB connection failed: \(detail)"
        case .connectionLost:
            return "The SMB connection was lost unexpectedly."
        case .notConnected:
            return "Not connected to any SMB share. Call connectShare() first."
        case .timeout:
            return "The SMB operation timed out."
        case .ntStatus(let code):
            return "Server returned NT status 0x\(String(code, radix: 16, uppercase: true)): \(ntStatusDescription(code))"
        case .negotiationFailed(let detail):
            return "SMB dialect negotiation failed: \(detail)"
        case .unexpectedCommand(let expected, let got):
            return "Expected SMB2 command 0x\(String(expected, radix: 16)), got 0x\(String(got, radix: 16))."
        case .fileNotFound(let path):
            return "File not found on the SMB share: \(path)"
        case .accessDenied(let path):
            return "Access denied: \(path)"
        case .invalidPath:
            return "The provided path is invalid."
        case .directoryNotEmpty(let path):
            return "Directory is not empty: \(path)"
        case .fileAlreadyExists(let path):
            return "File already exists: \(path)"
        case .insufficientCredits(let needed, let available):
            return "Not enough SMB2 credits: need \(needed), have \(available). Try a smaller read."
        case .signingRequired:
            return "The server requires message signing, but signing is not available."
        case .signatureVerificationFailed:
            return "The SMB2 response signature did not match. The packet may be corrupted."
        case .discoveryFailed(let detail):
            return "SMB server discovery failed: \(detail)"
        case .shareEnumerationFailed(let detail):
            return "Failed to enumerate shares: \(detail)"
        case .reconnectFailed(let detail):
            return "SMB reconnect failed: \(detail)"
        }
    }
}

// MARK: - NT Status → human-readable description

private func ntStatusDescription(_ code: UInt32) -> String {
    switch code {
    case 0x00000000: return "SUCCESS"
    case 0xC000000D: return "INVALID_PARAMETER — server rejected the request structure (often a malformed UNC path or NDR-encoded RPC argument)"
    case 0xC0000016: return "MORE_PROCESSING_REQUIRED"
    case 0xC0000022: return "ACCESS_DENIED"
    case 0xC0000034: return "OBJECT_NAME_NOT_FOUND"
    case 0xC000003A: return "OBJECT_PATH_NOT_FOUND"
    case 0xC0000035: return "OBJECT_NAME_COLLISION — file already exists"
    case 0xC0000064: return "NO_SUCH_USER — account does not exist"
    case 0xC000006A: return "WRONG_PASSWORD"
    case 0xC000006D: return "LOGON_FAILURE — wrong username or password"
    case 0xC000006E: return "ACCOUNT_RESTRICTION"
    case 0xC0000071: return "PASSWORD_EXPIRED"
    case 0xC0000072: return "ACCOUNT_DISABLED"
    case 0xC00000BB: return "NOT_SUPPORTED"
    case 0xC00000CC: return "BAD_NETWORK_NAME — share does not exist"
    case 0xC00000E7: return "USER_SESSION_DELETED"
    case 0xC0000101: return "DIRECTORY_NOT_EMPTY"
    case 0x80000006: return "NO_MORE_FILES"
    case 0xC0000011: return "END_OF_FILE"
    case 0xC0000043: return "SHARING_VIOLATION"
    default:         return "unknown status"
    }
}
