//
//  SPNEGO.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/7/26.
//
// SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) token
// encoding/decoding for SMB2 SESSION_SETUP.
//
// SMB2 wraps NTLM authentication tokens inside SPNEGO, which is itself
// wrapped in GSSAPI. The flow:
//
//   Client → NegTokenInit  (contains NTLM NEGOTIATE, Type 1)
//   Server → NegTokenResp  (contains NTLM CHALLENGE, Type 2)
//   Client → NegTokenResp  (contains NTLM AUTHENTICATE, Type 3)
//
// This implementation uses our generic ASN.1 DER codec rather than
// hard-coding byte sequences.

import Foundation

// MARK: - Well-known OIDs

public enum SPNEGO {

    /// SPNEGO mechanism OID: 1.3.6.1.5.5.2
    public static let spnegoOID = "1.3.6.1.5.5.2"

    /// NTLMSSP mechanism OID: 1.3.6.1.4.1.311.2.2.10
    public static let ntlmsspOID = "1.3.6.1.4.1.311.2.2.10"

    /// SPNEGO negotiation result values.
    public enum NegResult: UInt8 {
        case acceptCompleted  = 0
        case acceptIncomplete = 1
        case reject           = 2
    }

    // ── Encoding ────────────────────────────────────────────────────────

    /// Wrap an NTLM NEGOTIATE (Type 1) message in a SPNEGO NegTokenInit,
    /// further wrapped in the GSSAPI application tag.
    ///
    /// Structure:
    ///   APPLICATION [0] {
    ///     OID 1.3.6.1.5.5.2
    ///     NegTokenInit [0] {
    ///       SEQUENCE {
    ///         [0] SEQUENCE { OID ntlmssp }   -- mechTypes
    ///         [2] OCTET STRING { ntlm }      -- mechToken
    ///       }
    ///     }
    ///   }
    public static func wrapNegTokenInit(ntlmNegotiate: Data) -> Data {
        // MechType list: SEQUENCE { OID(ntlmssp) }
        let mechTypeList = ASN1Encoder.sequence([
            ASN1Encoder.oid(ntlmsspOID)
        ])

        // NegTokenInit inner SEQUENCE
        let negTokenInitInner = ASN1Encoder.sequence([
            ASN1Encoder.context(0, value: mechTypeList),       // mechTypes
            ASN1Encoder.context(2, value:
                ASN1Encoder.octetString(ntlmNegotiate)),       // mechToken
        ])

        // Wrap in context [0] (NegotiationToken choice = NegTokenInit)
        let negToken = ASN1Encoder.context(0, value: negTokenInitInner)

        // GSSAPI APPLICATION [0] wrapper
        let application = ASN1Encoder.constructed(tag: 0x60, children: [
            ASN1Encoder.oid(spnegoOID),
            negToken,
        ])

        return application
    }

    /// Wrap an NTLM AUTHENTICATE (Type 3) message in a SPNEGO NegTokenResp.
    ///
    /// Structure:
    ///   NegTokenResp [1] {
    ///     SEQUENCE {
    ///       [2] OCTET STRING { ntlm }   -- responseToken
    ///     }
    ///   }
    public static func wrapNegTokenResp(ntlmAuthenticate: Data) -> Data {
        let inner = ASN1Encoder.sequence([
            ASN1Encoder.context(2, value:
                ASN1Encoder.octetString(ntlmAuthenticate)),
        ])
        return ASN1Encoder.context(1, value: inner)
    }

    // ── Decoding ────────────────────────────────────────────────────────

    /// Parse a SPNEGO NegTokenResp (server's response containing the NTLM
    /// CHALLENGE token and negotiation result).
    ///
    /// The input may be either:
    ///   - A raw NegTokenResp [1] tag
    ///   - A GSSAPI APPLICATION [0] wrapper containing a NegTokenResp
    ///
    /// Returns the parsed fields.
    public static func parseNegTokenResp(_ data: Data) throws -> NegTokenRespFields {
        let root = try ASN1Decoder.parse(data)

        // Find the NegTokenResp SEQUENCE. It might be:
        //   - Directly inside a context [1] tag
        //   - Inside APPLICATION [0] > context [1]
        //   - The root itself if it's a SEQUENCE
        let respSequence: ASN1Node
        if root.tag == 0xA1 {
            // Context [1] → NegTokenResp
            guard let seq = root.children.first else { throw SMBError.spnegoDecodeFailed }
            respSequence = seq
        } else if root.tag == 0x60 {
            // GSSAPI APPLICATION [0] → look for context [1] inside
            guard let ctx1 = root.first(tag: 0xA1),
                  let seq = ctx1.children.first else { throw SMBError.spnegoDecodeFailed }
            respSequence = seq
        } else if root.tag == ASN1Tag.sequence {
            respSequence = root
        } else {
            throw SMBError.spnegoDecodeFailed
        }

        var result = NegTokenRespFields()

        for child in respSequence.children {
            switch child.tag {
            case 0xA0: // [0] negResult ENUMERATED
                if let enumNode = child.children.first, !enumNode.data.isEmpty {
                    result.negResult = NegResult(rawValue: enumNode.data[enumNode.data.startIndex])
                }
            case 0xA1: // [1] supportedMech OID
                if let oidNode = child.children.first {
                    result.supportedMech = oidNode.oidString
                }
            case 0xA2: // [2] responseToken OCTET STRING
                if let tokenNode = child.children.first {
                    result.responseToken = tokenNode.data
                }
            case 0xA3: // [3] mechListMIC OCTET STRING
                if let micNode = child.children.first {
                    result.mechListMIC = micNode.data
                }
            default:
                break
            }
        }

        return result
    }

    /// Convenience: extract just the NTLM token from a SPNEGO response.
    /// This is what you pass to `NTLMv2.parseChallenge()`.
    public static func extractNTLMToken(_ spnegoData: Data) throws -> Data {
        let fields = try parseNegTokenResp(spnegoData)
        guard let token = fields.responseToken, !token.isEmpty else {
            throw SMBError.spnegoDecodeFailed
        }
        return token
    }
}

// MARK: - Parsed NegTokenResp fields

extension SPNEGO {

    /// Fields extracted from a NegTokenResp.
    public struct NegTokenRespFields {
        public var negResult: NegResult?
        public var supportedMech: String?
        public var responseToken: Data?
        public var mechListMIC: Data?
    }
}
