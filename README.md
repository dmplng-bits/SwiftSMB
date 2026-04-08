# SwiftSMB

A pure Swift SMB2/3 client library for Apple platforms. Browses and streams videos and photos from SMB shares on a NAS.

## Platforms

- tvOS 17+
- iOS 17+
- macOS 14+

## Installation

Add SwiftSMB to your project via Swift Package Manager:

```swift
dependencies: [
    .package(url: "https://github.com/dmplng-bits/SwiftSMB.git", from: "0.1.0")
]
```

---

## Layer Architecture

The library is organized into seven layers, each building on the one below it.

```mermaid
flowchart TD
    Client["<b>Client Layer</b>\nSMBClient public API\nconnect · list · read · stream"]
    Streaming["<b>Streaming Layer</b>\nLocal HTTP/1.1 Proxy\nAVPlayer ↔ Range requests ↔ SMB2 READ"]
    Session["<b>Session Layer</b>\nNEGOTIATE → NTLMv2 Auth → TREE_CONNECT"]
    Protocol["<b>Protocol Layer</b>\nSMB2 Header · Packet Builders · Response Parsers\nCREATE · READ · CLOSE · QUERY_DIRECTORY · QUERY_INFO"]
    Crypto["<b>Crypto Layer</b>\nMD4 (pure Swift) · NTLMv2 · HMAC-MD5 (CryptoKit)\nASN.1 DER Codec · SPNEGO"]
    Transport["<b>Transport Layer</b>\nNetwork.framework TCP · NetBIOS 4-byte framing"]
    Core["<b>Core</b>\nByteWriter · ByteReader (little-endian I/O)\nSMBError (unified error enum)"]

    Client --> Streaming
    Streaming --> Session
    Session --> Protocol
    Protocol --> Crypto
    Protocol --> Transport
    Transport --> Core
    Crypto --> Core

    style Client fill:#4A90D9,color:#fff
    style Streaming fill:#7B68EE,color:#fff
    style Session fill:#E67E22,color:#fff
    style Protocol fill:#27AE60,color:#fff
    style Crypto fill:#E74C3C,color:#fff
    style Transport fill:#F39C12,color:#fff
    style Core fill:#2C3E50,color:#fff
```

---

## Module Dependency Graph

How the Swift source files depend on each other.

```mermaid
flowchart LR
    subgraph Core
        ByteBuffer["ByteBuffer\nByteWriter · ByteReader"]
        SMBError["SMBError"]
    end

    subgraph Crypto
        MD4["MD4"]
        NTLMv2["NTLMv2"]
        ASN1["ASN1\nEncoder · Decoder"]
        SPNEGO["SPNEGO"]
    end

    subgraph Protocol
        Constants["SMB2Constants"]
        Header["SMB2Header"]
        Negotiate["SMB2Negotiate"]
        Session["SMB2Session"]
        Tree["SMB2Tree"]
        Create["SMB2Create"]
        Close["SMB2Close"]
        Read["SMB2Read"]
        Query["SMB2Query"]
    end

    MD4 --> ByteBuffer
    NTLMv2 --> MD4
    NTLMv2 --> ByteBuffer
    SPNEGO --> ASN1
    SPNEGO --> SMBError
    ASN1 --> SMBError

    Header --> ByteBuffer
    Header --> Constants
    Header --> SMBError
    Negotiate --> ByteBuffer
    Negotiate --> Constants
    Session --> ByteBuffer
    Session --> Constants
    Tree --> ByteBuffer
    Tree --> Constants
    Create --> ByteBuffer
    Create --> Constants
    Close --> ByteBuffer
    Read --> ByteBuffer
    Query --> ByteBuffer
    Query --> Constants

    style Core fill:#2C3E50,color:#fff
    style Crypto fill:#E74C3C,color:#fff
    style Protocol fill:#27AE60,color:#fff
```

---

## Connection State Machine

The lifecycle of an SMB2 connection from the client's perspective.

```mermaid
stateDiagram-v2
    [*] --> Disconnected

    Disconnected --> Connecting : connect()
    Connecting --> Negotiating : TCP established

    Negotiating --> Authenticating : NEGOTIATE success
    Negotiating --> Error : dialect mismatch

    Authenticating --> Authenticated : SESSION_SETUP complete
    Authenticating --> ChallengeReceived : MORE_PROCESSING_REQUIRED
    ChallengeReceived --> Authenticating : send Type 3

    Authenticating --> Error : auth failed

    Authenticated --> TreeConnected : TREE_CONNECT success
    Authenticated --> Error : access denied

    TreeConnected --> Ready : FileId available
    Ready --> Ready : CREATE / READ / QUERY / CLOSE

    Ready --> TreeConnected : CLOSE last handle
    TreeConnected --> Authenticated : TREE_DISCONNECT
    Authenticated --> Disconnected : LOGOFF

    Ready --> Error : connection lost
    TreeConnected --> Error : connection lost

    Error --> Disconnected : reset
```

---

## SMB2 Authentication Sequence

The full NTLMv2 handshake wrapped in SPNEGO tokens.

```mermaid
sequenceDiagram
    participant App as Media Player
    participant Client as SMBClient
    participant Crypto as Crypto Layer
    participant Server as NAS (SMB Server)

    App->>Client: connect(host, share, user, password)

    rect rgb(240, 248, 255)
        Note over Client,Server: 1. Dialect Negotiation
        Client->>Server: NEGOTIATE (SMB 2.0.2, 2.1, 3.0, 3.0.2)
        Server->>Client: dialect, serverGuid, capabilities, securityBlob
    end

    rect rgb(255, 245, 238)
        Note over Client,Crypto: 2. NTLMv2 Authentication (Round 1)
        Client->>Crypto: NTLMv2.negotiate()
        Crypto-->>Client: NTLM Type 1 message
        Client->>Crypto: SPNEGO.wrapNegTokenInit(Type 1)
        Crypto-->>Client: SPNEGO token
        Client->>Server: SESSION_SETUP (SPNEGO token)
        Server->>Client: STATUS_MORE_PROCESSING + SPNEGO(Type 2 Challenge)
    end

    rect rgb(255, 243, 230)
        Note over Client,Crypto: 3. NTLMv2 Authentication (Round 2)
        Client->>Crypto: SPNEGO.extractNTLMToken(response)
        Crypto-->>Client: NTLM Type 2 (serverChallenge, targetInfo)
        Client->>Crypto: MD4(UTF16LE(password))
        Crypto-->>Client: ntHash
        Client->>Crypto: HMAC-MD5(ntHash, user + domain)
        Crypto-->>Client: ntlmv2Hash
        Client->>Crypto: HMAC-MD5(ntlmv2Hash, challenge + blob)
        Crypto-->>Client: ntProofStr + sessionBaseKey
        Client->>Crypto: NTLMv2.authenticate(...)
        Crypto-->>Client: NTLM Type 3 message
        Client->>Crypto: SPNEGO.wrapNegTokenResp(Type 3)
        Crypto-->>Client: SPNEGO token
        Client->>Server: SESSION_SETUP (SPNEGO token)
        Server->>Client: STATUS_SUCCESS + SessionId
    end

    rect rgb(240, 255, 240)
        Note over Client,Server: 4. Tree Connect
        Client->>Server: TREE_CONNECT ("\\\\host\\share")
        Server->>Client: TreeId + shareType + capabilities
    end

    Client-->>App: connected (sessionId, treeId)
```

---

## Data Flow: Video Streaming

How AVPlayer range requests are translated into SMB2 READ packets.

```mermaid
flowchart LR
    AVPlayer["AVPlayer\n(tvOS)"]
    Proxy["HTTP Proxy\n(localhost:port)"]
    Client["SMBClient"]
    Protocol["SMB2 READ\nPacket Builder"]
    Transport["TCP Socket\n(Network.framework)"]
    NAS["NAS\nSMB Server"]

    AVPlayer -- "HTTP GET\nRange: bytes=X-Y" --> Proxy
    Proxy -- "read(fileId, offset, length)" --> Client
    Client -- "build READ request" --> Protocol
    Protocol -- "64-byte header +\n49-byte body" --> Transport
    Transport -- "NetBIOS frame\n(4-byte length prefix)" --> NAS
    NAS -- "file bytes" --> Transport
    Transport -- "parse READ response" --> Protocol
    Protocol -- "extract data payload" --> Client
    Client -- "Data" --> Proxy
    Proxy -- "HTTP 206\nPartial Content" --> AVPlayer

    style AVPlayer fill:#4A90D9,color:#fff
    style Proxy fill:#7B68EE,color:#fff
    style Client fill:#E67E22,color:#fff
    style Protocol fill:#27AE60,color:#fff
    style Transport fill:#F39C12,color:#fff
    style NAS fill:#2C3E50,color:#fff
```

---

## SMB2 Packet Structure

Every SMB2 message is a 64-byte header followed by a variable-length command body.

```mermaid
flowchart TD
    subgraph Header["SMB2 Header — 64 bytes"]
        direction LR
        H1["0xFE 'SMB'\n(4 bytes)"]
        H2["StructureSize\nCreditCharge\n(4 bytes)"]
        H3["NT Status\nCommand\n(4+2 bytes)"]
        H4["Credits\nFlags\n(2+4 bytes)"]
        H5["NextCommand\nMessageId\n(4+8 bytes)"]
        H6["TreeId\nSessionId\n(4+4+8 bytes)"]
        H7["Signature\n(16 bytes)"]
        H1 --- H2 --- H3 --- H4 --- H5 --- H6 --- H7
    end

    subgraph Body["Command Body — variable length"]
        direction LR
        B1["StructureSize\n(2 bytes)"]
        B2["Fixed Fields\n(command-specific)"]
        B3["BufferOffset +\nBufferLength\n(2+2 bytes)"]
        B4["Payload\n(path, token,\nfile data)"]
        B1 --- B2 --- B3 --- B4
    end

    subgraph Frame["NetBIOS Transport Frame"]
        direction LR
        F1["Length Prefix\n(4 bytes, big-endian)"]
        F2["SMB2 Message\n(Header + Body)"]
        F1 --- F2
    end

    Frame --> Header
    Header --> Body

    style Header fill:#27AE60,color:#fff
    style Body fill:#4A90D9,color:#fff
    style Frame fill:#F39C12,color:#fff
```

---

## Error Handling Strategy

A single `SMBError` enum covers all layers, with cases declared upfront.

```mermaid
flowchart TD
    subgraph Errors["SMBError"]
        direction TB
        E1["Core Errors\ntruncatedPacket\ninvalidProtocolId"]
        E2["Crypto Errors\nauthenticationFailed\ninvalidNTLMMessage\nspnegoDecodeFailed"]
        E3["Transport Errors\nconnectionFailed\nconnectionLost\ntimeout"]
        E4["Session Errors\nntStatus(UInt32)\nnegotiationFailed\nunexpectedCommand"]
        E5["Client Errors\nfileNotFound\naccessDenied\ninvalidPath"]
    end

    Server["Server Response"] --> Parse["Parse NT Status"]
    Parse --> |"0x00000000"| Success["Success"]
    Parse --> |"0xC0000016"| MoreProcessing["More Processing\n(continue auth)"]
    Parse --> |"0xC000006D"| AuthFail["SMBError\n.authenticationFailed"]
    Parse --> |"0xC0000034"| NotFound["SMBError\n.fileNotFound(path)"]
    Parse --> |"other"| Generic["SMBError\n.ntStatus(code)"]

    style Errors fill:#E74C3C,color:#fff
    style Success fill:#27AE60,color:#fff
    style MoreProcessing fill:#F39C12,color:#fff
    style AuthFail fill:#C0392B,color:#fff
    style NotFound fill:#C0392B,color:#fff
    style Generic fill:#C0392B,color:#fff
```

---

## File Structure

```
Sources/SwiftSMB/
├── Core/
│   ├── ByteBuffer.swift      # Little-endian binary I/O
│   └── SMBError.swift         # Unified error enum for all layers
├── Crypto/
│   ├── MD4.swift              # Pure Swift MD4 (RFC 1320)
│   ├── NTLMv2.swift           # NTLMv2 auth + HMAC-MD5 via CryptoKit
│   ├── ASN1.swift             # ASN.1 DER encoder/decoder
│   └── SPNEGO.swift           # SPNEGO token wrapping/parsing
└── Protocol/
    ├── SMB2Constants.swift    # Commands, flags, dialects, capabilities
    ├── SMB2Header.swift       # 64-byte SMB2 header builder/parser
    ├── SMB2Negotiate.swift    # NEGOTIATE request/response
    ├── SMB2Session.swift      # SESSION_SETUP request/response, LOGOFF
    ├── SMB2Tree.swift         # TREE_CONNECT/DISCONNECT
    ├── SMB2Create.swift       # CREATE (open file) request/response
    ├── SMB2Close.swift        # CLOSE request/response
    ├── SMB2Read.swift         # READ request/response
    └── SMB2Query.swift        # QUERY_DIRECTORY, QUERY_INFO
```

## Design Decisions

- **Zero external dependencies.** Only Apple system frameworks (CryptoKit, Network.framework, Foundation).
- **Struct-based I/O.** ByteWriter and ByteReader are value types. Every SMB2 packet is built and parsed with these two structs.
- **Little-endian throughout.** SMB2 is entirely LE on the wire.
- **Pure Swift MD4.** Apple's CryptoKit doesn't include MD4, so we implement RFC 1320 ourselves. HMAC-MD5 uses CryptoKit.
- **Generic ASN.1 codec.** SPNEGO wrapping uses a proper ASN.1 DER encoder/decoder rather than hard-coded byte patterns.
- **One error enum.** SMBError covers all layers with cases declared upfront.

## License

MIT
