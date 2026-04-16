//
//  SMB2Constants.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/8/26.
//
// SMB2 protocol constants — commands, flags, dialects, capabilities,
// access masks, file attributes, share types, and info classes.
//
// References:
//   [MS-SMB2] §2.2  — Message Syntax
//   [MS-SMB2] §3.3  — Server Processing

import Foundation

// MARK: - Protocol ID

/// The 4-byte magic at the start of every SMB2 packet: 0xFE 'S' 'M' 'B'.
public let smb2ProtocolId: UInt32 = 0x424D53FE

// MARK: - Header

/// Every SMB2 header is exactly 64 bytes.
public let smb2HeaderSize: Int = 64

/// SMB2 header structure size field is always 64.
public let smb2HeaderStructureSize: UInt16 = 64

// MARK: - Commands ([MS-SMB2] §2.2.1)

public enum SMB2Command {
    public static let negotiate:      UInt16 = 0x0000
    public static let sessionSetup:   UInt16 = 0x0001
    public static let logoff:         UInt16 = 0x0002
    public static let treeConnect:    UInt16 = 0x0003
    public static let treeDisconnect: UInt16 = 0x0004
    public static let create:         UInt16 = 0x0005
    public static let close:          UInt16 = 0x0006
    public static let flush:          UInt16 = 0x0007
    public static let read:           UInt16 = 0x0008
    public static let write:          UInt16 = 0x0009
    public static let lock:           UInt16 = 0x000A
    public static let ioctl:          UInt16 = 0x000B
    public static let cancel:         UInt16 = 0x000C
    public static let echo:           UInt16 = 0x000D
    public static let queryDirectory:  UInt16 = 0x000E
    public static let changeNotify:   UInt16 = 0x000F
    public static let queryInfo:      UInt16 = 0x0010
    public static let setInfo:        UInt16 = 0x0011
    public static let oplockBreak:    UInt16 = 0x0012
}

// MARK: - Header Flags ([MS-SMB2] §2.2.1.1)

public enum SMB2Flags {
    /// This packet is a response (server → client).
    public static let serverToRedir: UInt32 = 0x0000_0001
    /// Async command — uses AsyncId instead of TreeId.
    public static let asyncCommand:  UInt32 = 0x0000_0002
    /// Packet is related to a compounded request chain.
    public static let related:       UInt32 = 0x0000_0004
    /// Packet is signed.
    public static let signed:        UInt32 = 0x0000_0008
    /// DFS operation.
    public static let dfsOperation:  UInt32 = 0x1000_0000
    /// Replay operation.
    public static let replayOperation: UInt32 = 0x2000_0000
}

// MARK: - Dialects ([MS-SMB2] §2.2.3)

public enum SMB2Dialect {
    public static let smb202: UInt16 = 0x0202
    public static let smb210: UInt16 = 0x0210
    public static let smb300: UInt16 = 0x0300
    public static let smb302: UInt16 = 0x0302
    public static let smb311: UInt16 = 0x0311
    /// Wildcard — used in multi-protocol negotiate.
    public static let wildcard: UInt16 = 0x02FF
}

// MARK: - Capabilities ([MS-SMB2] §2.2.3)

public enum SMB2Capabilities {
    public static let dfs:                UInt32 = 0x0000_0001
    public static let leasing:            UInt32 = 0x0000_0002
    public static let largeMTU:           UInt32 = 0x0000_0004
    public static let multiChannel:       UInt32 = 0x0000_0008
    public static let persistentHandles:  UInt32 = 0x0000_0010
    public static let directoryLeasing:   UInt32 = 0x0000_0020
    public static let encryption:         UInt32 = 0x0000_0040
}

// MARK: - Security Mode ([MS-SMB2] §2.2.3)

public enum SMB2SecurityMode {
    public static let signingEnabled:  UInt16 = 0x0001
    public static let signingRequired: UInt16 = 0x0002
}

// MARK: - Session Flags ([MS-SMB2] §2.2.6)

public enum SMB2SessionFlags {
    public static let isGuest:     UInt16 = 0x0001
    public static let isNull:      UInt16 = 0x0002
    public static let encryptData: UInt16 = 0x0004
}

// MARK: - Share Type ([MS-SMB2] §2.2.10)

public enum SMB2ShareType {
    public static let disk:  UInt8 = 0x01
    public static let pipe:  UInt8 = 0x02
    public static let print: UInt8 = 0x03
}

// MARK: - Share Flags ([MS-SMB2] §2.2.10)

public enum SMB2ShareFlags {
    public static let manualCaching:    UInt32 = 0x0000_0000
    public static let autoCaching:      UInt32 = 0x0000_0010
    public static let vdoCaching:       UInt32 = 0x0000_0020
    public static let noCaching:        UInt32 = 0x0000_0030
    public static let dfs:              UInt32 = 0x0000_0001
    public static let dfsRoot:          UInt32 = 0x0000_0002
    public static let encryptData:      UInt32 = 0x0000_0008
}

// MARK: - Share Capabilities ([MS-SMB2] §2.2.10)

public enum SMB2ShareCapabilities {
    public static let dfs:                   UInt32 = 0x0000_0008
    public static let continuousAvailability: UInt32 = 0x0000_0010
    public static let scaleout:              UInt32 = 0x0000_0020
    public static let cluster:               UInt32 = 0x0000_0040
    public static let asymmetric:            UInt32 = 0x0000_0080
}

// MARK: - Access Mask ([MS-SMB2] §2.2.13.1)

public enum SMB2AccessMask {
    // File-specific
    public static let fileReadData:        UInt32 = 0x0000_0001
    public static let fileWriteData:       UInt32 = 0x0000_0002
    public static let fileAppendData:      UInt32 = 0x0000_0004
    public static let fileReadEA:          UInt32 = 0x0000_0008
    public static let fileWriteEA:         UInt32 = 0x0000_0010
    public static let fileExecute:         UInt32 = 0x0000_0020
    public static let fileDeleteChild:     UInt32 = 0x0000_0040
    public static let fileReadAttributes:  UInt32 = 0x0000_0080
    public static let fileWriteAttributes: UInt32 = 0x0000_0100

    // Standard
    public static let delete:              UInt32 = 0x0001_0000
    public static let readControl:         UInt32 = 0x0002_0000
    public static let writeDac:            UInt32 = 0x0004_0000
    public static let writeOwner:          UInt32 = 0x0008_0000
    public static let synchronize:         UInt32 = 0x0010_0000

    // Generic
    public static let genericRead:         UInt32 = 0x8000_0000
    public static let genericWrite:        UInt32 = 0x4000_0000
    public static let genericExecute:      UInt32 = 0x2000_0000
    public static let genericAll:          UInt32 = 0x1000_0000
    public static let maximumAllowed:      UInt32 = 0x0200_0000
}

// MARK: - File Attributes ([MS-FSCC] §2.6)

public enum SMB2FileAttributes {
    public static let readonly:           UInt32 = 0x0000_0001
    public static let hidden:             UInt32 = 0x0000_0002
    public static let system:             UInt32 = 0x0000_0004
    public static let directory:          UInt32 = 0x0000_0010
    public static let archive:            UInt32 = 0x0000_0020
    public static let normal:             UInt32 = 0x0000_0080
    public static let temporary:          UInt32 = 0x0000_0100
    public static let sparseFile:         UInt32 = 0x0000_0200
    public static let reparsePoint:       UInt32 = 0x0000_0400
    public static let compressed:         UInt32 = 0x0000_0800
    public static let offline:            UInt32 = 0x0000_1000
    public static let notContentIndexed:  UInt32 = 0x0000_2000
    public static let encrypted:          UInt32 = 0x0000_4000
}

// MARK: - Create Disposition ([MS-SMB2] §2.2.13)

public enum SMB2CreateDisposition {
    public static let supersede:    UInt32 = 0x0000_0000
    public static let open:         UInt32 = 0x0000_0001
    public static let create:       UInt32 = 0x0000_0002
    public static let openIf:       UInt32 = 0x0000_0003
    public static let overwrite:    UInt32 = 0x0000_0004
    public static let overwriteIf:  UInt32 = 0x0000_0005
}

// MARK: - Create Options ([MS-SMB2] §2.2.13)

public enum SMB2CreateOptions {
    public static let directoryFile:          UInt32 = 0x0000_0001
    public static let writeThrough:           UInt32 = 0x0000_0002
    public static let sequentialOnly:         UInt32 = 0x0000_0004
    public static let noIntermediateBuffering: UInt32 = 0x0000_0008
    public static let nonDirectoryFile:       UInt32 = 0x0000_0040
    public static let noEaKnowledge:          UInt32 = 0x0000_0200
    public static let randomAccess:           UInt32 = 0x0000_0800
    public static let deleteOnClose:          UInt32 = 0x0000_1000
    public static let openByFileId:           UInt32 = 0x0000_2000
}

// MARK: - Share Access ([MS-SMB2] §2.2.13)

public enum SMB2ShareAccess {
    public static let read:   UInt32 = 0x0000_0001
    public static let write:  UInt32 = 0x0000_0002
    public static let delete: UInt32 = 0x0000_0004
}

// MARK: - Close Flags ([MS-SMB2] §2.2.15)

public enum SMB2CloseFlags {
    public static let postQueryAttributes: UInt16 = 0x0001
}

// MARK: - Query Directory Info Level ([MS-SMB2] §2.2.33)

public enum SMB2FileInfoClass {
    public static let fileDirectoryInformation:     UInt8 = 0x01
    public static let fileFullDirectoryInformation: UInt8 = 0x02
    public static let fileBothDirectoryInformation: UInt8 = 0x03
    public static let fileIdBothDirectoryInformation: UInt8 = 0x25
    public static let fileIdFullDirectoryInformation: UInt8 = 0x26
}

// MARK: - Query Info Type ([MS-SMB2] §2.2.37)

public enum SMB2InfoType {
    public static let file:       UInt8 = 0x01
    public static let fileSystem: UInt8 = 0x02
    public static let security:   UInt8 = 0x03
    public static let quota:      UInt8 = 0x04
}

// MARK: - File Information Class (for QUERY_INFO) ([MS-FSCC])

public enum SMB2FileInformationClass {
    public static let fileBasicInformation:      UInt8 = 0x04
    public static let fileStandardInformation:   UInt8 = 0x05
    public static let fileInternalInformation:   UInt8 = 0x06
    public static let fileEaInformation:         UInt8 = 0x07
    public static let fileAccessInformation:     UInt8 = 0x08
    public static let fileRenameInformation:     UInt8 = 0x0A
    public static let fileDispositionInformation: UInt8 = 0x0D
    public static let filePositionInformation:   UInt8 = 0x0E
    public static let fileAllInformation:        UInt8 = 0x12
    public static let fileNetworkOpenInformation: UInt8 = 0x22
    public static let fileStreamInformation:     UInt8 = 0x16
}

// MARK: - Oplock Levels ([MS-SMB2] §2.2.13)

public enum SMB2OplockLevel {
    public static let none:      UInt8 = 0x00
    public static let levelII:   UInt8 = 0x01  // shared read cache
    public static let exclusive: UInt8 = 0x08  // exclusive cache
    public static let batch:     UInt8 = 0x09  // batch (read+write+handle)
    public static let lease:     UInt8 = 0xFF  // use lease instead
}

// MARK: - Lease State ([MS-SMB2] §2.2.13.2.8)

public enum SMB2LeaseState {
    public static let none:          UInt32 = 0x00
    public static let readCaching:   UInt32 = 0x01  // R — cache reads locally
    public static let handleCaching: UInt32 = 0x02  // H — cache handle opens
    public static let writeCaching:  UInt32 = 0x04  // W — cache writes locally

    /// RH lease — good for media browsing (cache reads + handle across navigations)
    public static let readHandle:    UInt32 = 0x03
    /// RWH lease — full cache, only granted if no other clients have the file open
    public static let readWriteHandle: UInt32 = 0x07
}

// MARK: - NT Status codes (commonly seen)

public enum NTStatus {
    public static let success:                UInt32 = 0x0000_0000
    public static let moreProcessingRequired: UInt32 = 0xC000_0016
    public static let invalidParameter:       UInt32 = 0xC000_000D
    public static let noSuchFile:             UInt32 = 0xC000_000F
    public static let endOfFile:              UInt32 = 0xC000_0011
    public static let accessDenied:           UInt32 = 0xC000_0022
    public static let objectNameNotFound:     UInt32 = 0xC000_0034
    public static let objectNameCollision:    UInt32 = 0xC000_0035
    public static let objectPathNotFound:     UInt32 = 0xC000_003A
    public static let sharingViolation:       UInt32 = 0xC000_0043
    public static let noSuchUser:             UInt32 = 0xC000_0064
    public static let wrongPassword:          UInt32 = 0xC000_006A
    public static let logonFailure:           UInt32 = 0xC000_006D
    public static let accountRestriction:     UInt32 = 0xC000_006E
    public static let accountDisabled:        UInt32 = 0xC000_0072
    public static let passwordExpired:        UInt32 = 0xC000_0071
    public static let badNetworkName:         UInt32 = 0xC000_00CC
    public static let notSupported:           UInt32 = 0xC000_00BB
    public static let userSessionDeleted:     UInt32 = 0xC000_00E7
    public static let directoryNotEmpty:      UInt32 = 0xC000_0101
    public static let insufficientResources:  UInt32 = 0xC000_009A
    public static let cancelled:              UInt32 = 0xC000_0120
    public static let notFound:               UInt32 = 0xC000_0225
    public static let noMoreFiles:            UInt32 = 0x8000_0006
    public static let bufferOverflow:         UInt32 = 0x8000_0005
}
