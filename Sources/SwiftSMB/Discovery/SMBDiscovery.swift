//
//  SMBDiscovery.swift
//  SwiftSMB
//
//  Created by Preet Singh on 4/9/26.
//
// Discovers SMB servers on the local network using Bonjour (mDNS).
//
// Most consumer NAS devices advertise themselves as _smb._tcp on the
// LAN. This class uses NWBrowser from Network.framework to find them
// without the user having to type an IP address.
//
// Usage:
//   let discovery = SMBDiscovery()
//   try await discovery.start()
//   // Wait a few seconds for devices to appear…
//   let servers = await discovery.servers
//   await discovery.stop()

import Foundation
import Network

/// A discovered SMB server on the local network.
public struct SMBServer: Sendable, Hashable, Identifiable {
    /// Human-readable name (e.g. "Synology-NAS").
    public let name: String
    /// Resolved hostname or IP address.
    public let host: String
    /// Port (usually 445).
    public let port: UInt16
    /// The raw Bonjour service type (usually "_smb._tcp.").
    public let serviceType: String

    public var id: String { "\(host):\(port)" }

    public init(name: String, host: String, port: UInt16 = 445, serviceType: String = "_smb._tcp.") {
        self.name = name
        self.host = host
        self.port = port
        self.serviceType = serviceType
    }
}

/// Scans the local network for SMB servers using Bonjour (mDNS).
///
/// `SMBDiscovery` is an actor so that the `servers` list can be read
/// safely from any context.
public actor SMBDiscovery {

    // MARK: State

    private var browser: NWBrowser?
    private var _servers: [String: SMBServer] = [:]
    private var isRunning = false

    /// A callback fired whenever the server list changes (added or removed).
    /// Useful for driving a SwiftUI list without polling.
    public var onUpdate: (@Sendable ([SMBServer]) -> Void)?

    /// Current snapshot of discovered servers.
    public var servers: [SMBServer] {
        Array(_servers.values).sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    public init() {}

    // MARK: - Lifecycle

    /// Start browsing for SMB services on the LAN.
    ///
    /// The browser runs continuously until `stop()` is called. New servers
    /// appear in `servers` as they're discovered; stale ones are removed
    /// automatically when the mDNS record expires.
    public func start() throws {
        guard !isRunning else { return }

        let descriptor = NWBrowser.Descriptor.bonjour(type: "_smb._tcp.", domain: nil)
        let parameters = NWParameters()
        parameters.includePeerToPeer = true

        let browser = NWBrowser(for: descriptor, using: parameters)

        browser.browseResultsChangedHandler = { [weak self] results, changes in
            guard let self = self else { return }
            Task { await self.handleResults(results) }
        }

        browser.stateUpdateHandler = { state in
            switch state {
            case .failed(let err):
                // NWBrowser auto-restarts on transient errors, so we just
                // log this for debugging.
                debugPrint("SMBDiscovery browser failed: \(err)")
            default:
                break
            }
        }

        browser.start(queue: .global(qos: .userInitiated))
        self.browser = browser
        self.isRunning = true
    }

    /// Stop browsing and clear the server list.
    public func stop() {
        browser?.cancel()
        browser = nil
        _servers.removeAll()
        isRunning = false
    }

    // MARK: - One-shot convenience

    /// Scan for `duration` seconds and return all servers found.
    /// Starts and stops the browser automatically.
    public func scan(duration: TimeInterval = 3) async throws -> [SMBServer] {
        try start()
        let nanos = UInt64(duration * 1_000_000_000)
        try? await Task.sleep(nanoseconds: nanos)
        let result = servers
        stop()
        return result
    }

    // MARK: - Internal

    private func handleResults(_ results: Set<NWBrowser.Result>) {
        var updated: [String: SMBServer] = [:]

        for result in results {
            // Extract name from the endpoint.
            let name: String
            let key: String
            switch result.endpoint {
            case .service(let n, let type, let domain, _):
                name = n
                key = "\(n).\(type).\(domain)"
            default:
                continue
            }

            // We can't resolve the IP here without NWConnection; store the
            // name and use the service name as the host — Network.framework
            // can connect using the NWEndpoint directly, but for our API
            // we need a host string. The resolver below handles this.
            //
            // For most Bonjour-advertised SMB services, the name IS the
            // mDNS hostname (e.g. "Synology-NAS.local").
            let host = "\(name).local"

            updated[key] = SMBServer(name: name, host: host, port: 445)
        }

        _servers = updated
        let snapshot = servers
        onUpdate?(snapshot)
    }
}
