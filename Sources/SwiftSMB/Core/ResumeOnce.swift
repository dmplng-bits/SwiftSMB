//
//  ResumeOnce.swift
//  SwiftSMB
//
// A tiny reference-type latch used to guarantee `continuation.resume(...)`
// is called exactly once, even when the underlying callback (e.g.
// `NWConnection.stateUpdateHandler`, `NWListener.stateUpdateHandler`)
// fires multiple times or from multiple transitions.
//
// We need a reference type (rather than a local `var` in the closure)
// because Swift 6 forbids capturing a mutable stack variable from a
// `@Sendable` closure — the closure is dispatched on a Network.framework
// queue, which lives outside the actor's isolation domain.
//
// Thread safety: the Network.framework state-update callbacks for a single
// endpoint are serialized on the queue we hand them, so in practice we
// never race. We still use `NSLock` to satisfy `Sendable` and to stay
// safe if callers ever decide to share an instance across queues.

import Foundation

/// Single-shot latch for `withCheckedThrowingContinuation` bridges.
///
/// Call `fire()` once per attempt to resume. The first call returns
/// `true` (meaning "it's your turn — resume the continuation now").
/// Every subsequent call returns `false`.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    /// Returns true the first time it's called, false every time after.
    func fire() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if fired { return false }
        fired = true
        return true
    }
}
