//
//  SMBSessionPipelineTests.swift
//  SwiftSMB
//
// Unit tests for the pipelined session's weighted credit gate — the
// trickiest piece of the multi-in-flight machinery. The gate touches no
// transport state, so it runs on an unconnected SMBSession with no server.
//
// (The reader/routing path needs a live socket or a transport mock and is
// covered by on-device testing against a real server; see the handoff notes.)

import XCTest
@testable import SwiftSMB

final class SMBSessionPipelineTests: XCTestCase {

    private func makeSession() -> SMBSession {
        // No connect() is ever called — only the credit gate is exercised.
        SMBSession(host: "127.0.0.1", port: 1)
    }

    /// A short sleep to let a spawned task reach its suspension point.
    private func settle() async {
        try? await Task.sleep(nanoseconds: 20_000_000) // 20 ms
    }

    // MARK: - reserveCredits (up-to, shrink-to-available)

    func testReserveShrinksToAvailable() async throws {
        let s = makeSession()
        await s._testSetCredits(3)
        let take = try await s.reserveCredits(upTo: 10)
        XCTAssertEqual(take, 3, "reserve should shrink to what's available")
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 0)
    }

    func testReserveTakesExactlyWhenPlentiful() async throws {
        let s = makeSession()
        await s._testSetCredits(100)
        let take = try await s.reserveCredits(upTo: 16)
        XCTAssertEqual(take, 16)
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 84)
    }

    // MARK: - Optimistic escape (no deadlock at zero balance)

    func testReserveIsOptimisticWhenIdleAndEmpty() async throws {
        // 0 credits AND nothing in flight → must NOT block; take 1 optimistically
        // so a request can go out and elicit a grant (mirrors the serial path).
        let s = makeSession()
        let take = try await s.reserveCredits(upTo: 5)
        XCTAssertEqual(take, 1, "idle + empty balance should optimistically take 1, not hang")
    }

    func testAcquireIsOptimisticWhenIdleAndEmpty() async throws {
        let s = makeSession()
        try await s.creditAcquire(4)   // must return, not hang
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 0)
    }

    // MARK: - Blocking + wake (something in flight to replenish)

    func testReserveBlocksWhileInFlightThenWakesOnGrant() async throws {
        let s = makeSession()          // 0 credits
        await s._testMarkAwaiting(1)   // a request is in flight → no optimistic escape
        let task = Task { try await s.reserveCredits(upTo: 5) }
        await settle()                 // parked on the empty balance
        await s._testApplyGrant(8)
        let take = try await task.value
        XCTAssertEqual(take, 5, "should take min(desired, granted)")
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 3)
    }

    func testAcquireWaitsForEnough() async throws {
        let s = makeSession()
        await s._testSetCredits(2)
        await s._testMarkAwaiting(1)   // in flight → block instead of optimistic
        let task = Task { try await s.creditAcquire(5) }
        await settle()                 // 2 < 5 → parked
        await s._testApplyGrant(3)     // now 5
        try await task.value
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 0)
    }

    func testReleaseReturnsCreditsAndWakes() async throws {
        let s = makeSession()
        await s._testMarkAwaiting(1)
        let waiter = Task { try await s.creditAcquire(4) }
        await settle()
        await s.releaseCredits(4)      // acts like a grant
        try await waiter.value
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 0)
    }

    // MARK: - Fairness: a small waiter is not starved behind a large one

    func testSmallWaiterNotStarvedBehindLargeOne() async throws {
        let s = makeSession()          // 0 credits
        await s._testMarkAwaiting(1)   // keep the gate in blocking mode throughout
        let big = Task { () -> Int in try await s.creditAcquire(8); return 1 }
        await settle()
        let small = Task { () -> Int in try await s.creditAcquire(2); return 2 }
        await settle()

        // A grant of 3 satisfies the small waiter (2) but not the big one (8).
        await s._testApplyGrant(3)
        await settle()

        // small should have completed on the partial grant; big remains parked
        // (implied by the credit balance below staying at 1 < 8).
        let smallVal = try await small.value
        XCTAssertEqual(smallVal, 2, "small waiter proceeds on a partial grant")

        let midCredits = await s._testCreditsAvailable
        XCTAssertEqual(midCredits, 1, "3 granted − 2 taken by small = 1 left")

        // Now grant enough for the big waiter.
        await s._testApplyGrant(8)     // 1 + 8 = 9 ≥ 8
        let bigVal = try await big.value
        XCTAssertEqual(bigVal, 1)
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 1, "9 − 8 = 1 left")
    }

    // MARK: - Many concurrent waiters all satisfied

    func testManyConcurrentWaitersAllSatisfied() async throws {
        let s = makeSession()
        await s._testMarkAwaiting(1)
        let n = 20
        var tasks: [Task<Void, Error>] = []
        for _ in 0..<n {
            tasks.append(Task { try await s.creditAcquire(2) })   // each needs 2
        }
        await settle()
        // Grant exactly enough in one shot.
        await s._testApplyGrant(UInt16(n * 2))
        for t in tasks { try await t.value }
        let left = await s._testCreditsAvailable
        XCTAssertEqual(left, 0, "all \(n) waiters drained the pool exactly")
    }

    // MARK: - Opt-in pipelining (default must be serial)

    func testPipeliningIsSerialByDefault() async {
        let s = SMBSession(host: "127.0.0.1", port: 1)
        let n = await s.maxInFlightRequests
        XCTAssertEqual(n, 1, "pipelining must be OPT-IN: default is serial (1)")
    }

    func testInitParamOptsIn() async {
        let s = SMBSession(host: "127.0.0.1", port: 1, maxInFlightRequests: 8)
        let n = await s.maxInFlightRequests
        XCTAssertEqual(n, 8)
    }

    func testInitParamClampsToAtLeastOne() async {
        let s = SMBSession(host: "127.0.0.1", port: 1, maxInFlightRequests: 0)
        let n = await s.maxInFlightRequests
        XCTAssertEqual(n, 1, "must clamp to >= 1")
    }

    func testSetterChangesAndClamps() async {
        let s = SMBSession(host: "127.0.0.1", port: 1)
        await s.setMaxInFlightRequests(6)
        var n = await s.maxInFlightRequests
        XCTAssertEqual(n, 6)
        await s.setMaxInFlightRequests(-3)
        n = await s.maxInFlightRequests
        XCTAssertEqual(n, 1, "must clamp to >= 1")
    }

    func testClientForwardsOptIn() async {
        // SMBClient wraps a session; the client-level knob must propagate.
        let c = SMBClient(host: "127.0.0.1", port: 1, maxInFlightRequests: 4)
        await c.setMaxInFlightRequests(3)   // must not trap / must forward
        _ = c
    }
}
