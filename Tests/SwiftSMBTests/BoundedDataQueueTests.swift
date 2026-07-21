//
//  BoundedDataQueueTests.swift
//  SwiftSMB
//
// Unit tests for the BoundedDataQueue that backs the streaming proxy's
// read-ahead producer/consumer pipeline. These are pure Swift-concurrency
// tests — no SMB server or socket required.

import XCTest
@testable import SwiftSMB

final class BoundedDataQueueTests: XCTestCase {

    /// One-byte payload carrying `n` (low 8 bits), for easy identity checks.
    private func byte(_ n: Int) -> Data { Data([UInt8(n & 0xFF)]) }

    /// Two-byte little-endian payload so tests can distinguish >255 values.
    private func word(_ n: Int) -> Data {
        Data([UInt8(n & 0xFF), UInt8((n >> 8) & 0xFF)])
    }
    private func value(_ d: Data) -> Int { Int(d[d.startIndex]) | (Int(d[d.startIndex + 1]) << 8) }

    // MARK: - Ordering

    func testFIFOOrdering() async {
        let q = BoundedDataQueue(capacity: 8)
        for i in 0..<5 { await q.enqueue(byte(i)) }
        await q.finish()

        var got: [UInt8] = []
        while let s = await q.dequeue() { got.append(s[s.startIndex]) }
        XCTAssertEqual(got, [0, 1, 2, 3, 4])
    }

    // MARK: - finish() semantics

    func testDrainsBufferedItemsAfterFinish() async {
        // finish() must not discard items already in the buffer.
        let q = BoundedDataQueue(capacity: 4)
        await q.enqueue(byte(1))
        await q.enqueue(byte(2))
        await q.finish()

        let a = await q.dequeue()
        let b = await q.dequeue()
        let c = await q.dequeue()
        XCTAssertEqual(a?[a!.startIndex], 1)
        XCTAssertEqual(b?[b!.startIndex], 2)
        XCTAssertNil(c)
    }

    func testEnqueueAfterFinishReturnsFalse() async {
        let q = BoundedDataQueue(capacity: 2)
        await q.finish()

        let accepted = await q.enqueue(byte(9))
        XCTAssertFalse(accepted, "enqueue after finish should report the queue is closed")
        let out = await q.dequeue()
        XCTAssertNil(out)
    }

    func testFinishIsIdempotent() async {
        let q = BoundedDataQueue(capacity: 2)
        await q.enqueue(byte(1))
        await q.finish()
        await q.finish()   // must not crash or lose the buffered item
        let a = await q.dequeue()
        let b = await q.dequeue()
        XCTAssertEqual(a?[a!.startIndex], 1)
        XCTAssertNil(b)
    }

    // MARK: - Back-pressure

    func testBackpressureDeliversAllItemsInOrder() async {
        // Capacity is far smaller than the item count, so the producer must
        // repeatedly park on a full queue and resume as the consumer drains.
        let q = BoundedDataQueue(capacity: 2)
        let n = 500

        let producer = Task {
            for i in 0..<n {
                let ok = await q.enqueue(self.word(i))
                XCTAssertTrue(ok)
            }
            await q.finish()
        }

        var received: [Int] = []
        while let s = await q.dequeue() { received.append(self.value(s)) }
        _ = await producer.value

        XCTAssertEqual(received, Array(0..<n))
    }

    func testConsumerBlocksUntilProducerEnqueues() async {
        // Consumer starts on an empty queue and must suspend until items arrive.
        let q = BoundedDataQueue(capacity: 4)

        let consumer = Task { () -> [UInt8] in
            var out: [UInt8] = []
            while let s = await q.dequeue() { out.append(s[s.startIndex]) }
            return out
        }

        // Let the consumer park on the empty queue before we produce anything.
        try? await Task.sleep(nanoseconds: 10_000_000)

        await q.enqueue(byte(7))
        await q.enqueue(byte(8))
        await q.finish()

        let out = await consumer.value
        XCTAssertEqual(out, [7, 8])
    }
}
