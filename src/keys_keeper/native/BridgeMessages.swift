import Foundation

enum BridgeFramingError: Error {
    case oversizedMessage
    case undeliveredMessages
}

/// Bounds closures waiting for the main thread, including small-message floods.
final class BridgeMessageDeliveryBudget {
    private let slots = DispatchSemaphore(value: 4)

    func reserve() throws {
        guard slots.wait(timeout: .now()) == .success else {
            throw BridgeFramingError.undeliveredMessages
        }
    }

    func complete() { slots.signal() }
}

/// Bounded JSONL framing for the companion's private stdout pipe.
/// A chunk can contain many small messages; only the unfinished line is kept.
struct BridgeMessageFramer {
    let maxMessageBytes: Int
    private(set) var buffered = Data()

    init(maxMessageBytes: Int = 64 * 1024) {
        precondition(maxMessageBytes > 0)
        self.maxMessageBytes = maxMessageBytes
    }

    mutating func append(_ data: Data, emit: (Data) throws -> Void) throws {
        for byte in data {
            if byte == 10 {
                try emit(buffered)
                buffered.removeAll(keepingCapacity: true)
            } else {
                guard buffered.count < maxMessageBytes else {
                    buffered.removeAll(keepingCapacity: false)
                    throw BridgeFramingError.oversizedMessage
                }
                buffered.append(byte)
            }
        }
    }
}
