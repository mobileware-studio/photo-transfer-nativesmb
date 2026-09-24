import Foundation
import Darwin

/// A minimal SMB2 server on loopback, on the same port for 127.0.0.1 and ::1, so `localhost`
/// (both families, from /etc/hosts) gives `SMBTransport` two addresses of one server. It answers
/// NEGOTIATE with dialect 2.0.2 (or rejects it), then handles SESSION_SETUP as `mode` says, and
/// counts every NEGOTIATE and SESSION_SETUP it receives on either address.
final class FakeSMBServer: @unchecked Sendable {
    enum Mode {
        /// Answer SESSION_SETUP with this NT error status.
        case reject(UInt32)
        /// Close the connection when SESSION_SETUP arrives, without answering.
        case drop
        /// Answer NEGOTIATE with this NT error status.
        case rejectNegotiate(UInt32)
    }

    let port: Int
    private let mode: Mode
    private let listeners: [Int32]
    private let lock = NSLock()
    private let threads = DispatchGroup()
    private var negotiations = 0
    private var setups = 0
    private var running = true

    var negotiates: Int { lock.lock(); defer { lock.unlock() }; return negotiations }
    var sessionSetups: Int { lock.lock(); defer { lock.unlock() }; return setups }

    init(mode: Mode) throws {
        self.mode = mode
        var bound: (port: Int, listeners: [Int32])?
        for _ in 0..<20 where bound == nil {
            bound = Self.bindBothFamilies()
        }
        guard let bound else { throw POSIXError(.EADDRINUSE) }
        port = bound.port
        listeners = bound.listeners
        for listener in listeners {
            threads.enter()
            Thread.detachNewThread { [self] in acceptLoop(listener); threads.leave() }
        }
    }

    /// Stops both accept loops. Closing a listener does not reliably wake a thread blocked in
    /// accept() on Darwin, so connect once to each address first; the loops then see `running`
    /// is false and return. The listeners close only after both threads have exited, so no
    /// accept() can run on a closed or reused descriptor.
    func stop() {
        lock.lock(); running = false; lock.unlock()
        for (family, host) in [(AF_INET, "127.0.0.1"), (AF_INET6, "::1")] {
            let waker = socket(family, SOCK_STREAM, 0)
            if family == AF_INET {
                var address = ipv4(host); address.sin_port = UInt16(port).bigEndian
                _ = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(waker, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            } else {
                var address = ipv6(host); address.sin6_port = UInt16(port).bigEndian
                _ = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(waker, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
            }
            Darwin.close(waker)
        }
        _ = threads.wait(timeout: .now() + 5)
        listeners.forEach { Darwin.close($0) }
    }

    private var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return running }

    /// Binds 127.0.0.1 on a free port, then ::1 on the same port; nil if that port is taken on IPv6.
    private static func bindBothFamilies() -> (port: Int, listeners: [Int32])? {
        let v4 = socket(AF_INET, SOCK_STREAM, 0)
        var address4 = ipv4("127.0.0.1")
        var length4 = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound4 = withUnsafeMutablePointer(to: &address4) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(v4, $0, length4) == 0 && getsockname(v4, $0, &length4) == 0 }
        }
        guard v4 >= 0, bound4, listen(v4, 8) == 0 else { Darwin.close(v4); return nil }
        let port = UInt16(bigEndian: address4.sin_port)

        let v6 = socket(AF_INET6, SOCK_STREAM, 0)
        var only: Int32 = 1
        setsockopt(v6, IPPROTO_IPV6, IPV6_V6ONLY, &only, socklen_t(MemoryLayout<Int32>.size))
        var address6 = ipv6("::1")
        address6.sin6_port = port.bigEndian
        let bound6 = withUnsafePointer(to: &address6) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(v6, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) == 0 }
        }
        guard v6 >= 0, bound6, listen(v6, 8) == 0 else { Darwin.close(v4); Darwin.close(v6); return nil }
        return (Int(port), [v4, v6])
    }

    private func acceptLoop(_ listener: Int32) {
        while isRunning {
            let client = accept(listener, nil, nil)
            guard client >= 0 else { return }
            serve(client)
            Darwin.close(client)
        }
    }

    private func serve(_ client: Int32) {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        // A reply to a client that already hung up must not raise SIGPIPE and end the test run.
        var noSignal: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        while let packet = readFrame(client) {
            guard packet.count >= 64, packet.starts(with: [0xFE, 0x53, 0x4D, 0x42]) else { return }
            let command = UInt16(packet[12]) | UInt16(packet[13]) << 8
            let messageID = (0..<8).reduce(UInt64(0)) { $0 | UInt64(packet[24 + $1]) << (8 * UInt64($1)) }
            switch command {
            case 0: // NEGOTIATE
                lock.lock(); negotiations += 1; lock.unlock()
                if case .rejectNegotiate(let status) = mode {
                    send(client, header(command: 0, status: status, messageID: messageID, session: 0) + errorBody())
                    continue
                }
                var body = Data()
                body.appendLE(UInt16(65)); body.appendLE(UInt16(1)); body.appendLE(UInt16(0x0202)); body.appendLE(UInt16(0))
                body.append(Data(repeating: 0x47, count: 16))                   // server GUID
                body.appendLE(UInt32(0))                                          // capabilities
                body.appendLE(UInt32(65_536)); body.appendLE(UInt32(65_536)); body.appendLE(UInt32(65_536))
                body.appendLE(UInt64(0)); body.appendLE(UInt64(0))              // system and start time
                body.appendLE(UInt16(128)); body.appendLE(UInt16(0))             // no security buffer
                body.appendLE(UInt32(0))
                body.append(0)
                send(client, header(command: 0, status: 0, messageID: messageID, session: 0) + body)
            case 1: // SESSION_SETUP
                lock.lock(); setups += 1; lock.unlock()
                switch mode {
                case .drop:
                    return
                case .reject(let status):
                    send(client, header(command: 1, status: status, messageID: messageID, session: 0x1234) + errorBody())
                case .rejectNegotiate:
                    return
                }
            default:
                return
            }
        }
    }

    /// SMB2 ERROR response body.
    private func errorBody() -> Data {
        var body = Data()
        body.appendLE(UInt16(9)); body.append(0); body.append(0); body.appendLE(UInt32(0)); body.append(0)
        return body
    }

    private func header(command: UInt16, status: UInt32, messageID: UInt64, session: UInt64) -> Data {
        var header = Data([0xFE, 0x53, 0x4D, 0x42])
        header.appendLE(UInt16(64)); header.appendLE(UInt16(0)); header.appendLE(status)
        header.appendLE(command); header.appendLE(UInt16(1))
        header.appendLE(UInt32(1))                                               // server to redirector
        header.appendLE(UInt32(0)); header.appendLE(messageID)
        header.appendLE(UInt32(0xFEFF)); header.appendLE(UInt32(0))
        header.appendLE(session)
        header.append(Data(repeating: 0, count: 16))                              // no signature
        return header
    }

    /// Reads one NetBIOS-framed packet; nil when the peer closes, times out or sends too little.
    private func readFrame(_ client: Int32) -> Data? {
        guard let prefix = readExactly(client, 4) else { return nil }
        let length = Int(prefix[1]) << 16 | Int(prefix[2]) << 8 | Int(prefix[3])
        return readExactly(client, length)
    }

    private func readExactly(_ client: Int32, _ count: Int) -> Data? {
        var data = Data(count: count)
        var received = 0
        while received < count {
            let n = data.withUnsafeMutableBytes { recv(client, $0.baseAddress! + received, count - received, 0) }
            guard n > 0 else { return nil }
            received += n
        }
        return data
    }

    private func send(_ client: Int32, _ packet: Data) {
        var frame = Data([0, UInt8(packet.count >> 16 & 0xFF), UInt8(packet.count >> 8 & 0xFF), UInt8(packet.count & 0xFF)])
        frame.append(packet)
        _ = frame.withUnsafeBytes { Darwin.send(client, $0.baseAddress, frame.count, 0) }
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
}
