import Foundation
import Darwin
import Testing
@testable import NativeSMB

/// Real libsmb2 connects to loopback sockets; no network or SMB server is involved.
@Suite("SMB connect failures", .serialized)
struct SMBConnectFailureTests {
    @Test("a refused IPv4 port fails at once as .port, not as a generic connection error")
    func refusedIPv4() {
        let port = closedLoopbackPort()
        let result = measure { _ = try SMBTransport(connection: connection(host: "127.0.0.1", port: port), share: "Photos", timeout: 5, cancelled: { false }) }
        #expect(result.failure as? SMBFailure == .port, "failed as \(String(describing: result.failure))")
        #expect(result.seconds < 2, "took \(result.seconds) s")
    }

    @Test("a refused IPv6 port fails at once as .port")
    func refusedIPv6() {
        let port = closedLoopbackPort(family: AF_INET6)
        let result = measure { _ = try SMBTransport(connection: connection(host: "::1", port: port), share: "Photos", timeout: 5, cancelled: { false }) }
        #expect(result.failure as? SMBFailure == .port, "failed as \(String(describing: result.failure))")
        #expect(result.seconds < 2, "took \(result.seconds) s")
    }

    @Test("a server that accepts and then drops the connection is not reported as a closed port")
    func droppedAfterAccept() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        try #require(listener >= 0)
        defer { close(listener) }
        var address = ipv4("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, length) == 0 && getsockname(listener, $0, &length) == 0 }
        }
        try #require(bound && listen(listener, 1) == 0)
        _ = fcntl(listener, F_SETFL, fcntl(listener, F_GETFL) | O_NONBLOCK)
        // The event loop samples `cancelled` between polls: accept there and hang up at once,
        // after the TCP connect has succeeded and the NEGOTIATE request is in flight.
        var dropped = false
        let result = measure {
            _ = try SMBTransport(connection: connection(host: "127.0.0.1", port: Int(UInt16(bigEndian: address.sin_port))),
                                 share: "Photos", timeout: 5, cancelled: {
                if !dropped {
                    let accepted = accept(listener, nil, nil)
                    if accepted >= 0 { close(accepted); dropped = true }
                }
                return false
            })
        }
        #expect(dropped)
        #expect(result.failure as? SMBFailure == .connection, "failed as \(String(describing: result.failure))")
        #expect(result.seconds < 3, "took \(result.seconds) s")
    }
}
