import Foundation
import Testing
@testable import NativeSMB

/// Real libsmb2 against a fake SMB2 server on loopback (#249). `localhost` resolves to ::1 and
/// 127.0.0.1 from /etc/hosts, so the server has two addresses, as a dual-stack NAS name does.
@Suite("SMB login failures", .serialized)
struct SMBLoginFailureTests {
    @Test("a rejected login fails at once as .authentication and reaches the server only once",
          arguments: [UInt32(0xC000006D), 0xC000006A, 0xC0000072, 0xC0000234])
    func rejectedLogin(status: UInt32) throws {
        try requireTwoLocalhostAddresses()
        let server = try FakeSMBServer(mode: .reject(status))
        defer { server.stop() }
        let result = measure { _ = try connectToLocalhost(port: server.port) }
        #expect(result.failure as? SMBFailure == .authentication,
                "status 0x\(String(status, radix: 16)) failed as \(String(describing: result.failure))")
        #expect(server.sessionSetups == 1, "the credentials reached the server \(server.sessionSetups) times")
        #expect(result.seconds < 2, "took \(result.seconds) s")
    }

    @Test("a server error that is not a login rejection still falls back to the next address",
          arguments: [UInt32(0xC000009A), 0xC0000022]) // INSUFFICIENT_RESOURCES, ACCESS_DENIED
    func otherServerStatus(status: UInt32) throws {
        try requireTwoLocalhostAddresses()
        let server = try FakeSMBServer(mode: .reject(status))
        defer { server.stop() }
        let result = measure { _ = try connectToLocalhost(port: server.port) }
        #expect(result.failure as? SMBFailure == .connection,
                "status 0x\(String(status, radix: 16)) failed as \(String(describing: result.failure))")
        #expect(server.sessionSetups == 2, "expected one attempt per address, got \(server.sessionSetups)")
    }

    @Test("a login status in a NEGOTIATE rejection is not a login rejection: the next address is tried")
    func rejectedNegotiate() throws {
        try requireTwoLocalhostAddresses()
        let server = try FakeSMBServer(mode: .rejectNegotiate(0xC000006D))
        defer { server.stop() }
        let result = measure { _ = try connectToLocalhost(port: server.port) }
        #expect(result.failure as? SMBFailure == .connection, "failed as \(String(describing: result.failure))")
        #expect(server.negotiates == 2, "expected one NEGOTIATE per address, got \(server.negotiates)")
        #expect(server.sessionSetups == 0)
    }

    @Test("a connection dropped during the handshake, with no status, still falls back to the next address")
    func droppedDuringHandshake() throws {
        try requireTwoLocalhostAddresses()
        let server = try FakeSMBServer(mode: .drop)
        defer { server.stop() }
        let result = measure { _ = try connectToLocalhost(port: server.port) }
        #expect(result.failure as? SMBFailure == .connection, "failed as \(String(describing: result.failure))")
        #expect(server.sessionSetups == 2, "expected one attempt per address, got \(server.sessionSetups)")
        #expect(result.seconds < 3, "took \(result.seconds) s")
    }

    private func connectToLocalhost(port: Int) throws -> SMBTransport {
        try SMBTransport(connection: connection(host: "localhost", port: port), share: "Photos", timeout: 5, cancelled: { false })
    }

    /// These tests count attempts per address, so a `localhost` with a single address would make
    /// "reached the server once" pass for the wrong reason.
    private func requireTwoLocalhostAddresses() throws {
        let addresses = try SMBTransport.resolve("localhost", timeout: 5, cancelled: { false })
        try #require(Set(addresses) == ["::1", "127.0.0.1"], "localhost resolved to \(addresses)")
    }
}
