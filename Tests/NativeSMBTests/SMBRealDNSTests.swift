import Foundation
import Darwin
import Testing
import NativeSMB

/// The system resolver end to end, through the public API only (so these also run against older
/// NativeSMB revisions). Needs network access for nip.io; every connection goes to a closed
/// loopback port, so no SMB server is contacted. Opt in: NATIVESMB_REAL_DNS=1 swift test
@Suite("SMB name resolution against the system resolver (issue #246)", .serialized,
       .enabled(if: ProcessInfo.processInfo.environment["NATIVESMB_REAL_DNS"] == "1", "set NATIVESMB_REAL_DNS=1"))
struct SMBRealDNSTests {
    @Test("a name with only an A record connects without waiting for AAAA")
    func ipv4OnlyName() {
        let port = closedLoopbackPort()
        let result = measure { _ = try SMBTransport(connection: connection(host: "127.0.0.1.nip.io", port: port), share: "Photos", cancelled: { false }) }
        #expect(result.seconds < 2, "took \(result.seconds) s")
        #expect(result.failure as? SMBFailure == .port, "failed as \(String(describing: result.failure))")
    }

    @Test("a name that does not exist fails promptly as .host")
    func missingName() {
        let result = measure { _ = try SMBTransport(connection: connection(host: "pt-qa-nonexistent.invalid", port: 445), share: "Photos", cancelled: { false }) }
        #expect(result.seconds < 2, "took \(result.seconds) s")
        #expect(result.failure as? SMBFailure == .host, "failed as \(String(describing: result.failure))")
    }

    @Test("an unanswered .local name gives up after the 5 s resolution limit, as .host")
    func unansweredLocalName() {
        let host = "pt-qa-\(UUID().uuidString.prefix(8)).local"
        let result = measure { _ = try SMBTransport(connection: connection(host: host, port: 445), share: "Photos", cancelled: { false }) }
        #expect(result.seconds >= 4.5 && result.seconds < 8, "took \(result.seconds) s")
        #expect(result.failure as? SMBFailure == .host, "failed as \(String(describing: result.failure))")
    }

    @Test("localhost resolves both families and a refused port is still .port")
    func localhost() {
        let port = closedLoopbackPort()
        let result = measure { _ = try SMBTransport(connection: connection(host: "localhost", port: port), share: "Photos", cancelled: { false }) }
        #expect(result.seconds < 2, "took \(result.seconds) s")
        #expect(result.failure as? SMBFailure == .port, "failed as \(String(describing: result.failure))")
    }
}
