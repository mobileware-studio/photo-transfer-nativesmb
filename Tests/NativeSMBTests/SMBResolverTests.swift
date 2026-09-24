import Foundation
import Darwin
import CSMB
import Testing
@testable import NativeSMB

/// `SMBTransport.resolve` against scripted dns_sd queries. The grace period and limits are
/// stretched to seconds so that "waited" and "did not wait" differ by far more than scheduling noise.
@Suite("SMB name resolver (issue #246)", .serialized)
struct SMBResolverTests {
    private func resolve(_ resolver: ScriptedResolver, host: String = "nas.example", timeout: TimeInterval = 20,
                         limit: TimeInterval = 10, grace: TimeInterval = 2,
                         cancelled: () -> Bool = { false }) -> (addresses: [String]?, failure: Error?, seconds: Double) {
        var addresses: [String]?
        let result = measure {
            addresses = try SMBTransport.resolve(host, timeout: timeout, cancelled: cancelled, limit: limit, grace: grace,
                                                 start: resolver.start)
        }
        return (addresses, result.failure, result.seconds)
    }

    @Test("asks dns_sd for negative answers, one query per family")
    func requestsNegativeAnswers() {
        let resolver = ScriptedResolver(ipv4: [.now(.address("192.0.2.10"))], ipv6: [.now(.none)])
        _ = resolve(resolver, host: "DiskStation.local")
        let flags = DNSServiceFlags(kDNSServiceFlagsReturnIntermediates)
        #expect(resolver.started == [.init(host: "DiskStation.local", family: AF_INET6, flags: flags),
                                     .init(host: "DiskStation.local", family: AF_INET, flags: flags)])
    }

    @Test("families answering together keep IPv6 first, as dns_sd and getaddrinfo order them, then alternate")
    func dualStackOrder() {
        let resolver = ScriptedResolver(ipv4: [.now(.address("192.168.1.131")), .now(.address("192.168.1.132"))],
                                        ipv6: [.now(.address("fe80::1%lo0")), .now(.address("2001:db8::10"))])
        #expect(resolve(resolver).addresses == ["fe80::1%lo0", "192.168.1.131", "2001:db8::10", "192.168.1.132"])
    }

    @Test("a host with only an A record resolves without waiting for AAAA")
    func ipv4Only() {
        let result = resolve(ScriptedResolver(ipv4: [.now(.address("192.0.2.10"))], ipv6: [.now(.none)]))
        #expect(result.failure == nil)
        #expect(result.addresses == ["192.0.2.10"])
        #expect(result.seconds < 1, "waited \(result.seconds) s; the 2 s grace period should not apply")
    }

    @Test("a host with only an AAAA record resolves without waiting for A")
    func ipv6Only() {
        let result = resolve(ScriptedResolver(ipv4: [.now(.none)], ipv6: [.now(.address("2001:db8::10"))]))
        #expect(result.addresses == ["2001:db8::10"])
        #expect(result.seconds < 1, "waited \(result.seconds) s")
    }

    @Test("a name that does not exist fails promptly with .host")
    func missingName() {
        let result = resolve(ScriptedResolver(ipv4: [.now(.none)], ipv6: [.now(.none)]))
        #expect(result.failure as? SMBFailure == .host)
        #expect(result.seconds < 1, "took \(result.seconds) s; the 10 s limit should not apply")
    }

    @Test("every answer of one dns_sd batch is applied before deciding")
    func wholeBatch() {
        let addresses = (1...8).map { "20.190.147.\($0)" }
        let resolver = ScriptedResolver(ipv4: addresses.map { .now(.address($0)) }, ipv6: [.now(.none)])
        #expect(resolve(resolver).addresses == addresses)
    }

    @Test("a family that never answers (mDNS) costs only the grace period")
    func silentFamily() {
        let result = resolve(ScriptedResolver(ipv4: [.now(.address("192.168.1.120"))]), grace: 0.5)
        #expect(result.addresses == ["192.168.1.120"])
        #expect(result.seconds >= 0.5 && result.seconds < 3, "took \(result.seconds) s")
    }

    @Test("a family that answers within the grace period is kept, and ends the wait")
    func lateFamily() {
        let resolver = ScriptedResolver(ipv4: [.now(.address("192.0.2.10"))], ipv6: [.after(0.2, .address("2001:db8::10"))])
        let result = resolve(resolver, grace: 3)
        #expect(result.addresses == ["192.0.2.10", "2001:db8::10"])
        #expect(result.seconds >= 0.2 && result.seconds < 2, "took \(result.seconds) s")
    }

    @Test("with no answer at all, the lookup fails with .host at the resolution limit")
    func resolutionLimit() {
        let result = resolve(ScriptedResolver(), timeout: 20, limit: 0.5)
        #expect(result.failure as? SMBFailure == .host)
        #expect(result.seconds >= 0.5 && result.seconds < 3, "took \(result.seconds) s")
    }

    @Test("resolution never outlasts the connection timeout")
    func connectionTimeoutBoundsResolution() {
        let result = resolve(ScriptedResolver(), timeout: 0.5, limit: 10)
        #expect(result.failure as? SMBFailure == .host)
        #expect(result.seconds >= 0.5 && result.seconds < 3, "took \(result.seconds) s")
    }

    @Test("cancellation stops a lookup within its 50 ms sampling interval")
    func cancellation() {
        let start = Date()
        let result = resolve(ScriptedResolver(), cancelled: { Date().timeIntervalSince(start) > 0.2 })
        #expect(result.failure as? SMBFailure == .cancelled)
        #expect(result.seconds < 1.5, "took \(result.seconds) s")
    }

    @Test("an operation cancelled before resolution starts no query")
    func cancelledBeforeStart() {
        let resolver = ScriptedResolver()
        let result = resolve(resolver, cancelled: { true })
        #expect(result.failure as? SMBFailure == .cancelled)
        #expect(resolver.started.isEmpty)
    }

    @Test("a failed family query keeps the other family's addresses")
    func failedQuery() {
        let result = resolve(ScriptedResolver(ipv6: [.now(.address("2001:db8::10"))], failing: [AF_INET]))
        #expect(result.addresses == ["2001:db8::10"])
        #expect(result.seconds < 1, "took \(result.seconds) s")
    }

    @Test("both family queries failing is a name error")
    func bothQueriesFail() {
        let result = resolve(ScriptedResolver(failing: [AF_INET, AF_INET6]))
        #expect(result.failure as? SMBFailure == .host)
        #expect(result.seconds < 1, "took \(result.seconds) s")
    }

    @Test("a query dns_sd cannot start is a name error")
    func startFailure() {
        #expect(throws: SMBFailure.host) {
            _ = try SMBTransport.resolve("nas.example", timeout: 20, cancelled: { false }) { _, _, _ in throw SMBFailure.host }
        }
    }

    @Test("IP literals are returned unchanged without starting a query",
          arguments: ["192.168.1.120", "2001:db8::10", "fe80::1%lo0"])
    func literals(host: String) {
        let resolver = ScriptedResolver()
        let result = resolve(resolver, host: host)
        #expect(result.addresses == [host])
        #expect(resolver.started.isEmpty)
    }
}
