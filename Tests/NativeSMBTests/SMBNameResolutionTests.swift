import Foundation
import Darwin
import CSMB
import Testing
@testable import NativeSMB

/// The waiting policy, driven with explicit timestamps (seconds since the lookup started).
@Suite("SMB name resolution policy (issue #246)")
struct SMBNameResolutionTests {
    private func resolution(timeout: TimeInterval = 20) -> SMBNameResolution {
        SMBNameResolution(start: 0, timeout: timeout)
    }

    @Test("defaults: 250 ms grace, 5 s resolution limit, 16 addresses")
    func defaults() {
        #expect(SMBNameResolution.defaultGrace == 0.25)
        #expect(SMBNameResolution.defaultLimit == 5)
        #expect(SMBNameResolution.maximumAddresses == 16)
        #expect(resolution().deadline == 5)
        #expect(resolution(timeout: 3).deadline == 3, "resolution never outlasts the connection timeout")
    }

    @Test("a host with only an A record resolves as soon as AAAA is known missing")
    func ipv4Only() {
        var state = resolution()
        state.receive(.address("192.0.2.10"), family: AF_INET, at: 0.010)
        #expect(state.next(at: 0.011) == .wait(until: 0.260))
        state.receive(.none, family: AF_INET6, at: 0.012)
        #expect(state.next(at: 0.012) == .resolved(["192.0.2.10"]))
    }

    @Test("a host with only an AAAA record resolves as soon as A is known missing")
    func ipv6Only() {
        var state = resolution()
        state.receive(.none, family: AF_INET, at: 0.003)
        #expect(state.next(at: 0.004) == .wait(until: 5), "a negative answer alone does not start the grace period")
        state.receive(.address("2001:db8::10"), family: AF_INET6, at: 0.005)
        #expect(state.next(at: 0.005) == .resolved(["2001:db8::10"]))
    }

    @Test("a name with no records fails with .host as soon as both families answer")
    func missingName() {
        var state = resolution()
        state.receive(.none, family: AF_INET6, at: 0.003)
        state.receive(.none, family: AF_INET, at: 0.003)
        #expect(state.next(at: 0.003) == .failed(.host))
    }

    @Test("a family that never answers (mDNS) is waited for only for the grace period")
    func silentFamily() {
        var state = resolution()
        state.receive(.address("192.168.1.120"), family: AF_INET, at: 0.100)
        #expect(state.next(at: 0.200) == .wait(until: 0.350))
        #expect(state.next(at: 0.349) == .wait(until: 0.350))
        #expect(state.next(at: 0.350) == .resolved(["192.168.1.120"]))
    }

    @Test("an answer inside the grace period is kept")
    func lateFamilyWithinGrace() {
        var state = resolution()
        state.receive(.address("192.0.2.10"), family: AF_INET, at: 0.050)
        state.receive(.address("2001:db8::10"), family: AF_INET6, at: 0.250)
        #expect(state.next(at: 0.250) == .resolved(["192.0.2.10", "2001:db8::10"]))
    }

    @Test("with no answer at all, the lookup fails with .host at the deadline, not .timeout")
    func noAnswer() {
        let state = resolution()
        #expect(state.next(at: 0) == .wait(until: 5))
        #expect(state.next(at: 4.999) == .wait(until: 5))
        #expect(state.next(at: 5) == .failed(.host))
    }

    @Test("the grace period never extends past the deadline")
    func graceCappedByDeadline() {
        var state = SMBNameResolution(start: 0, timeout: 20, limit: 1)
        state.receive(.address("192.0.2.10"), family: AF_INET, at: 0.9)
        #expect(state.next(at: 0.95) == .wait(until: 1))
        #expect(state.next(at: 1) == .resolved(["192.0.2.10"]))
    }

    @Test("a failed family query settles that family")
    func endedFamily() {
        var state = resolution()
        state.receive(.address("2001:db8::10"), family: AF_INET6, at: 0.01)
        state.end(family: AF_INET)
        #expect(state.next(at: 0.01) == .resolved(["2001:db8::10"]))

        var nothing = resolution()
        nothing.end(family: AF_INET)
        nothing.end(family: AF_INET6)
        #expect(nothing.next(at: 0.01) == .failed(.host))
    }

    @Test("duplicates are dropped and at most 16 addresses are kept")
    func cap() {
        var state = resolution()
        for index in 0..<20 {
            state.receive(.address("10.0.0.\(index)"), family: AF_INET, at: 0.01)
            state.receive(.address("10.0.0.\(index)"), family: AF_INET, at: 0.01)
        }
        state.receive(.address("10.0.0.19"), family: AF_INET, at: 0.01)
        state.receive(.none, family: AF_INET6, at: 0.01)
        #expect(state.next(at: 0.01) == .resolved((0..<16).map { "10.0.0.\($0)" }))
    }

    @Test("families interleave, first-answering family first, so neither can be crowded out")
    func interleave() {
        var state = resolution()
        for index in 1...19 { state.receive(.address("2001:db8::\(index)"), family: AF_INET6, at: 0.01) }
        state.receive(.address("2001:db8::20"), family: AF_INET6, at: 0.01)
        state.receive(.address("192.0.2.1"), family: AF_INET, at: 0.02)
        state.receive(.address("192.0.2.2"), family: AF_INET, at: 0.02)
        let expected = ["2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"] + (3...14).map { "2001:db8::\($0)" }
        #expect(state.next(at: 0.02) == .resolved(expected))
    }

    @Test("withdrawn addresses are removed; with none left the name fails as .host")
    func withdrawn() {
        var state = resolution()
        state.receive(.address("192.0.2.10"), family: AF_INET, at: 0.01)
        state.receive(.withdrawn("192.0.2.10"), family: AF_INET, at: 0.02)
        #expect(state.next(at: 0.03) == .wait(until: 5), "no usable address, so no grace period")
        state.receive(.none, family: AF_INET6, at: 0.04)
        #expect(state.next(at: 0.04) == .failed(.host))
    }

    @Test("an uninterpretable reply settles nothing")
    func ignored() {
        var state = resolution()
        state.receive(.ignored, family: AF_INET, at: 0.01)
        state.receive(.none, family: AF_INET6, at: 0.01)
        #expect(state.next(at: 0.01) == .wait(until: 5))
    }
}

/// How one dns_sd callback is read. On errors dns_sd leaves the address undefined.
@Suite("SMB dns_sd answer parsing (issue #246)")
struct SMBAddressAnswerTests {
    @Test("a negative answer counts for the query's family, whatever address it carries")
    func negativeAnswers() {
        #expect(answer(ipv4("0.0.0.0"), error: noSuchRecord, family: AF_INET) == .none)
        #expect(answer(ipv6("::"), error: noSuchRecord, family: AF_INET6) == .none)
        #expect(answer(Optional<sockaddr_in>.none, error: noSuchRecord, family: AF_INET) == .none)
        #expect(answer(sockaddr_in(), error: DNSServiceErrorType(kDNSServiceErr_PolicyDenied), family: AF_INET6) == .none,
                "a zeroed address of no family still settles the queried family")
    }

    @Test("usable addresses, including scoped link-local IPv6, become numeric hosts")
    func addresses() {
        #expect(answer(ipv4("192.168.1.120"), family: AF_INET) == .address("192.168.1.120"))
        #expect(answer(ipv6("2001:db8::10"), family: AF_INET6) == .address("2001:db8::10"))
        let loopback = if_nametoindex("lo0")
        #expect(answer(ipv6("fe80::1", scope: loopback), family: AF_INET6) == .address("fe80::1%lo0"))
        var unsized = ipv4("192.0.2.10")
        unsized.sin_len = 0
        #expect(answer(unsized, family: AF_INET) == .address("192.0.2.10"), "a zero sa_len is not trusted")
    }

    @Test("a reply without the Add flag withdraws the address")
    func withdrawal() {
        #expect(answer(ipv4("192.0.2.10"), flags: 0, family: AF_INET) == .withdrawn("192.0.2.10"))
    }

    @Test("unspecified addresses (e.g. a DNS blocklist's 0.0.0.0) are unusable answers")
    func unspecified() {
        #expect(answer(ipv4("0.0.0.0"), family: AF_INET) == .none)
        #expect(answer(ipv6("::"), family: AF_INET6) == .none)
    }

    @Test("a success without an address, or with another family's, settles nothing")
    func uninterpretable() {
        #expect(answer(Optional<sockaddr_in>.none, family: AF_INET) == .ignored)
        #expect(answer(ipv4("192.0.2.10"), family: AF_INET6) == .ignored)
        #expect(answer(sockaddr_in(), family: AF_INET) == .ignored)
    }
}

@Suite("SMB IP literal detection")
struct SMBAddressLiteralTests {
    @Test("IPv4, IPv6 and scoped IPv6 literals skip DNS", arguments: ["192.168.1.120", "2001:db8::10", "::1", "fe80::1%lo0"])
    func literals(host: String) {
        #expect(SMBNameResolution.isAddressLiteral(host))
    }

    @Test("names are resolved", arguments: ["DiskStation.local", "nas.fritz.box", "localhost", "10.1", "nas%20.local", ""])
    func names(host: String) {
        #expect(!SMBNameResolution.isAddressLiteral(host))
    }
}
