import Foundation
import Darwin
import CSMB

/// One `DNSServiceGetAddrInfo` callback of a single-family query, reduced to what resolution needs.
enum SMBAddressAnswer: Equatable {
    /// A usable numeric address. IPv6 link-local addresses keep their `%zone`.
    case address(String)
    /// A previously reported address was withdrawn.
    case withdrawn(String)
    /// The family has no usable address: a negative answer, an error, or an unspecified address.
    case none
    /// Nothing interpretable (no address, or another family's); the family is not settled by it.
    case ignored

    init(flags: DNSServiceFlags, error: DNSServiceErrorType, address: UnsafePointer<sockaddr>?, family: Int32) {
        // dns_sd leaves every other parameter undefined when errorCode is set (negative answers carry a
        // zeroed address, some errors none at all), so the family is the query's, never the callback's.
        guard error == DNSServiceErrorType(kDNSServiceErr_NoError) else { self = .none; return }
        guard let address, Int32(address.pointee.sa_family) == family else { self = .ignored; return }
        guard let host = Self.numericHost(address, family: family) else { self = .none; return }
        self = flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0 ? .address(host) : .withdrawn(host)
    }

    /// Numeric form of a specified address; nil for 0.0.0.0 and ::, which cannot be connected to.
    private static func numericHost(_ address: UnsafePointer<sockaddr>, family: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status: Int32
        if family == AF_INET {
            var value = UnsafeRawPointer(address).loadUnaligned(as: sockaddr_in.self)
            guard value.sin_addr.s_addr != 0 else { return nil }
            value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            status = withUnsafePointer(to: &value) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST)
                }
            }
        } else {
            var value = UnsafeRawPointer(address).loadUnaligned(as: sockaddr_in6.self)
            let unspecified = withUnsafeBytes(of: value.sin6_addr) { $0.allSatisfy { $0 == 0 } }
            guard !unspecified else { return nil }
            value.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            status = withUnsafePointer(to: &value) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in6>.size), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST)
                }
            }
        }
        return status == 0 ? String(cString: buffer) : nil
    }
}

/// Decides when a name lookup is complete (issue #246). Pure: callers pass every timestamp as
/// monotonic seconds, so the waiting policy is testable without a resolver or a clock.
///
/// Each family settles on its first answer, positive or negative. The lookup completes when both
/// families have settled. Once a usable address exists, the other family gets `grace` to answer:
/// mDNS may never answer negatively for a family a host lacks. With no usable address, it fails
/// with `.host` when both families answered negatively or at `deadline`. Callers feed a whole
/// `process()` batch before asking for the next step (see `SMBAddressQuery`).
struct SMBNameResolution {
    enum Step: Equatable {
        case wait(until: TimeInterval)
        case resolved([String])
        case failed(SMBFailure)
    }

    /// Answers for both families normally land within milliseconds of each other (one mDNS response
    /// carries all of a host's addresses); a cold unicast lookup was measured up to ~205 ms apart.
    static let defaultGrace: TimeInterval = 0.25
    /// Bound on resolution alone. Matches the system resolver, which gives up on an unanswered
    /// `.local` name after 5 s. The connection attempts that follow keep their own timeout.
    static let defaultLimit: TimeInterval = 5
    static let maximumAddresses = 16

    let deadline: TimeInterval
    let grace: TimeInterval
    private var ipv4: [String] = []
    private var ipv6: [String] = []
    private var settled: Set<Int32> = []
    private var firstFamily: Int32?
    private var firstAddressAt: TimeInterval?

    init(start: TimeInterval, timeout: TimeInterval, limit: TimeInterval = defaultLimit, grace: TimeInterval = defaultGrace) {
        deadline = start + min(timeout, limit)
        self.grace = grace
    }

    /// Up to 16 addresses, interleaved by family (RFC 8305 section 4) starting with the family that
    /// answered first, so an unreachable family costs at most one connection attempt.
    var addresses: [String] {
        let (first, second) = firstFamily == AF_INET6 ? (ipv6, ipv4) : (ipv4, ipv6)
        var result: [String] = []
        for index in 0..<max(first.count, second.count) {
            if index < first.count { result.append(first[index]) }
            if index < second.count { result.append(second[index]) }
        }
        return Array(result.prefix(Self.maximumAddresses))
    }

    mutating func receive(_ answer: SMBAddressAnswer, family: Int32, at now: TimeInterval) {
        guard family == AF_INET || family == AF_INET6 else { return }
        switch answer {
        case .address(let host):
            settled.insert(family)
            if family == AF_INET { Self.add(host, to: &ipv4) } else { Self.add(host, to: &ipv6) }
            if firstAddressAt == nil { firstAddressAt = now; firstFamily = family }
        case .withdrawn(let host):
            if family == AF_INET { ipv4.removeAll { $0 == host } } else { ipv6.removeAll { $0 == host } }
        case .none:
            settled.insert(family)
        case .ignored:
            break
        }
    }

    private static func add(_ host: String, to list: inout [String]) {
        if !list.contains(host), list.count < maximumAddresses { list.append(host) }
    }

    /// The family's query failed: nothing more will arrive from it.
    mutating func end(family: Int32) {
        settled.insert(family)
    }

    func next(at now: TimeInterval) -> Step {
        let usable = addresses
        let complete = settled.contains(AF_INET) && settled.contains(AF_INET6)
        if complete || now >= deadline { return usable.isEmpty ? .failed(.host) : .resolved(usable) }
        guard let firstAddressAt, !usable.isEmpty else { return .wait(until: deadline) }
        let graceEnd = firstAddressAt + grace
        return now >= graceEnd ? .resolved(usable) : .wait(until: min(graceEnd, deadline))
    }

    /// IP literals skip DNS. Darwin's `inet_pton` also accepts a scoped IPv6 literal (`fe80::1%en0`);
    /// libsmb2's own getaddrinfo applies the zone when it connects.
    static func isAddressLiteral(_ host: String) -> Bool {
        var ipv4 = in_addr(); var ipv6 = in6_addr()
        return inet_pton(AF_INET, host, &ipv4) == 1 || inet_pton(AF_INET6, host, &ipv6) == 1
    }
}

/// One address query for a single family. Answers are delivered only from `process()`, on the
/// caller's thread, so a query is confined to its worker and needs no locking.
protocol SMBAddressQuery: AnyObject {
    /// Readable when `process()` has answers to deliver.
    var descriptor: Int32 { get }
    /// Reads every queued answer; nil once the query has failed. Call only when `descriptor` is readable.
    /// dns_sd's `DNSServiceProcessResult` keeps reading while replies are queued, flagging each callback
    /// but the last with kDNSServiceFlagsMoreComing, so a batch always ends with the queue drained and
    /// resolution decides only between batches. The flag itself is not tracked across batches: a queued
    /// reply can produce no callback (the client library drops CNAME intermediates), which would leave
    /// such a gate waiting for the deadline.
    func process() -> [SMBAddressAnswer]?
}

typealias SMBAddressQueryStart = (_ host: String, _ family: Int32, _ flags: DNSServiceFlags) throws -> SMBAddressQuery

/// `DNSServiceGetAddrInfo` for one family. dns_sd invokes the callback only inside
/// `DNSServiceProcessResult`, and deinit deallocates the ref before the reply storage goes away.
final class DNSServiceAddressQuery: SMBAddressQuery {
    private var service: DNSServiceRef?
    private let family: Int32
    private var answers: [SMBAddressAnswer] = []

    private init(family: Int32) { self.family = family }
    deinit { if let service { DNSServiceRefDeallocate(service) } }

    static func start(host: String, family: Int32, flags: DNSServiceFlags) throws -> SMBAddressQuery {
        let query = DNSServiceAddressQuery(family: family)
        let protocols = DNSServiceProtocol(family == AF_INET ? kDNSServiceProtocol_IPv4 : kDNSServiceProtocol_IPv6)
        var service: DNSServiceRef?
        let status = DNSServiceGetAddrInfo(&service, flags, 0, protocols, host, { _, flags, _, error, _, address, _, context in
            guard let context else { return }
            let query = Unmanaged<DNSServiceAddressQuery>.fromOpaque(context).takeUnretainedValue()
            query.answers.append(SMBAddressAnswer(flags: flags, error: error, address: address, family: query.family))
        }, Unmanaged.passUnretained(query).toOpaque())
        guard status == DNSServiceErrorType(kDNSServiceErr_NoError), let service else { throw SMBFailure.host }
        query.service = service
        return query
    }

    var descriptor: Int32 { service.map { DNSServiceRefSockFD($0) } ?? -1 }

    func process() -> [SMBAddressAnswer]? {
        guard let service, DNSServiceProcessResult(service) == DNSServiceErrorType(kDNSServiceErr_NoError) else { return nil }
        defer { answers.removeAll() }
        return answers
    }
}

extension SMBTransport {
    /// Resolves `host` to at most 16 numeric addresses; IP literals are returned unchanged. Fails with
    /// `.host` when the name has no usable address, `.cancelled` when `cancelled` turns true (sampled
    /// at least every 50 ms). Takes at most `min(timeout, limit)`.
    static func resolve(_ host: String, timeout: TimeInterval, cancelled: () -> Bool,
                        limit: TimeInterval = SMBNameResolution.defaultLimit,
                        grace: TimeInterval = SMBNameResolution.defaultGrace,
                        start: SMBAddressQueryStart = DNSServiceAddressQuery.start) throws -> [String] {
        if SMBNameResolution.isAddressLiteral(host) { return [host] }
        if cancelled() { throw SMBFailure.cancelled }
        let clock = { ProcessInfo.processInfo.systemUptime }
        var resolution = SMBNameResolution(start: clock(), timeout: timeout, limit: limit, grace: grace)
        // Without ReturnIntermediates dns_sd withholds negative answers (NXDOMAIN, no AAAA record), so
        // a missing family would only be noticed at the deadline. One query per family attributes each
        // answer to its family without reading the address that dns_sd leaves undefined on errors.
        let flags = DNSServiceFlags(kDNSServiceFlagsReturnIntermediates)
        // Replies read in the same poll are applied IPv6 first, keeping the order a combined dns_sd
        // query and getaddrinfo give dual-stack hosts; `addresses` then alternates the families.
        var queries: [(family: Int32, query: SMBAddressQuery)] = try [AF_INET6, AF_INET].map { ($0, try start(host, $0, flags)) }
        while true {
            if cancelled() { throw SMBFailure.cancelled }
            let now = clock()
            switch resolution.next(at: now) {
            case .resolved(let addresses): return addresses
            case .failed(let failure): throw failure
            case .wait(let until):
                let milliseconds = Int32(min(50, max(1, ((until - now) * 1_000).rounded(.up))))
                var fds = queries.map { pollfd(fd: $0.query.descriptor, events: Int16(POLLIN), revents: 0) }
                if poll(&fds, nfds_t(fds.count), milliseconds) < 0 && errno != EINTR {
                    // Unusable descriptors: settle with whatever has arrived.
                    for entry in queries { resolution.end(family: entry.family) }
                    queries.removeAll()
                    continue
                }
                var failed: [Int32] = []
                for (entry, fd) in zip(queries, fds) where fd.revents != 0 {
                    guard let answers = entry.query.process() else { failed.append(entry.family); continue }
                    for answer in answers { resolution.receive(answer, family: entry.family, at: clock()) }
                }
                for family in failed { resolution.end(family: family) }
                queries.removeAll { failed.contains($0.family) }
            }
        }
    }
}
