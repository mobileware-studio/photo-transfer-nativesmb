import Foundation
import Darwin
import CSMB
@testable import NativeSMB

// MARK: - Addresses

func ipv4(_ text: String) -> sockaddr_in {
    var value = sockaddr_in()
    value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    value.sin_family = sa_family_t(AF_INET)
    precondition(inet_pton(AF_INET, text, &value.sin_addr) == 1)
    return value
}

func ipv6(_ text: String, scope: UInt32 = 0) -> sockaddr_in6 {
    var value = sockaddr_in6()
    value.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
    value.sin6_family = sa_family_t(AF_INET6)
    value.sin6_scope_id = scope
    precondition(inet_pton(AF_INET6, text, &value.sin6_addr) == 1)
    return value
}

// MARK: - dns_sd callback arguments

let added = DNSServiceFlags(kDNSServiceFlagsAdd)
let noError = DNSServiceErrorType(kDNSServiceErr_NoError)
let noSuchRecord = DNSServiceErrorType(kDNSServiceErr_NoSuchRecord)

/// Interprets a callback the way `DNSServiceAddressQuery` does, with `address` passed as dns_sd would.
func answer<Address>(_ address: Address?, flags: DNSServiceFlags = added, error: DNSServiceErrorType = noError,
                     family: Int32) -> SMBAddressAnswer {
    guard var address else { return SMBAddressAnswer(flags: flags, error: error, address: nil, family: family) }
    return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            SMBAddressAnswer(flags: flags, error: error, address: $0, family: family)
        }
    }
}

// MARK: - Scripted queries

struct ScriptedReply {
    let delay: TimeInterval
    let answer: SMBAddressAnswer
    static func now(_ answer: SMBAddressAnswer) -> ScriptedReply { ScriptedReply(delay: 0, answer: answer) }
    static func after(_ delay: TimeInterval, _ answer: SMBAddressAnswer) -> ScriptedReply { ScriptedReply(delay: delay, answer: answer) }
}

/// A pipe that wakes `poll` the way a dns_sd socket does.
/// @unchecked Sendable: both descriptors are immutable after init, and read(2)/write(2) are safe to
/// call from the delayed-signal queue while the resolver thread reads.
final class TestPipe: @unchecked Sendable {
    let readEnd: Int32
    private let writeEnd: Int32
    init() {
        var fds: [Int32] = [-1, -1]
        precondition(pipe(&fds) == 0)
        readEnd = fds[0]; writeEnd = fds[1]
        _ = fcntl(readEnd, F_SETFL, fcntl(readEnd, F_GETFL) | O_NONBLOCK)
    }
    deinit { close(readEnd); close(writeEnd) }
    func signal() { var byte: UInt8 = 1; _ = write(writeEnd, &byte, 1) }
    func consume() -> Bool { var byte: UInt8 = 0; return read(readEnd, &byte, 1) == 1 }
}

/// One family's scripted lookup. Like dns_sd, it withholds negative answers unless the query asked
/// for kDNSServiceFlagsReturnIntermediates, and one `process()` delivers every answer already due.
final class ScriptedQuery: SMBAddressQuery {
    private let pipe = TestPipe()
    private var queue: [SMBAddressAnswer]
    private let fails: Bool

    init(_ script: [ScriptedReply], flags: DNSServiceFlags, fails: Bool) {
        let intermediates = flags & DNSServiceFlags(kDNSServiceFlagsReturnIntermediates) != 0
        let delivered = script.filter { intermediates || $0.answer != .none }
        queue = delivered.map(\.answer)
        self.fails = fails
        if fails { pipe.signal() }
        for item in delivered {
            if item.delay <= 0 {
                pipe.signal()
            } else {
                // The closure keeps the pipe open until it has fired, even after the test is done.
                let pipe = self.pipe
                DispatchQueue.global().asyncAfter(deadline: .now() + item.delay) { pipe.signal() }
            }
        }
    }

    var descriptor: Int32 { pipe.readEnd }

    func process() -> [SMBAddressAnswer]? {
        if fails { return nil }
        var answers: [SMBAddressAnswer] = []
        while !queue.isEmpty, pipe.consume() { answers.append(queue.removeFirst()) }
        return answers
    }
}

/// Starts scripted queries and records how resolution started them.
final class ScriptedResolver {
    struct Start: Equatable { let host: String; let family: Int32; let flags: DNSServiceFlags }
    private(set) var started: [Start] = []
    private let scripts: [Int32: [ScriptedReply]]
    private let failing: Set<Int32>

    init(ipv4: [ScriptedReply] = [], ipv6: [ScriptedReply] = [], failing: Set<Int32> = []) {
        scripts = [AF_INET: ipv4, AF_INET6: ipv6]
        self.failing = failing
    }

    func start(host: String, family: Int32, flags: DNSServiceFlags) throws -> SMBAddressQuery {
        started.append(Start(host: host, family: family, flags: flags))
        return ScriptedQuery(scripts[family] ?? [], flags: flags, fails: failing.contains(family))
    }
}

// MARK: - Sockets and timing

/// A loopback port that refuses connections: bound once to learn a free number, then closed.
func closedLoopbackPort(family: Int32 = AF_INET) -> Int {
    let fd = socket(family, SOCK_STREAM, 0)
    precondition(fd >= 0)
    defer { close(fd) }
    if family == AF_INET6 {
        var address = ipv6("::1")
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                precondition(bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0)
            }
        }
        return Int(UInt16(bigEndian: address.sin6_port))
    }
    var address = ipv4("127.0.0.1")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            precondition(bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0)
        }
    }
    return Int(UInt16(bigEndian: address.sin_port))
}

func connection(host: String, port: Int) -> SMBConnection {
    SMBConnection(host: host, port: port, username: "alice", password: "not-a-real-password", domain: "",
                  guest: false, requireEncryption: false)
}

/// Runs `body`, returning its failure (nil if it succeeded) and how long it took.
func measure(_ body: () throws -> Void) -> (failure: Error?, seconds: Double) {
    let clock = ContinuousClock()
    let start = clock.now
    var failure: Error?
    do { try body() } catch { failure = error }
    let elapsed = clock.now - start
    return (failure, Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18)
}
