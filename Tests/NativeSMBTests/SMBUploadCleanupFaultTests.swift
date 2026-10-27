import Foundation
import Testing
@testable import NativeSMB

/// The upload cleanup (#267) branches that the stock SMB fixtures cannot reach: a sharing violation that is retried
/// and one that never ends (the 5 s budget), and a reparse point at the path. They run against an opt-in fault
/// fixture, `Tests/Fixtures/smb_fault_server.py`: the stock Impacket SMB2 fixture whose answer to the cleanup's
/// delete-open (a CREATE of an existing file with DELETE access) depends on the file's name:
///
///     *.busy3.*  three STATUS_SHARING_VIOLATIONs, then normal
///     *.stuck.*  sharing violations forever
///     *.link.*   the open reports FILE_ATTRIBUTE_REPARSE_POINT
///
/// Start it with `python smb_fault_server.py --root <empty temp dir> --port 1446` in the virtualenv of the paired
/// Android repo's `smb_server.py` (.claude/docs/smb-testing.md), then run `SMB_FAULT_FIXTURE=1 swift test`.
/// Each upload fails after its own exclusive create (the source ends early), so the cleanup always runs. The tests
/// that make it give up leave one partial file in the fixture's root, which is disposable.
@Suite("SMB upload cleanup fault fixture", .serialized,
       .enabled(if: ProcessInfo.processInfo.environment["SMB_FAULT_FIXTURE"] == "1",
                "requires the SMB fault fixture on 127.0.0.1:1446 (Tests/Fixtures/smb_fault_server.py)"))
struct SMBUploadCleanupFaultTests {
    private func transport() throws -> SMBTransport {
        try SMBTransport(connection: SMBConnection(host: "127.0.0.1", port: 1446, username: "alice", password: "fixture-password",
                                                   domain: "", guest: false, requireEncryption: false),
                         share: "Photos", cancelled: { false })
    }

    private func names() throws -> Set<String> {
        let reader = try transport()
        defer { reader.close() }
        return Set(try reader.list(path: "").map(\.name))
    }

    /// Fails an upload of `name` after its create and returns how long that took, cleanup included.
    private func failedUpload(_ name: String) throws -> TimeInterval {
        let uploader = try transport()
        defer { uploader.close() }
        let start = Date()
        do {
            try uploader.upload(path: name, size: 200_000, read: { count, offset in
                offset == 0 ? Data(repeating: 3, count: count) : nil
            }, progress: { _ in })
            Issue.record("short upload succeeded")
        } catch SMBFailure.connection { }
        return Date().timeIntervalSince(start)
    }

    @Test("control: an ordinary name is removed at once")
    func ordinaryNameIsRemoved() throws {
        let name = UUID().uuidString + ".jpg"
        let elapsed = try failedUpload(name)
        #expect(!(try names()).contains(name))
        #expect(elapsed < 2, "took \(elapsed) s")
    }

    @Test("three sharing violations are retried 250 ms apart, then the file is removed")
    func sharingViolationsAreRetried() throws {
        let name = UUID().uuidString + ".busy3.jpg"
        let elapsed = try failedUpload(name)
        #expect(!(try names()).contains(name))
        #expect(elapsed >= 0.7, "three retries should take at least 0.75 s, took \(elapsed) s")
        #expect(elapsed < 4, "took \(elapsed) s")
    }

    @Test("sharing violations that never stop end at the 5 s budget, with the file left and the upload's own error",
          .timeLimit(.minutes(1)))
    func endlessSharingViolationsAreBounded() throws {
        let name = UUID().uuidString + ".stuck.jpg"
        let elapsed = try failedUpload(name)
        #expect(try names().contains(name))
        #expect(elapsed >= 4, "gave up after \(elapsed) s")
        #expect(elapsed < 15, "took \(elapsed) s")
    }

    @Test("a reparse point at the path is refused: the file stays and nothing waits for a retry")
    func reparsePointIsRefused() throws {
        let name = UUID().uuidString + ".link.jpg"
        let elapsed = try failedUpload(name)
        #expect(try names().contains(name), "the cleanup deleted a link")
        #expect(elapsed < 2, "a refusal is not retried: took \(elapsed) s")
    }
}
