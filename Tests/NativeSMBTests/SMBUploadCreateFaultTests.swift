import Foundation
import Testing
import CSMB
@testable import NativeSMB

/// #329 on the wire. `UploadCreateFailureTests` pins the rule without a server, and the Samba cases in the app's
/// SMB fixture tests pin it for a real folder. These pin what only a scripted server can reach, through libsmb2
/// and `command()`: that the NT status read is the one the create itself was answered with, that only the
/// upload's create is refined, and that a create counts as made only when it succeeded. They run against the
/// opt-in fault fixture, `Tests/Fixtures/smb_fault_server.py`, which answers by file name:
///
///     *.folder.*    an exclusive create (of a file or a folder) answers STATUS_FILE_IS_A_DIRECTORY (what Samba says for a
///                   file create over a folder of that name)
///     *.perm.*      an exclusive create answers STATUS_PRIVILEGE_NOT_HELD (EPERM in libsmb2 as well, but a real denial)
///     *.writedir.*  the first WRITE answers STATUS_FILE_IS_A_DIRECTORY, after a normal create
///
/// Start it as `SMBUploadCleanupFaultTests` describes (port 1446), then run `SMB_FAULT_FIXTURE=1 swift test`.
/// Every test uses a name of its own. The fixture's root is disposable.
@Suite("SMB upload create fault fixture", .serialized,
       .enabled(if: ProcessInfo.processInfo.environment["SMB_FAULT_FIXTURE"] == "1",
                "requires the SMB fault fixture on 127.0.0.1:1446 (Tests/Fixtures/smb_fault_server.py)"))
struct SMBUploadCreateFaultTests {
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

    /// Uploads 70,000 bytes under `name` and returns the failure, if any, and how many chunks the upload asked its source for.
    private func upload(_ name: String) throws -> (failure: SMBFailure?, reads: Int) {
        let uploader = try transport()
        defer { uploader.close() }
        var reads = 0
        do {
            try uploader.upload(path: name, size: 70_000, read: { wanted, _ in reads += 1; return Data(repeating: 6, count: wanted) },
                                progress: { _ in })
            return (nil, reads)
        } catch let failure as SMBFailure {
            return (failure, reads)
        }
    }

    @Test("a create answered with STATUS_FILE_IS_A_DIRECTORY reads as a taken name; nothing is read, made or removed")
    func folderStatusIsATakenName() throws {
        let name = UUID().uuidString + ".folder.jpg"
        let result = try upload(name)
        #expect(result.failure == .exists)
        #expect(result.reads == 0, "the taken name consumed the source")
        let listed = try names()
        #expect(!listed.contains(name))
        #expect(!listed.contains("delete-open-seen-" + name),
                "the interrupted-upload removal ran for a create that made nothing")
    }

    @Test("a create answered with another EPERM status, STATUS_PRIVILEGE_NOT_HELD, stays access denied")
    func otherDenialStays() throws {
        let name = UUID().uuidString + ".perm.jpg"
        let result = try upload(name)
        #expect(result.failure == .accessDenied)
        #expect(result.reads == 0)
        #expect(!(try names()).contains(name))
    }

    /// The premise of reading the status in `command`'s catch (smb.md invariant 10), held against libsmb2 itself on one context:
    /// a failed open records the status the server answered it with, a command that succeeds leaves it alone, and the next failed
    /// open replaces it. So after a failed create, the status read is that create's own, never an earlier command's; and a
    /// status left on a context by something earlier is exactly what a command that records none would be mistaken for.
    @Test("libsmb2 keeps one NT status per context: a failed open records it, a success leaves it, the next failed open replaces it")
    func statusIsStickyAndReplacedByTheNextFailedOpen() throws {
        let context = try #require(smb2_init_context())
        defer { smb2_destroy_context(context) }
        smb2_set_timeout(context, 10)
        smb2_set_authentication(context, Int32(SMB2_SEC_NTLMSSP.rawValue))
        smb2_set_version(context, SMB2_VERSION_ANY)
        smb2_set_security_mode(context, UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED))
        smb2_set_sign(context, 1)
        context.pointee.use_cached_creds = 0
        smb2_set_user(context, "alice"); smb2_set_password(context, "fixture-password"); smb2_set_domain(context, "")
        try #require(smb2_connect_share(context, "127.0.0.1:1446", "Photos", "alice") == 0, "could not connect to the fault fixture")
        func status() -> UInt32 { UInt32(bitPattern: smb2_get_nterror(context)) }
        #expect(status() == 0, "a connected context starts with no status")

        #expect(smb2_open(context, UUID().uuidString + ".folder.jpg", O_WRONLY | O_CREAT | O_EXCL) == nil)
        #expect(status() == SMBTransport.fileIsADirectory, "the failed open did not record the status it was answered with")

        var info = smb2_stat_64()
        #expect(smb2_stat(context, "", &info) == 0, "the stat of the share's root failed")
        #expect(status() == SMBTransport.fileIsADirectory, "a command that succeeded cleared the status")

        #expect(smb2_open(context, UUID().uuidString + ".perm.jpg", O_WRONLY | O_CREAT | O_EXCL) == nil)
        #expect(status() == UInt32(SMB2_STATUS_PRIVILEGE_NOT_HELD), "the next failed open kept the earlier status instead of its own")
    }

    @Test("a folder creation answered with STATUS_FILE_IS_A_DIRECTORY stays access denied: only the upload's create is refined")
    func folderCreationIsNotRefined() throws {
        let creator = try transport()
        defer { creator.close() }
        #expect(throws: SMBFailure.accessDenied) { try creator.mkdir(path: UUID().uuidString + ".folder.d") }
    }

    @Test("a write answered with STATUS_FILE_IS_A_DIRECTORY stays access denied: only the create is refined, and the file it made is removed")
    func writeStatusIsNotRefined() throws {
        let name = UUID().uuidString + ".writedir.jpg"
        let result = try upload(name)
        #expect(result.failure == .accessDenied)
        #expect(result.reads == 1, "one chunk was read and its write answered")
        #expect(!(try names()).contains(name), "the create succeeded, so the failed upload's removal had to run")
    }
}
