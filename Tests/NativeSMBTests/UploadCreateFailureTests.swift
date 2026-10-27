import Testing
@testable import NativeSMB

/// #329: only an upload create that itself failed with EPERM over a folder (Samba's
/// STATUS_FILE_IS_A_DIRECTORY) reads as a taken name. Pure, so it runs without a fixture.
@Suite("Upload create failures")
struct UploadCreateFailureTests {
    @Test("a create over a same-named folder is a taken name")
    func folderIsATakenName() {
        #expect(SMBTransport.uploadCreateFailure(SMBFailure.accessDenied, status: 0xC00000BA) as? SMBFailure == .exists)
    }

    @Test("EPERM with any other status stays access denied", arguments: [UInt32(0xC0000061), 0xC0000121, 0xC0000123, 0])
    func otherDenialsStay(status: UInt32) {
        // PRIVILEGE_NOT_HELD, CANNOT_DELETE, FILE_DELETED, none recorded
        #expect(SMBTransport.uploadCreateFailure(SMBFailure.accessDenied, status: status) as? SMBFailure == .accessDenied)
    }

    @Test("a failure that isn't the create's own EPERM keeps itself, whatever status is recorded",
          arguments: [SMBFailure.cancelled, .timeout, .connection, .authentication, .exists])
    func otherFailuresStay(failure: SMBFailure) {
        #expect(SMBTransport.uploadCreateFailure(failure, status: 0xC00000BA) as? SMBFailure == failure)
        #expect(SMBTransport.uploadCreateFailure(failure, status: nil) as? SMBFailure == failure)
    }

    @Test("no context, no status: the failure stays")
    func noStatus() {
        #expect(SMBTransport.uploadCreateFailure(SMBFailure.accessDenied, status: nil) as? SMBFailure == .accessDenied)
    }
}
