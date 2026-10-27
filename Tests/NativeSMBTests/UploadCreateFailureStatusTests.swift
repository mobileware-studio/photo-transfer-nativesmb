import Foundation
import Testing
import CSMB
@testable import NativeSMB

/// #329: the rule that reads an upload's create over a folder as a taken name, held against libsmb2's own
/// tables instead of numbers copied by hand. `UploadCreateFailureTests` pins the three denials its authors
/// thought of; these pin the rule for every status libsmb2 can hand to Swift. Pure, so they run without a fixture.
@Suite("Upload create failure statuses")
struct UploadCreateFailureStatusTests {
    /// Every NT status value libsmb2 can name: the success, warning and error ranges up to 0xC000FFFF (the
    /// largest it names is 0xC0000466), and the two special values outside them (SMB_BAD_FID, SHUTDOWN).
    private static let statuses: [UInt32] = {
        var all: [UInt32] = [0x0006_0001, 0xFFFF_FFFF]
        for base: UInt32 in [0x0000_0000, 0x8000_0000, 0xC000_0000] {
            all.append(contentsOf: (0...0xFFFF).map { base + UInt32($0) })
        }
        return all
    }()

    private static func refined(_ status: UInt32) -> SMBFailure? {
        SMBTransport.uploadCreateFailure(SMBFailure.accessDenied, status: status) as? SMBFailure
    }

    @Test("of every status libsmb2 names, only STATUS_FILE_IS_A_DIRECTORY turns an access denial into a taken name")
    func onlyTheFolderStatusIsRefined() {
        let taken = Self.statuses.filter { Self.refined($0) == .exists }
        #expect(taken.map { String($0, radix: 16) } == [String(SMB2_STATUS_FILE_IS_A_DIRECTORY, radix: 16)],
                "statuses read as a taken name: \(taken.map { String($0, radix: 16) })")
    }

    @Test("the status the rule looks for is libsmb2's STATUS_FILE_IS_A_DIRECTORY")
    func theConstantIsLibsmb2s() {
        #expect(SMBTransport.fileIsADirectory == UInt32(SMB2_STATUS_FILE_IS_A_DIRECTORY))
        #expect(String(cString: nterror_to_str(SMBTransport.fileIsADirectory)) == "STATUS_FILE_IS_A_DIRECTORY")
    }

    @Test("the denials that must stay are statuses libsmb2 reports as EPERM, as the folder status is")
    func theDenialsReachSwiftAsEPERM() {
        // EPERM is what `failure(errno:)` reads as `.accessDenied`; any other errno never reaches the rule with it.
        let eperm = Self.statuses.filter { nterror_to_errno($0) == EPERM }
        #expect(eperm.contains(SMBTransport.fileIsADirectory))
        for named in [SMB2_STATUS_PRIVILEGE_NOT_HELD, SMB2_STATUS_CANNOT_DELETE, SMB2_STATUS_FILE_DELETED] {
            #expect(eperm.contains(UInt32(named)), "0x\(String(UInt32(named), radix: 16)) is no longer EPERM in libsmb2")
        }
        let stays = eperm.filter { $0 != SMBTransport.fileIsADirectory }
        #expect(stays.count >= 3)
        for status in stays {
            #expect(Self.refined(status) == .accessDenied, "EPERM status 0x\(String(status, radix: 16)) was read as a taken name")
        }
    }

    @Test("an error that isn't an SMBFailure comes back as it was, whatever status is recorded")
    func foreignErrorStays() {
        struct Foreign: Error, Equatable { let tag = 329 }
        for status in [SMBTransport.fileIsADirectory, 0] {
            #expect(SMBTransport.uploadCreateFailure(Foreign(), status: status) as? Foreign == Foreign())
        }
    }
}
