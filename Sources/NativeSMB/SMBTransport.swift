import Foundation
import Darwin
import CSMB

public struct SMBConnection: Sendable {
    public let host: String
    public let port: Int
    public let username: String
    public let password: String
    public let domain: String
    public let guest: Bool
    public let requireEncryption: Bool

    public init(host: String, port: Int, username: String, password: String, domain: String, guest: Bool, requireEncryption: Bool) {
        self.host = host; self.port = port; self.username = username; self.password = password
        self.domain = domain; self.guest = guest; self.requireEncryption = requireEncryption
    }
}

public enum SMBFailure: Error, Sendable { case authentication, accessDenied, exists, connection, unsupported, invalid, host, port, timeout, cancelled }
public struct SMBEntry: Sendable {
    public let name: String
    public let directory: Bool
    public let size: Int64
    public let modified: Int64
}

/// Each instance is confined to one worker. Only the supplied cancellation signal crosses threads.
/// Destroying the context drains pending callbacks before any callback storage is released.
public final class SMBTransport {
    private var context: UnsafeMutablePointer<smb2_context>?
    private let connection: SMBConnection
    private let share: String
    private let cancelled: () -> Bool
    private var heldDirectories: [OpaquePointer] = []
    private let timeout: TimeInterval
    /// Set when the server at the current address rejected the login. Its other addresses reach
    /// the same server and would reject the same credentials again, counting toward the server's
    /// failed-login lockout, so `init` stops there (#249).
    private var loginRejected = false

    public init(connection: SMBConnection, share: String, timeout: TimeInterval = 20, cancelled: @escaping () -> Bool) throws {
        self.cancelled = cancelled; self.timeout = timeout
        self.connection = connection; self.share = share
        guard (1...65535).contains(connection.port), timeout > 0, timeout <= 120,
              !connection.guest || !connection.requireEncryption else { throw SMBFailure.invalid }
        let addresses = try Self.resolve(connection.host, timeout: timeout, cancelled: cancelled)
        let deadline = Date().addingTimeInterval(timeout)
        var lastFailure: Error = SMBFailure.host
        for address in addresses {
            try checkCancellation()
            guard Date() < deadline else { throw SMBFailure.timeout }
            guard let context = smb2_init_context() else { throw SMBFailure.connection }
            self.context = context
            loginRejected = false
            do {
                smb2_set_timeout(context, Int32(max(1, timeout)))
                smb2_set_authentication(context, Int32(SMB2_SEC_NTLMSSP.rawValue))
                smb2_set_version(context, connection.requireEncryption ? SMB2_VERSION_ANY3 : SMB2_VERSION_ANY)
                smb2_set_security_mode(context, connection.guest ? 0 : UInt16(SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED))
                smb2_set_sign(context, connection.guest ? 0 : 1)
                smb2_set_seal(context, connection.requireEncryption ? 1 : 0)
                context.pointee.use_cached_creds = 0
                smb2_set_user(context, connection.guest ? "" : connection.username)
                smb2_set_password(context, connection.guest ? "" : connection.password)
                smb2_set_domain(context, connection.guest ? "" : connection.domain)
                let server = address.contains(":") ? "[\(address)]:\(connection.port)" : "\(address):\(connection.port)"
                let attemptTimeout = min(deadline.timeIntervalSinceNow, addresses.count > 1 ? 3 : timeout)
                _ = try command(timeout: attemptTimeout, handshake: true) { smb2_connect_share_async(context, server, share, connection.guest ? "" : connection.username, callback, $0) }
                guard smb2_get_dialect(context) >= 0x0202,
                      connection.guest || context.pointee.sign != 0 || context.pointee.seal != 0,
                      !connection.requireEncryption || (smb2_get_dialect(context) >= 0x0300 && context.pointee.seal != 0)
                else { throw SMBFailure.authentication }
                return
            } catch {
                close()
                if loginRejected { throw error }
                switch error as? SMBFailure {
                case .port, .timeout, .connection: lastFailure = error
                default: throw error
                }
            }
        }
        throw lastFailure
    }

    deinit { close() }
    public func close() {
        if let context { smb2_destroy_context(context); self.context = nil }
        heldDirectories.removeAll()
    }

    public func shares() throws -> [String] {
        guard let context else { throw SMBFailure.connection }
        let result = try command { smb2_share_enum_async(context, SHARE_INFO_1, callback, $0) }
        guard let pointer = result.data else { throw SMBFailure.connection }
        defer { smb2_free_data(context, pointer) }
        let response = pointer.assumingMemoryBound(to: srvsvc_NetrShareEnum_rep.self).pointee
        guard response.status == 0, response.ses.Level == 1 else { throw SMBFailure.accessDenied }
        let count = Int(response.ses.ShareInfo.Level1.EntriesRead)
        if count == 0 { return [] }
        guard let buffer = response.ses.ShareInfo.Level1.Buffer else { throw SMBFailure.connection }
        guard count <= Int(buffer.pointee.max_count), count <= 100_000 else { throw SMBFailure.connection }
        guard let entries = buffer.pointee.share_info_1 else { return [] }
        return (0..<count).compactMap { i in
            let item = entries[i]
            guard item.type & 3 == 0, let name = item.netname.utf8 else { return nil }
            return String(cString: name)
        }
    }

    public func list(path: String) throws -> [SMBEntry] {
        try guardAncestors(path, includeLeaf: true)
        guard let context else { throw SMBFailure.connection }
        let result = try command { smb2_opendir_async(context, path, callback, $0) }
        guard let data = result.data else { throw SMBFailure.connection }
        let directory = data.assumingMemoryBound(to: smb2dir.self)
        defer { smb2_closedir(context, directory) }
        var entries: [SMBEntry] = []
        while let next = smb2_readdir(context, directory) {
            try checkCancellation()
            let entry = next.pointee
            let name = String(cString: entry.name)
            guard name != ".", name != "..", entry.st.smb2_type != SMB2_TYPE_LINK else { continue }
            guard entry.st.smb2_size <= Int64.max else { throw SMBFailure.connection }
            entries.append(SMBEntry(name: name, directory: entry.st.smb2_type == SMB2_TYPE_DIRECTORY,
                                    size: Int64(entry.st.smb2_size), modified: milliseconds(entry.st)))
        }
        return entries
    }

    public func mkdir(path: String) throws {
        try guardAncestors(path)
        // Use exclusive directory creation through OPEN, retaining the actual create error.
        let handle = try open(path, flags: O_RDONLY | O_DIRECTORY | O_CREAT | O_EXCL)
        try closeFile(handle)
    }

    public func upload(path: String, size: Int64, read: (Int, Int64) throws -> Data?, progress: (Float) -> Void) throws {
        guard size >= 0 else { throw SMBFailure.invalid }
        try guardAncestors(path)
        guard let context else { throw SMBFailure.connection }
        // Only this exclusive create makes the file ours to remove; `.exists` throws before it.
        let handle = try open(path, flags: O_WRONLY | O_CREAT | O_EXCL, exclusiveCreate: true)
        do {
            var offset: Int64 = 0
            while offset < size {
                try checkCancellation()
                let count = Int(min(65_536, size - offset))
                guard let data = try read(count, offset), !data.isEmpty, data.count <= count else { throw SMBFailure.connection }
                let written = try data.withUnsafeBytes { bytes in
                    try command { smb2_pwrite_async(context, handle, bytes.bindMemory(to: UInt8.self).baseAddress, UInt32(data.count), UInt64(offset), callback, $0) }.status
                }
                guard written == data.count else { throw SMBFailure.connection }
                offset += Int64(written)
                progress(min(0.99, Float(offset) / Float(max(1, size))))
            }
            _ = try command { smb2_fsync_async(context, handle, callback, $0) }
            try closeFile(handle)
            try checkCancellation()
        } catch {
            // A cancelled or failed upload leaves no partial file under its name (#267).
            // The caller still sees the upload's own error.
            removeInterruptedUpload(path)
            throw error
        }
        progress(1)
    }

    public func download(path: String, expectedSize: Int64? = nil, modified: Int64? = nil, maxBytes: Int64 = Int64.max,
                         write: (Data) throws -> Void, progress: (Float) -> Void) throws -> Int64 {
        guard maxBytes >= 0 else { throw SMBFailure.invalid }
        try guardAncestors(path)
        let handle = try open(path, flags: O_RDONLY)
        let info = try stat(handle)
        try validate(info, size: expectedSize, modified: modified)
        guard info.smb2_size <= UInt64(maxBytes) else { throw SMBFailure.invalid }
        let size = Int64(info.smb2_size)
        var offset: Int64 = 0
        while offset < size {
            let data = try read(handle, offset: offset, count: Int(min(65_536, size - offset)))
            guard !data.isEmpty else { throw SMBFailure.connection }
            try write(data)
            offset += Int64(data.count)
            progress(min(0.99, Float(offset) / Float(max(1, size))))
        }
        try closeFile(handle)
        try checkCancellation()
        progress(1)
        return size
    }

    public func range(path: String, size: Int64, modified: Int64, offset: Int64, count: Int) throws -> Data {
        guard size >= 0, offset >= 0, offset < size, count > 0, count <= 262_144 else { throw SMBFailure.invalid }
        try guardAncestors(path)
        let handle = try open(path, flags: O_RDONLY)
        try validate(stat(handle), size: size, modified: modified)
        let wanted = Int(min(Int64(count), size - offset))
        var result = Data()
        while result.count < wanted {
            let chunk = try read(handle, offset: offset + Int64(result.count), count: min(65_536, wanted - result.count))
            guard !chunk.isEmpty else { throw SMBFailure.connection }
            result.append(chunk)
        }
        try closeFile(handle)
        return result
    }

    /// The cleanup's whole budget, DNS and reconnect included: the repository's mutex and the
    /// caller wait for it.
    static let cleanupTimeout: TimeInterval = 5
    /// How long to wait before retrying while the server still holds the interrupted handle.
    static let sharingRetryDelay: TimeInterval = 0.25

    /// Removes the file an interrupted upload created (#267), as Android's SMB backend does.
    /// This context can't do it: `command()` destroys it on any error and refuses to run once
    /// the user cancelled. So the upload's handle is released by closing this context, and a
    /// fresh one, with the same signing and encryption checks, ignores the user's cancel and
    /// gives up at `cleanupTimeout`. Best effort: a failure leaves the file, as before.
    private func removeInterruptedUpload(_ path: String) {
        // The upload's handle denies delete sharing (invariant 6); closing the connection
        // releases it, although the server may take a moment to notice.
        close()
        let deadline = Date().addingTimeInterval(Self.cleanupTimeout)
        guard let cleanup = try? SMBTransport(connection: connection, share: share, timeout: Self.cleanupTimeout,
                                              cancelled: { Date() >= deadline }) else { return }
        defer { cleanup.close() }
        do {
            try cleanup.guardAncestors(path)
            while try cleanup.removeCreatedFile(path) == .busy {
                guard Date().addingTimeInterval(Self.sharingRetryDelay) < deadline else { return }
                Thread.sleep(forTimeInterval: Self.sharingRetryDelay)
            }
        } catch {
            // Best effort, bounded; the upload's own error is reported.
        }
    }

    private enum Removal { case removed, gone, busy }

    /// Deletes `path` on close if it is a regular file. A link at the path is opened itself and
    /// refused, never followed. Sharing is open to all, as in Android's cleanup, so this open
    /// never conflicts with a reader's access (a reader that denies delete sharing still blocks
    /// the delete: `.busy`); the handle lives only for the delete.
    private func removeCreatedFile(_ path: String) throws -> Removal {
        let opened = try openForDelete(path)
        switch opened.status {
        case 0: break
        case UInt32(SMB2_STATUS_OBJECT_NAME_NOT_FOUND), UInt32(SMB2_STATUS_DELETE_PENDING): return .gone
        case UInt32(SMB2_STATUS_SHARING_VIOLATION): return .busy
        default: throw SMBFailure.accessDenied
        }
        // The delete happens when this handle closes.
        defer { _ = try? closeRaw(opened.fileID) }
        guard opened.attributes & UInt32(SMB2_FILE_ATTRIBUTE_REPARSE_POINT) == 0 else { throw SMBFailure.invalid }
        guard try setDeleteOnClose(opened.fileID) == 0 else { throw SMBFailure.accessDenied }
        return .removed
    }

    /// SMB2 CREATE with DELETE and READ_ATTRIBUTES on an existing non-directory, opening a
    /// reparse point itself. libsmb2's `smb2_unlink_async` would follow a link at the path.
    private func openForDelete(_ path: String) throws -> (status: UInt32, fileID: smb2_file_id, attributes: UInt32) {
        guard let context else { throw SMBFailure.connection }
        var fileID: smb2_file_id = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var attributes: UInt32 = 0
        let reply = try path.withCString { name -> Reply in
            var request = smb2_create_request()
            request.requested_oplock_level = UInt8(SMB2_OPLOCK_LEVEL_NONE)
            request.impersonation_level = UInt32(SMB2_IMPERSONATION_IMPERSONATION)
            request.desired_access = UInt32(SMB2_DELETE) | UInt32(SMB2_FILE_READ_ATTRIBUTES)
            request.share_access = UInt32(SMB2_FILE_SHARE_READ) | UInt32(SMB2_FILE_SHARE_WRITE) | UInt32(SMB2_FILE_SHARE_DELETE)
            request.create_disposition = UInt32(SMB2_FILE_OPEN)
            request.create_options = UInt32(SMB2_FILE_NON_DIRECTORY_FILE) | UInt32(SMB2_FILE_OPEN_REPARSE_POINT)
            request.name = name
            return try command(raw: true, copy: { data in
                // The reply is freed when the callback returns.
                let created = data.assumingMemoryBound(to: smb2_create_reply.self).pointee
                fileID = created.file_id
                attributes = created.file_attributes
            }) { cbData in
                guard let pdu = smb2_cmd_create_async(context, &request, callback, cbData) else { return -1 }
                smb2_queue_pdu(context, pdu)
                return 0
            }
        }
        return (UInt32(bitPattern: reply.status), fileID, attributes)
    }

    /// Marks an open file for deletion when its handle closes (FILE_DISPOSITION_INFORMATION).
    private func setDeleteOnClose(_ fileID: smb2_file_id) throws -> UInt32 {
        guard let context else { throw SMBFailure.connection }
        var disposition = smb2_file_disposition_info(delete_pending: 1)
        var request = smb2_set_info_request()
        request.info_type = UInt8(SMB2_0_INFO_FILE)
        request.file_info_class = UInt8(SMB2_FILE_DISPOSITION_INFORMATION)
        request.file_id = fileID
        let reply = try withUnsafeMutablePointer(to: &disposition) { pointer -> Reply in
            request.input_data = UnsafeMutableRawPointer(pointer)
            return try command(raw: true) { cbData in
                guard let pdu = smb2_cmd_set_info_async(context, &request, callback, cbData) else { return -1 }
                smb2_queue_pdu(context, pdu)
                return 0
            }
        }
        return UInt32(bitPattern: reply.status)
    }

    private func closeRaw(_ fileID: smb2_file_id) throws -> UInt32 {
        guard let context else { throw SMBFailure.connection }
        var request = smb2_close_request()
        request.file_id = fileID
        let reply = try command(raw: true) { cbData in
            guard let pdu = smb2_cmd_close_async(context, &request, callback, cbData) else { return -1 }
            smb2_queue_pdu(context, pdu)
            return 0
        }
        return UInt32(bitPattern: reply.status)
    }

    private func guardAncestors(_ path: String, includeLeaf: Bool = false) throws {
        let components = path.split(separator: "\\", omittingEmptySubsequences: false)
        guard path.isEmpty || components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("/") && !$0.contains(":") }) else { throw SMBFailure.invalid }
        let count = path.isEmpty ? 0 : components.count - (includeLeaf ? 0 : 1)
        for i in 0..<count {
            let handle = try open(components[0...i].joined(separator: "\\"), flags: O_RDONLY | O_DIRECTORY)
            let info = try stat(handle)
            guard info.smb2_type == SMB2_TYPE_DIRECTORY else { throw SMBFailure.invalid }
            heldDirectories.append(handle)
        }
    }

    /// `exclusiveCreate`: an upload's create, whose failure over a folder of the same name is
    /// read as a taken name (`uploadCreateFailure`, #329).
    private func open(_ path: String, flags: Int32, exclusiveCreate: Bool = false) throws -> OpaquePointer {
        guard let context else { throw SMBFailure.connection }
        let result = try command(exclusiveCreate: exclusiveCreate) { smb2_open_async(context, path, flags, callback, $0) }
        guard let data = result.data else { throw SMBFailure.connection }
        return OpaquePointer(data)
    }
    private func closeFile(_ handle: OpaquePointer) throws {
        guard let context else { throw SMBFailure.connection }
        _ = try command { smb2_close_async(context, handle, callback, $0) }
    }
    private func stat(_ handle: OpaquePointer) throws -> smb2_stat_64 {
        guard let context else { throw SMBFailure.connection }
        var info = smb2_stat_64()
        _ = try command { smb2_fstat_async(context, handle, &info, callback, $0) }
        return info
    }
    private func validate(_ info: smb2_stat_64, size: Int64?, modified: Int64?) throws {
        guard info.smb2_type == SMB2_TYPE_FILE, info.smb2_size <= Int64.max,
              size == nil || size == Int64(info.smb2_size), modified == nil || modified == milliseconds(info)
        else { throw SMBFailure.invalid }
    }
    private func milliseconds(_ info: smb2_stat_64) -> Int64 {
        Int64(min(info.smb2_mtime, UInt64(Int64.max / 1_000 - 1))) * 1_000 + Int64(min(info.smb2_mtime_nsec, 999_999_999) / 1_000_000)
    }
    private func read(_ handle: OpaquePointer, offset: Int64, count: Int) throws -> Data {
        guard let context else { throw SMBFailure.connection }
        var bytes = [UInt8](repeating: 0, count: count)
        let size = try bytes.withUnsafeMutableBufferPointer { buffer in
            try command { smb2_pread_async(context, handle, buffer.baseAddress, UInt32(count), UInt64(offset), callback, $0) }.status
        }
        guard size <= count else { throw SMBFailure.connection }
        return Data(bytes.prefix(Int(size)))
    }

    private final class Reply {
        var done = false
        var status: Int32 = 0
        var data: UnsafeMutableRawPointer?
        /// Copies a raw command's reply, which libsmb2 frees when the callback returns.
        var copy: ((UnsafeMutableRawPointer) -> Void)?
    }
    private var callback: smb2_command_cb { { _, status, data, opaque in
        guard let opaque else { return }
        let reply = Unmanaged<Reply>.fromOpaque(opaque).takeUnretainedValue()
        reply.status = status; reply.data = data
        if status == 0, let data { reply.copy?(data) }
        reply.done = true
    } }
    /// `raw` commands (libsmb2-raw.h) complete with an NT status, which the caller reads from
    /// `Reply.status`; only the event loop's own failures throw and destroy the context.
    private func command(timeout operationTimeout: TimeInterval? = nil, handshake: Bool = false, raw: Bool = false,
                         exclusiveCreate: Bool = false, copy: ((UnsafeMutableRawPointer) -> Void)? = nil,
                         _ start: (UnsafeMutableRawPointer) -> Int32) throws -> Reply {
        try checkCancellation()
        guard let context else { throw SMBFailure.connection }
        let reply = Reply()
        reply.copy = copy
        let pointer = Unmanaged.passRetained(reply).toOpaque()
        defer { Unmanaged<Reply>.fromOpaque(pointer).release() }
        do {
            try service(start(pointer))
            let deadline = Date().addingTimeInterval(operationTimeout ?? timeout)
            var nextConnect: Date?
            while !reply.done {
                try checkCancellation()
                guard Date() < deadline else { throw SMBFailure.timeout }
                var count = 0
                var connectTimeout: Int32 = -1
                let fds = smb2_get_fds(context, &count, &connectTimeout)
                var polls = (0..<count).map { pollfd(fd: fds![$0], events: Int16(smb2_which_events(context)), revents: 0) }
                let ready = poll(&polls, nfds_t(count), 50)
                if ready < 0 && errno != EINTR { throw SMBFailure.connection }
                for fd in polls where fd.revents != 0 {
                    let connecting = context.pointee.fd < 0
                    guard smb2_service_fd(context, fd.fd, Int32(fd.revents)) >= 0 else {
                        throw (connecting ? connectFailure(reply, socket: fd.fd) : nil) ?? SMBFailure.connection
                    }
                    if reply.done { break }
                }
                if !reply.done {
                    if connectTimeout >= 0 && nextConnect == nil {
                        nextConnect = Date().addingTimeInterval(Double(max(50, connectTimeout)) / 1_000)
                    }
                    if let connectionDeadline = nextConnect, connectTimeout >= 0 && Date() >= connectionDeadline {
                        try service(smb2_service_fd(context, -1, 0))
                        nextConnect = nil
                    } else { try service(smb2_service(context, 0)) }
                }
            }
            if !raw { try check(reply.status) }
            return reply
        } catch {
            // Read what the server said before destroying the context: libsmb2 keeps the status it
            // recorded only until `close()` (and doesn't reset it between commands).
            let status = UInt32(bitPattern: smb2_get_nterror(context))
            let failure = handshake ? handshakeFailure(error) : exclusiveCreate ? Self.uploadCreateFailure(error, status: status) : error
            // Destruction invokes outstanding callbacks while Reply and I/O buffers still live.
            close()
            throw failure
        }
    }
    private func checkCancellation() throws { if cancelled() { throw SMBFailure.cancelled } }
    // libsmb2 scheduling/event-loop failures return -1, not an errno status.
    // Only completed command callbacks use the negative-errno contract below.
    private func service(_ status: Int32) throws {
        guard status >= 0 else { throw SMBFailure.connection }
    }
    private func check(_ status: Int32) throws {
        guard status >= 0 else { throw Self.failure(errno: -status) }
    }
    // ECONNREFUSED is also what libsmb2 reports for STATUS_LOGON_FAILURE; `handshakeFailure`
    // corrects that case from the recorded NT status.
    private static func failure(errno value: Int32) -> SMBFailure {
        switch value {
        case EACCES: return .authentication
        case EPERM: return .accessDenied
        case EEXIST: return .exists
        case ETIMEDOUT: return .timeout
        case ECONNREFUSED, ENETUNREACH, EHOSTUNREACH: return .port
        case ENOTSUP: return .unsupported
        default: return .connection
        }
    }
    /// Refines a failed connect command before its context is destroyed (#249). When a server
    /// rejects SESSION_SETUP, libsmb2 records the NT status and closes the connection. The failure
    /// then reaches Swift as an event-loop error (`.connection`). Through the errno table,
    /// STATUS_LOGON_FAILURE would also read as a refused port (ECONNREFUSED), and several account
    /// statuses as EIO. A recorded login rejection after NEGOTIATE is `.authentication` and ends the
    /// connect, so the same credentials are not sent to the server's other addresses. Every other
    /// failure, with or without a status (a share's ACCESS_DENIED, a reset, a timeout), keeps the
    /// address fallback, as it can depend on the address or the path.
    private func handshakeFailure(_ error: Error) -> Error {
        guard let context, smb2_get_dialect(context) != 0,
              Self.loginRejections.contains(UInt32(bitPattern: smb2_get_nterror(context))) else { return error }
        loginRejected = true
        return SMBFailure.authentication
    }
    /// Refines a failed exclusive create of an upload (#329), from the status libsmb2 recorded, which
    /// `command` reads before it destroys the context. Samba (most NAS) answers a file create over a
    /// folder of the same name with STATUS_FILE_IS_A_DIRECTORY, which libsmb2 maps to EPERM and so
    /// to `.accessDenied`; Windows answers STATUS_OBJECT_NAME_COLLISION, which reads as `.exists`.
    /// Either way the name is taken, so the upload's walk moves on to "name (1)", as on Windows, and
    /// nothing was created to remove. Only a create that itself completed with EPERM is refined:
    /// a cancel, a deadline or a lost connection keeps its failure whatever status is recorded, and
    /// EPERM with another status (PRIVILEGE_NOT_HELD, CANNOT_DELETE, FILE_DELETED…) stays
    /// `.accessDenied`. Downloads and previews that meet a folder keep their own failure.
    static func uploadCreateFailure(_ error: Error, status: UInt32?) -> Error {
        guard error as? SMBFailure == .accessDenied, status == fileIsADirectory else { return error }
        return SMBFailure.exists
    }
    /// STATUS_FILE_IS_A_DIRECTORY.
    static let fileIsADirectory: UInt32 = 0xC00000BA
    /// NT statuses with which a server rejects the credentials or the account at SESSION_SETUP.
    /// STATUS_ACCESS_DENIED is deliberately absent: servers send it for a share the user may not
    /// open (TREE_CONNECT), which can depend on the address used, not for a wrong password.
    static let loginRejections: Set<UInt32> = [
        0xC0000064, // STATUS_NO_SUCH_USER
        0xC000006A, // STATUS_WRONG_PASSWORD
        0xC000006D, // STATUS_LOGON_FAILURE
        0xC000006E, // STATUS_ACCOUNT_RESTRICTION
        0xC000006F, // STATUS_INVALID_LOGON_HOURS
        0xC0000070, // STATUS_INVALID_WORKSTATION
        0xC0000071, // STATUS_PASSWORD_EXPIRED
        0xC0000072, // STATUS_ACCOUNT_DISABLED
        0xC000015B, // STATUS_LOGON_TYPE_NOT_GRANTED
        0xC0000193, // STATUS_ACCOUNT_EXPIRED
        0xC0000224, // STATUS_PASSWORD_MUST_CHANGE
        0xC0000234  // STATUS_ACCOUNT_LOCKED_OUT
    ]
    // A failed TCP connect is an event-loop failure (-1) too. libsmb2 completes the command with the
    // errno on POLLERR/POLLOUT, but Darwin polls a refused connect as POLLHUP alone: libsmb2 then
    // returns without reading the socket error or completing the command, and the socket stays in
    // its connecting list until the context is destroyed. Recover the errno from either, so a
    // refused port reads as `.port`. Nil when there is no connect errno (e.g. accepted, then closed).
    private func connectFailure(_ reply: Reply, socket: Int32) -> SMBFailure? {
        if reply.done { return reply.status < 0 ? Self.failure(errno: -reply.status) : nil }
        guard let context, context.pointee.fd < 0 else { return nil }
        var count = 0
        var connectTimeout: Int32 = -1
        // Read SO_ERROR only from a socket libsmb2 still owns; it closes the ones it gives up on.
        guard let fds = smb2_get_fds(context, &count, &connectTimeout), (0..<count).contains(where: { fds[$0] == socket })
        else { return nil }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error != 0 else { return nil }
        return Self.failure(errno: error)
    }
}
