#!/usr/bin/env python3
"""Opt-in SMB2 fault fixture for the #267 upload-cleanup tests (SMBUploadCleanupFaultTests, Packages/NativeSMB).

The stock Impacket fixture (smb_server.py in the Android repo) plus scripted answers to the cleanup's
delete-open: a CREATE of an existing file with DELETE access. Same share, user and password
(Photos / alice / fixture-password), so run it from the same virtualenv (impacket 0.13.1):

    python smb_fault_server.py --root /tmp/smb-fault-share --port 1446
    SMB_FAULT_FIXTURE=1 swift test        # in Packages/NativeSMB

The file NAME scripts what the server answers; every other request is stock Impacket:
  *.busy3.*   STATUS_SHARING_VIOLATION to the first three delete-opens of that name, then normal
  *.stuck.*   STATUS_SHARING_VIOLATION to every delete-open of that name
  *.link.*    a FILE_OPEN_REPARSE_POINT open of that name reports FILE_ATTRIBUTE_REPARSE_POINT
and, for the upload's create over a taken name (#329, SMBUploadCreateFaultTests):
  *.folder.*  an exclusive create (FILE_CREATE, of a file or a folder) of that name answers STATUS_FILE_IS_A_DIRECTORY, as
              Samba does for a file create over a folder of that name (Impacket answers a name collision there). Any later
              delete-open of the name (the interrupted-upload removal, #267) leaves an empty marker file
              `delete-open-seen-<name>` in the root.
  *.perm.*    an exclusive create of that name answers STATUS_PRIVILEGE_NOT_HELD: libsmb2 maps it to EPERM too, like the
              folder status, but it is a real denial
  *.writedir.* the first WRITE to that name answers STATUS_FILE_IS_A_DIRECTORY, after a normal create
Disposable loopback test double: no production files or credentials.
"""
import argparse
import threading
from pathlib import Path
from impacket import smbserver, ntlm
from impacket import smb3structs as smb2
from impacket.nt_errors import STATUS_SHARING_VIOLATION, STATUS_FILE_IS_A_DIRECTORY, STATUS_PRIVILEGE_NOT_HELD

DELETE = 0x00010000
REPARSE_POINT = 0x400

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--port', type=int, default=1446)
args = parser.parse_args()

# Impacket 0.13.1 passes config strings directly to NDR integers, reporting IPC$ as a disk.
class TypedShareServer(smbserver.SRVSServer):
    def NetrShareEnum(self, data):
        for share in self._shares.values():
            share['share type'] = int(share['share type'])
        return super().NetrShareEnum(data)

smbserver.SRVSServer = TypedShareServer

refused = {}
lock = threading.Lock()
stock_create = smbserver.SMB2Commands.smb2Create

def create(connId, smbServer, recvPacket):
    request = smb2.SMB2Create(recvPacket['Data'])
    name = request['Buffer'][:request['NameLength']].decode('utf-16le')
    opens_existing = request['CreateDisposition'] == smb2.FILE_OPEN
    if request['CreateDisposition'] == smb2.FILE_CREATE:
        if '.folder.' in name:
            return [smb2.SMB2Error()], None, STATUS_FILE_IS_A_DIRECTORY
        if '.perm.' in name:
            return [smb2.SMB2Error()], None, STATUS_PRIVILEGE_NOT_HELD
    if '.folder.' in name and request['DesiredAccess'] & DELETE:
        (args.root / ('delete-open-seen-' + name)).touch()
    if opens_existing and request['DesiredAccess'] & DELETE:
        with lock:
            seen = refused.get(name, 0)
            if '.stuck.' in name or ('.busy3.' in name and seen < 3):
                refused[name] = seen + 1
                return [smb2.SMB2Error()], None, STATUS_SHARING_VIOLATION
    responses, extra, status = stock_create(connId, smbServer, recvPacket)
    if status == 0 and '.link.' in name and opens_existing and request['CreateOptions'] & smb2.FILE_OPEN_REPARSE_POINT:
        responses[0]['FileAttributes'] = responses[0]['FileAttributes'] | REPARSE_POINT
    return responses, extra, status

smbserver.SMB2Commands.smb2Create = staticmethod(create)

stock_write = smbserver.SMB2Commands.smb2Write

def write(connId, smbServer, recvPacket):
    request = smb2.SMB2Write(recvPacket['Data'])
    opened = smbServer.getConnectionData(connId)['OpenedFiles'].get(request['FileID'].getData())
    if opened is not None and '.writedir.' in str(opened['FileName']):
        return [smb2.SMB2Error()], None, STATUS_FILE_IS_A_DIRECTORY
    return stock_write(connId, smbServer, recvPacket)

smbserver.SMB2Commands.smb2Write = staticmethod(write)

args.root.mkdir(parents=True, exist_ok=True)
server = smbserver.SimpleSMBServer(listenAddress='127.0.0.1', listenPort=args.port)
server.addShare('Photos', str(args.root.resolve()), 'Disposable photo fixture')
server.setSMB2Support(True)
server.addCredential('alice', 0, ntlm.compute_lmhash('fixture-password'), ntlm.compute_nthash('fixture-password'))
print(f'SMB2 fault fixture ready on 127.0.0.1:{args.port}, share Photos', flush=True)
server.start()
