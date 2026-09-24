# NativeSMB

## Source and licence

NativeSMB is the SMB module of Photo Transfer for iOS. The app ships it as a separate
dynamic framework, `NativeSMB.framework`. This package is its complete source:
`Sources/CSMB` is libsmb2 with the local changes listed below, and `Sources/NativeSMB` is
the Swift adapter.

- libsmb2 is © Ronnie Sahlberg and contributors, licensed under the GNU Lesser General Public
  License 2.1 or later (`COPYING`, `LICENCE-LGPL-2.1.txt`). Each file changed by Mobileware
  Studio carries a dated notice.
- The Swift adapter and the tests are © Mobileware Studio and are distributed under the same
  LGPL 2.1-or-later terms.
- Published at https://github.com/mobileware-studio/photo-transfer-nativesmb, with a tag for
  every app version that ships it (for example `ios-10.5.0`). You can rebuild the framework
  from this source and replace it under the terms of the LGPL.

## Implementation

A dynamically linked, bounded SMB2/3 adapter for Photo Transfer. The C sources are
vendored from libsmb2 `aedafb2c8742c83188e27841e270fdaad6035d41`, the revision used by
AMSMB2 `90737c486c9d1a6ed1c1d4307060587c7bb0dfec`. Upstream:
https://github.com/sahlberg/libsmb2 . See COPYING and each source file for licenses.
Only `include/` and C/header files from `lib/` are included. No network dependency
resolution is needed. The Swift package product is explicitly dynamic.

Local patches to lib/libsmb2.c: authenticated connections reject guest/null session
fallback before TREE_CONNECT; DFS trees are rejected and share-required encryption
is honored; file and directory opens do not share write/delete
access and open final reparse points themselves. The adapter retains guarded
ancestor-directory handles and rejects reparse points. The public API does not
expose delete, rename, DFS referrals, cached credentials, or SMB1.

Local patches to lib/init.c and include/libsmb2-private.h: active-context list
insertion/removal/membership checks are locked; local file handles are tracked by
context and freed after outstanding callbacks drain. The upstream server-only
active-context enumerator is unused by this client (the server API is not exposed).

Local patch to lib/socket.c: require the negotiated signing/encryption policy on
received application replies before invoking client callbacks.

All libsmb2 context access stays on one worker. Cancellation is a lock-protected
signal sampled by bounded DNS and SMB event loops; context destruction drains
callbacks before the worker completes. No other thread closes or reuses its fd.

Server names are resolved with one `DNSServiceGetAddrInfo` query per address family,
with `kDNSServiceFlagsReturnIntermediates` so that "no such record" answers arrive
(`SMBNameResolution.swift`). A lookup ends when both families have answered, 250 ms
after the first usable address (mDNS may never answer for a family a host lacks),
or with `SMBFailure.host` when no address can be found, within min(timeout, 5 s).
A refused TCP connect keeps its errno and fails as `SMBFailure.port`.

`swift test` in this directory runs the package tests on macOS. Tests that use the
system resolver (and nip.io) are opt-in: `NATIVESMB_REAL_DNS=1 swift test`.
