# Accepted vulnerabilities in release images

The release gate is "zero critical and zero fixable high in either final image".
Both images meet it.
What remains is a set of high-severity advisories for which the distribution has published no patch, so there is nothing to upgrade to.
This file is the written record the gate requires: what is left, why it is not reachable, what stops it if that judgement is wrong, who owns it, and when the acceptance expires.

An entry that reaches its expiry date is treated as a failing gate, not as a stale document.
Re-running the scan is the renewal process: if the vendor has since published a fix, the fix ships and the entry is deleted.

**Owner:** release owner.
**Accepted on:** 2026-08-03, against candidate `d4278a6` plus the SP-1 image hardening.
**Expires:** 2026-11-01.

## Scope

`leaflyst-web` carries no critical or high finding at all after SP-1, so it has no entries.

`leaflyst-python` carries 15 high findings across four advisories.
All 15 are vendor-unfixed on Debian 13: Trivy reports no `FixedVersion` for any of them.
None is critical.

## The advisories

### CVE-2026-53615 - util-linux

Affects `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount`, `util-linux` (9 of the 15).

*Reachability.*
The application never executes a util-linux binary.
It runs `uvicorn`, the scanner and rules workers, and `infra/migrate.py`, none of which shell out.
The container `CMD` is an exec-form array, so no shell is started even at PID 1.
`libuuid1` and `libblkid1` are linked by system tooling rather than by the Python runtime.

*Compensating control.*
The image previously shipped `mount` and `umount` setuid-root and reachable by the application user, which would have made this advisory a genuine local escalation path.
The build now strips every setuid and setgid bit in the image, verified after each build.
The process also runs as uid 10001 with no home directory and `/usr/sbin/nologin` as its shell.

### CVE-2025-69720 - ncurses

Affects `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` (4 of the 15).

*Reachability.*
Nothing in the workspace imports `curses` or `readline`, and the CPython binary in this image does not link ncurses.
The library is present only because Debian's base layer includes it.
Exploitation requires feeding attacker-controlled terminal data to an ncurses consumer, and this image runs no interactive terminal program.

*Compensating control.*
No terminal is attached to the runtime container, and the application user cannot start one that matters, since setuid binaries are stripped.

### CVE-2026-41992 - gzip

*Reachability.*
The `/usr/bin/gzip` binary is never executed.
Python compresses through its own `zlib` and `gzip` module bindings, which are CPython code against `libz`, not calls into this package.

*Compensating control.*
Untrusted archives are never written to disk and decompressed by a subprocess anywhere in the ingest or scan path.

### CVE-2026-54369 - libacl1

*Reachability.*
Linked by coreutils, not by the application.
The runtime performs no POSIX ACL manipulation.

*Compensating control.*
The container filesystem is not shared with another tenant or another workload, so an ACL parsing defect has no boundary to cross.

## What was fixed rather than accepted

For the record, and so that this list is not mistaken for the whole picture:

- the six criticals in the Python image were removed by moving to `python:3.12-slim-trixie` and purging `perl-base`, which is Debian-Essential but has no consumer in this runtime;
- the two fixable OpenSSL highs in the web image were closed by upgrading in the final stage;
- the two vendor-unfixed gstreamer highs were removed by purging the package, after confirming Chromium still renders report PDFs without it; and
- the npm, npx, yarn, and corepack tooling was removed from the web runtime, closing the condition behind SEC-B01 rather than waiting for the base image to stay clean.
