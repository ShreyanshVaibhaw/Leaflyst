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

## Repository controls

These live in GitHub's settings rather than in the tree, so they are recorded here.
A control that exists only in a web UI is one nobody can review in a pull request, and one nobody notices being switched off.

### Rulesets

`protect-main` (branch, active) applies to the default branch: block deletion, block force-push, require a pull request, and require the `python`, `web`, `supply-chain`, and `containers` checks, each pinned to the GitHub Actions app so a status of the same name from another source cannot satisfy them.
Branches must be up to date with the base before merging, so a pull request cannot be merged against a base that predates a newly added check.

`immutable-tags` (tag, active) blocks deletion and force-movement of every tag, which keeps a published release tag pointing at the code it was cut from.

The bypass actor on `protect-main` is the repository admin role, scoped to `pull_request` rather than `always`.
This is deliberate and load-bearing.
A pull-request-scoped bypass can only be exercised by merging a pull request, and merging a pull request cannot force-push or delete the protected base branch, so rewriting the history of `main` stays closed to everyone while an emergency merge past a red check stays possible and leaves a durable record.

Two limits on that guarantee, stated so the sentence above is not read more broadly than it holds.
Merging still deletes the pull request's own head branch when automatic head-branch deletion is on, because a topic branch is not a protected ref.
And the guarantee holds only while the ruleset is active: an actor with the Administration permission can edit or disable it, which is precisely why the day-to-day token is being narrowed to exclude that permission.
The alternative, an empty bypass list, sounds stronger but is weaker in practice: bypass is per-ruleset rather than per-rule, so the only emergency lever would be disabling the whole ruleset, dropping force-push protection and every required check at once.

### Actions policy

Default workflow token permissions are read-only, and workflows may not approve pull requests.

Actions are restricted to an allowlist: GitHub-owned actions, plus exactly these third-party patterns and nothing else.

```
astral-sh/setup-uv@*
pnpm/action-setup@*
docker/setup-buildx-action@*
anchore/sbom-action@*
anchore/sbom-action/*@*
```

The last pattern is not redundant. `anchore/sbom-action/download-syft` is an action in a subdirectory, and `anchore/sbom-action@*` does not match it; without the subpath pattern the workflow is refused before any job starts.

SHA pinning is enforced at the platform level, so a workflow referencing an action by mutable tag is refused before it runs rather than caught in review.
That makes the pinning discipline a property of the repository instead of a convention someone has to remember.

The residual gap is deliberate and worth naming: the `@*` suffix admits *any* revision of those four repositories, so platform enforcement guarantees a commit SHA is used without constraining which one.
An upstream account compromise followed by a workflow edit to the malicious SHA would still be permitted.
Pinning each allowlist entry to the exact SHA in `ci.yml` would close that, at the cost of every action upgrade becoming a two-place change that fails at dispatch if either place is forgotten.

Adding a new third-party action is a two-part change: the workflow edit, and an allowlist entry.
GitHub-owned actions need only the workflow edit, since they are permitted as a class.

### What these controls do not cover

Nothing binds a check *name* to check *content*.
A single pull request can rewrite `.github/workflows/ci.yml` and still report four green checks of the right names from the right app.
The platform fix is an organization-only ruleset rule, unavailable to a user-owned repository, so the current mitigation is that exactly one account has write access.
