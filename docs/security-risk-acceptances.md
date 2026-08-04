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

```text
astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9
pnpm/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86
docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c
anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610
```

Each entry names one commit, so the allowlist constrains which revision runs rather than only which repository it comes from.

The subpath entry is spelled out in full because `anchore/sbom-action` does not match `anchore/sbom-action/download-syft`; the parent pattern alone gets the workflow refused before any job starts.

SHA pinning is enforced at the platform level, so a workflow referencing an action by mutable tag is refused before it runs rather than caught in review.
That makes the pinning discipline a property of the repository instead of a convention someone has to remember.

Both halves were verified against a real dispatch rather than inferred from the settings page.
A throwaway branch running every one of these actions at the pinned SHAs completed normally; the same workflow with `astral-sh/setup-uv` swapped to a different legitimate revision of the same action was refused with `startup_failure` before any job began.
Accepting a pattern at write time and matching it at dispatch are different things, and only the second one is a control.

The cost is real and worth stating: upgrading an action is now a two-place change, the workflow and the allowlist, and forgetting either one fails at dispatch rather than in review.
That failure is loud, which is the intended trade.

Adding a new third-party action is a two-part change: the workflow edit, and an allowlist entry.
GitHub-owned actions need only the workflow edit, since they are permitted as a class.

### What these controls do not cover

Nothing binds a check *name* to check *content*.
A single pull request can rewrite `.github/workflows/ci.yml` and still report four green checks of the right names from the right app.
The platform fix is an organization-only ruleset rule, unavailable to a user-owned repository, so the current mitigation is that exactly one account has write access.

## An encoded secret is not decoded and rescanned

Accepted 2026-08-05, owner: repository maintainer, expires 2027-02-05.

Redaction matches patterns against text as written.
A secret that has been base64-, hex-, or otherwise encoded before it reaches the recorder does not match, and is stored.

The evasions that only change how the secret is *written* are caught rather than accepted.
A token carrying a zero-width space, a soft hyphen, a combining mark, a bidirectional override, or a full-width homoglyph prefix now folds to its canonical form for matching, and the match redacts the exact span in the original text.
Those arrive by accident, which is precisely the case redaction exists for: copying a credential out of a rendered page or a terminal picks up invisible characters silently.

Encoding is different, and the difference is why it is accepted rather than fixed.
Catching it means decoding every base64-shaped run in every payload and rescanning, at every nesting level.
This product records a large volume of legitimately encoded data, so that turns a recorder into something that rewrites its own evidence on a guess about what a byte sequence means.
A false positive there destroys the record an incident depends on, and the failure is silent.

The compensating control is that payload bodies are envelope-encrypted at rest with a per-payload data key, and reachable only through tenant-scoped, capability-checked routes.
An encoded secret in a stored payload is not readable without an authorised token for that tenant.
That is weaker than redaction: redaction means the secret was never written down, while this means it was written down and access-controlled.
The distinction is the whole reason this is recorded here rather than left implied.

`test_an_encoded_secret_is_not_decoded_and_rescanned` asserts the current behaviour, so if a future rule does start catching an encoded form, the test fails and this acceptance gets revisited rather than quietly outliving its reason.

## A secret split across separate fields is not reassembled

Accepted 2026-08-05, owner: repository maintainer, expires 2027-02-05.

Neither half of a split token is a credential.
`ghp_` followed by eighteen characters matches no rule and authenticates nowhere.
Detecting the split would mean concatenating every combination of every field and rescanning, which is quadratic in the number of fields and still misses a split across two events.

It is also the wrong threat model.
Redaction protects against a secret reaching the record by accident.
Splitting one across fields is not something an agent does by accident; it is something an attacker does deliberately, and an attacker doing it already holds the secret.
They gain nothing by storing half of it in a system they must authenticate to read back.

`test_a_secret_split_across_fields_is_not_reassembled` asserts that neither half matches a rule, so the reasoning above stays true or the test fails.
