"""Redaction at ingest (blueprint 4.3). Non-negotiable and non-skippable.

Order inside the collector: scrub -> truncate -> digest -> split.
Matches become [REDACTED:<rule>:<last4>] so incidents remain investigable
(the last 4 characters let a responder correlate with a known credential)
without ever storing the secret.

Pattern-based rules only at MVP; entropy detection is a v0.2 improvement.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    # Which regex group holds the secret itself (0 = whole match).
    secret_group: int = 0


# Trailing \b anchors are deliberately absent on token rules: a secret glued to
# other text must still be caught. Over-redaction is acceptable; leakage is not.
RULES: list[Rule] = [
    Rule("aws-access-key-id", re.compile(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}")),
    Rule(
        "aws-secret-key",
        re.compile(
            r"""(?ix)
            aws [^\n]{0,30}? (?:secret|private) [^\n]{0,15}?
            ['"=:\s] \s* ['"]?
            (?P<secret>[A-Za-z0-9/+=]{40}) (?![A-Za-z0-9/+=])
            """,
        ),
        secret_group=1,
    ),
    Rule(
        "github-token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}"),
    ),
    Rule(
        "github-fine-grained-pat",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
    ),
    Rule("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,250}")),
    Rule(
        "jwt",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    Rule(
        "pem-private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    Rule(
        "authorization-header",
        re.compile(
            r"(?i)\bauthorization['\"]?\s*[=:]\s*['\"]?(?:Bearer|Basic|token)\s+"
            r"(?P<secret>[A-Za-z0-9._~+/=-]{8,})",
        ),
        secret_group=1,
    ),
    Rule(
        "connection-string-password",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^:/\s]+:(?P<secret>[^@/\s]+)@",
        ),
        secret_group=1,
    ),
    Rule(
        "generic-api-key-assignment",
        re.compile(
            r"""(?ix)
            [A-Za-z0-9_-]* (?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|client[_-]?secret)
            ['"]? \s* [=:] \s* ['"]?
            (?P<secret>[A-Za-z0-9_\-./+=]{16,}) (?!['\"A-Za-z0-9_\-./+=])
            """,
        ),
        secret_group=1,
    ),
]


def _replacement(rule: Rule, secret: str) -> str:
    return f"[REDACTED:{rule.id}:{secret[-4:]}]"


#: Rules whose match is an IDENTIFIER rather than a secret. An AWS access key id
#: (AKIA...) is the public half of the pair; the scanner stores it verbatim as
#: credentials.fingerprint, and the replay timeline joins events to credentials
#: on exactly that value. Scrubbing it out of a credential reference would break
#: the join while protecting nothing, so callers that are scrubbing a reference
#: rather than free text exclude these.
IDENTIFIER_RULE_IDS = frozenset({"aws-access-key-id"})

SECRET_RULES: Sequence[Rule] = [r for r in RULES if r.id not in IDENTIFIER_RULE_IDS]


def redact(text: str, rules: Sequence[Rule] = RULES) -> tuple[str, list[str]]:
    """Apply every rule; returns (scrubbed text, ordered unique rule ids that fired)."""
    fired: list[str] = []
    for rule in rules:

        def sub(m: re.Match[str], rule: Rule = rule) -> str:
            secret = m.group(rule.secret_group)
            # Replace only the secret portion, keep surrounding context.
            start, end = m.span(rule.secret_group)
            whole_start = m.span(0)[0]
            s = m.group(0)
            return (
                s[: start - whole_start]
                + _replacement(rule, secret)
                + s[end - whole_start :]
            )

        text, n = rule.pattern.subn(sub, text)
        if n:
            fired.append(rule.id)
    return text, fired


def redact_and_truncate(text: str, max_bytes: int) -> tuple[bytes, list[str], bool]:
    """Full payload pipeline before digest: scrub, then cap size.

    Returns (payload bytes, redaction rule ids, truncated flag).
    Truncation happens AFTER redaction so a secret can never survive by
    straddling the cut.
    """
    scrubbed, fired = redact(text)
    body = scrubbed.encode("utf-8")
    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]
    return body, fired, truncated
