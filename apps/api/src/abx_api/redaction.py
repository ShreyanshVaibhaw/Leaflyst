"""Redaction at ingest (blueprint 4.3). Non-negotiable and non-skippable.

Order inside the collector: scrub -> truncate -> digest -> split.
Matches become [REDACTED:<rule>:<last4>] so incidents remain investigable
(the last 4 characters let a responder correlate with a known credential)
without ever storing the secret.

Pattern-based rules only at MVP; entropy detection is a v0.2 improvement.
"""

from __future__ import annotations

import re
import unicodedata
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


#: Characters that render as nothing but break a regex in half.
#:
#: Unicode category Cf is format characters - zero-width space and joiners, the
#: bidirectional overrides, the byte-order mark. Soft hyphen is Cf too. A token
#: with one of these in the middle looks identical to the real thing on screen
#: and to anyone who pastes it, but `ghp_[A-Za-z0-9]{36}` no longer matches it.
#: They arrive by accident far more often than by attack: copying a credential
#: out of a rendered web page or a terminal picks them up silently.
def _is_invisible(char: str) -> bool:
    return unicodedata.category(char) in {"Cf", "Mn"}


def _fold(text: str) -> tuple[str, list[int]]:
    """Return (searchable text, index of each character in the original).

    NFKC collapses compatibility forms, so a full-width or otherwise confusable
    prefix folds to the ASCII the rules are written against. Invisible
    characters are dropped outright.

    The index map is the point. Matching on a folded copy and then scrubbing
    that copy would leave the ORIGINAL - the thing actually stored - still
    carrying the secret. The map lets a match found in folded space redact the
    exact original span, so what gets written is the real text with the real
    secret removed.
    """
    folded: list[str] = []
    origin: list[int] = []
    for index, char in enumerate(text):
        if _is_invisible(char):
            continue
        replacement = unicodedata.normalize("NFKC", char)
        # NFKC can expand one character into several; every piece points back
        # at the single original character it came from.
        for piece in replacement:
            folded.append(piece)
            origin.append(index)
    return "".join(folded), origin


def _redact_via_folding(text: str, rules: Sequence[Rule]) -> tuple[str, list[str]]:
    """Catch secrets that only fail to match because of how they are written."""
    folded, origin = _fold(text)
    if folded == text:
        return text, []  # nothing was folded, so the direct pass already saw it

    spans: list[tuple[int, int, Rule, str]] = []
    fired: list[str] = []
    for rule in rules:
        for match in rule.pattern.finditer(folded):
            start, end = match.span(rule.secret_group)
            if start < 0 or end <= start:
                continue
            spans.append((origin[start], origin[end - 1] + 1, rule,
                          match.group(rule.secret_group)))
            if rule.id not in fired:
                fired.append(rule.id)
    if not spans:
        return text, []

    # Right to left so earlier offsets stay valid as the string is rewritten.
    scrubbed = text
    for start, end, rule, secret in sorted(spans, reverse=True):
        scrubbed = scrubbed[:start] + _replacement(rule, secret) + scrubbed[end:]
    return scrubbed, fired


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

    # Second pass for anything written so it would not match the first. Run
    # after, not instead: the direct pass is exact, and this one only sees what
    # survived it.
    text, folded_fired = _redact_via_folding(text, rules)
    for rule_id in folded_fired:
        if rule_id not in fired:
            fired.append(rule_id)
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
