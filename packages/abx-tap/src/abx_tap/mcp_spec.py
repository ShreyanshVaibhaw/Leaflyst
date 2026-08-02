"""MCP wire vocabulary - the ONLY module that knows literal protocol strings.

Same discipline as the SDK's conventions.py for OTel gen_ai.*: the protocol's
names churn, so they live in exactly one place. The 2026-07-28 revision proved
the need by deleting the initialize handshake that everything used to key off.

Two eras, both live (the deprecation window is a minimum of twelve months, so
mixed fleets are normal for at least a year):

- legacy (<= 2025-11-25): an `initialize` handshake carries protocolVersion,
  client capabilities, and server identity once per session.
- modern (>= 2026-07-28): no handshake. Every request carries its own version
  and client identity in `params._meta`; every result may carry server identity
  in `result._meta`. `server/discover` reports supported versions on demand.

Nothing here parses messages; it names things and extracts fields. Callers must
treat every value as untrusted input from a process we do not control.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

# --- _meta keys (2026-07-28) -------------------------------------------------
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
META_SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"

# W3C trace context, now documented by the spec for _meta propagation. This is
# the join between tap-captured MCP traffic and SDK-captured LLM spans.
META_TRACEPARENT = "traceparent"

# --- methods -----------------------------------------------------------------
METHOD_INITIALIZE = "initialize"  # legacy only; removed in 2026-07-28
METHOD_DISCOVER = "server/discover"  # modern; servers MUST implement
METHOD_TOOLS_LIST = "tools/list"
METHOD_SUBSCRIPTIONS_LISTEN = "subscriptions/listen"

# --- error codes -------------------------------------------------------------
# -32020..-32099 is reserved for the MCP spec; -32000..-32019 stays
# implementation-defined.
ERR_HEADER_MISMATCH = -32020
ERR_MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
ERR_UNSUPPORTED_PROTOCOL_VERSION = -32022

# --- result envelope ---------------------------------------------------------
RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"

ERA_MODERN = "modern"
ERA_LEGACY = "legacy"
ERA_UNKNOWN = "unknown"

PROTOCOL_UNKNOWN = "unknown"

# version-traceid-spanid-flags; we want the trace id.
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


# --- Streamable HTTP transport (2026-07-28) ----------------------------------
# Required on every POST so gateways can route and meter without parsing the
# JSON-RPC body. Servers reject requests whose headers and body disagree, which
# closed a class of routing/security mismatch - so a proxy must forward both
# faithfully or it breaks the session it is observing.
HEADER_MCP_METHOD = "Mcp-Method"
HEADER_MCP_NAME = "Mcp-Name"
HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
HEADER_AUTHORIZATION = "Authorization"

# Hop-by-hop headers must not be forwarded; the proxy terminates its own
# connection semantics.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})


def header_matches_body(headers: dict[str, str], body: bytes) -> bool | None:
    """Whether Mcp-Method agrees with the JSON-RPC method in the body.

    Returns None when the check does not apply (no header, or an unparseable
    body - a batch or malformed payload is the server's business, not ours).
    A proxy never REPAIRS a mismatch: the disagreement is the signal, and
    rewriting it would hide an attempt to route one method while executing
    another.
    """
    declared = next(
        (value for key, value in headers.items() if key.lower() == HEADER_MCP_METHOD.lower()),
        None,
    )
    if not declared:
        return None
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(parsed, dict) or "method" not in parsed:
        return None
    return str(parsed["method"]) == declared


def token_fingerprint(authorization: str) -> str | None:
    """Stable, non-reversible reference for a bearer token.

    The tap observes OAuth flows and must never become a credential-laundering
    path: the value is hashed here and the plaintext is never stored, logged,
    or emitted. A fingerprint is enough to prove two requests used the same
    token, which is all the graph needs.
    """
    token = authorization.strip()
    if not token.lower().startswith("bearer "):
        return None
    value = token[7:].strip()
    if not value:
        return None
    return "mcptoken:" + hashlib.sha256(value.encode()).hexdigest()[:32]


def issuer_of(token: str) -> str | None:
    """The `iss` claim of a JWT access token, without verifying the signature.

    Recorded because 2026-07-28 requires clients to key persisted credentials
    by issuer and re-register when the authorization server changes; a token
    whose issuer moves is worth seeing. Unverified by construction - the tap
    does not hold the signing key - so callers must treat it as a claim.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    issuer = claims.get("iss") if isinstance(claims, dict) else None
    return str(issuer) if isinstance(issuer, str) and issuer else None


def audience_of(token: str) -> list[str]:
    """The `aud` claim (RFC 8707 audience binding), unverified."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return []
    if not isinstance(claims, dict):
        return []
    audience = claims.get("aud")
    if isinstance(audience, str):
        return [audience]
    return string_list(audience)


def meta_of(container: Any) -> dict[str, Any]:
    """The `_meta` object of a params or result body, or {} if absent."""
    if isinstance(container, dict):
        meta = container.get("_meta")
        if isinstance(meta, dict):
            return meta
    return {}


def protocol_version_of_request(method: str, params: Any) -> tuple[str | None, str]:
    """(version, era) declared by one request.

    Modern requests declare it in `_meta` on every request. Legacy declares it
    once, in the `initialize` params. Returns (None, ERA_UNKNOWN) when neither
    is present - the caller must say so rather than assuming a version.
    """
    version = meta_of(params).get(META_PROTOCOL_VERSION)
    if isinstance(version, str) and version:
        return version, ERA_MODERN
    if method == METHOD_INITIALIZE and isinstance(params, dict):
        legacy = params.get("protocolVersion")
        if isinstance(legacy, str) and legacy:
            return legacy, ERA_LEGACY
    return None, ERA_UNKNOWN


def result_type(result: Any) -> str:
    """`resultType` of a result body.

    Required from 2026-07-28. Results from earlier-protocol servers omit it and
    MUST be treated as complete.
    """
    if isinstance(result, dict):
        value = result.get("resultType")
        if isinstance(value, str) and value:
            return value
    return RESULT_COMPLETE


def describe_party(info: Any) -> str | None:
    """'name@version' from a clientInfo/serverInfo object.

    Self-reported and unverified: the spec states explicitly that serverInfo is
    not verified by the protocol and must not drive security decisions. Callers
    record it as a claim, never as identity.
    """
    if not isinstance(info, dict):
        return None
    name = info.get("name")
    if not isinstance(name, str) or not name:
        return None
    version = info.get("version")
    return f"{name}@{version}" if isinstance(version, str) and version else name


def trace_id_of(meta: dict[str, Any]) -> str | None:
    """W3C trace id from a `traceparent`, or None if absent/malformed."""
    raw = meta.get(META_TRACEPARENT)
    if not isinstance(raw, str):
        return None
    match = _TRACEPARENT.match(raw.strip().lower())
    return match.group(1) if match else None


def cache_hints(result: Any) -> tuple[int | None, str | None]:
    """`ttlMs` and `cacheScope` from a CacheableResult (2026-07-28).

    These exist so clients cache list results and poll less, which directly
    weakens tool-inventory drift detection: fewer tools/list calls on the wire
    means longer blind windows. Recording the hints lets the server report
    inventory confidence as a function of time since last ground truth instead
    of implying continuous coverage.
    """
    if not isinstance(result, dict):
        return None, None
    ttl = result.get("ttlMs")
    scope = result.get("cacheScope")
    return (
        int(ttl) if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl >= 0 else None,
        scope if isinstance(scope, str) and scope in ("public", "private") else None,
    )


def string_list(value: Any) -> list[str]:
    """Non-empty strings from a value that should be a list of them."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def supported_versions_of(result: Any) -> list[str]:
    """`supportedVersions` from a DiscoverResult."""
    if not isinstance(result, dict):
        return []
    return string_list(result.get("supportedVersions"))
