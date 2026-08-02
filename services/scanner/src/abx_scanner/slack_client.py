"""Read-only Slack Enterprise Grid admin client for scanner workers.

Slack's Web API is method-name addressed, not resource-and-verb addressed:
`admin.apps.approve` and `admin.apps.approved.list` are both POST-able to the
same host. So an HTTP-verb check proves nothing here, and the guard is an
explicit allowlist of read-only METHOD NAMES - the same reasoning behind the
botocore operation allowlist in readonly.py.

Anything not on the list raises, which means a stray call to a mutating method
fails loudly instead of changing a customer's workspace.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from abx_scanner.readonly import CallCounter, ReadOnlyViolation

SLACK_ROOT = "https://slack.com/api"

# Read-only Enterprise Grid admin methods. Additions here are a security
# decision, not a convenience one.
ALLOWED_METHODS: frozenset[str] = frozenset({
    "auth.test",
    "admin.apps.approved.list",
    "admin.apps.restricted.list",
    "admin.apps.requests.list",
    "admin.teams.list",
    "team.info",
})


@dataclass
class Response:
    status: int
    body: bytes


Opener = Callable[[str, str], Response]


def _token_opener(token: str) -> Opener:
    import requests

    def open_url(url: str, bearer: str) -> Response:
        response = requests.get(
            url, headers={"Authorization": f"Bearer {bearer}"}, timeout=30
        )
        return Response(status=response.status_code, body=response.content)

    del token
    return open_url


class SlackClient:
    def __init__(
        self,
        token: str,
        opener: Opener | None = None,
        counter: CallCounter | None = None,
    ) -> None:
        self.token = token
        self.opener = opener or _token_opener(token)
        self.counter = counter or CallCounter()

    def call(self, method: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        if method not in ALLOWED_METHODS:
            raise ReadOnlyViolation(
                f"scanner attempted Slack method {method}; only read-only "
                "Enterprise Grid admin methods are permitted"
            )
        query = f"?{urlencode(params)}" if params else ""
        self.counter.increment()
        response = self.opener(f"{SLACK_ROOT}/{method}{query}", self.token)
        if response.status != 200:
            raise SlackError(response.status, response.body.decode("utf-8", "replace")[:500])
        value = json.loads(response.body) if response.body else {}
        if not isinstance(value, dict):
            raise SlackError(response.status, "expected an object response")
        if not value.get("ok", False):
            raise SlackError(response.status, str(value.get("error", "unknown slack error")))
        return value


class SlackError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"slack api {status}: {message}")
        self.status = status
        self.slack_error = message


# Slack returns this when the token's workspace is not on Enterprise Grid.
NOT_ENTERPRISE_ERRORS = frozenset({
    "not_an_enterprise", "enterprise_is_restricted", "not_allowed_token_type",
})
