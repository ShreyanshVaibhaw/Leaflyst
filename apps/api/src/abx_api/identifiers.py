"""One shape for every identifier that reaches a UUID column (SEC-B07).

Every tenant and object id in this API is a Postgres UUID. Passing a string
that is not one does not fail politely: psycopg raises on the cast, which
surfaces as a 500. That is wrong twice over. It tells a caller that malformed
input reached the database, and it turns an ordinary client mistake into an
error-rate signal indistinguishable from a real fault.

Validation lives here rather than in each handler because there are 78 places
that take a tenant id, and a rule enforced in 78 places is a rule enforced in
77 places by the end of the quarter. Tenant ids are checked once inside the
capability guard that every guarded route already depends on; object ids use
the annotated type below, which makes the constraint part of the published
OpenAPI document rather than a runtime surprise.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import Path

UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
_UUID = re.compile(UUID_PATTERN)

#: A path parameter naming a row by its UUID primary key. FastAPI rejects a
#: non-matching value with the documented 422 before the handler runs.
ResourceId = Annotated[str, Path(pattern=UUID_PATTERN)]

#: An agent is named, not numbered: `events.agent_id` is a ClickHouse String
#: holding whatever the SDK or tap reported, such as "pocketos-sandbox". It is
#: bounded rather than pattern-matched, because constraining the shape of a name
#: the customer chooses would reject legitimate agents. The value only ever
#: reaches the database as a bound query parameter.
AgentName = Annotated[str, Path(min_length=1, max_length=256)]


def is_uuid(value: str) -> bool:
    return bool(_UUID.match(value))
