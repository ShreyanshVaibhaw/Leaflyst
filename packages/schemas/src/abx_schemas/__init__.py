"""Event types generated from the JSON Schemas in schema/.

Never hand-edit the generated modules; change the JSON Schema and run
packages/schemas/scripts/codegen.py (enforced by the CI drift check).

CanonicalEvent is the stored shape (hash-chained, payload split out).
IngestEvent is the producer-facing submission shape (tap, SDK, OTLP).
"""

from abx_schemas.generated.event import (
    CanonicalEvent,
    EventType,
    Operation,
    Outcome,
    Source,
)
from abx_schemas.generated.ingest import (
    EventType as IngestEventType,
)
from abx_schemas.generated.ingest import (
    IngestEvent,
)
from abx_schemas.generated.ingest import (
    Operation as IngestOperation,
)
from abx_schemas.generated.ingest import (
    Outcome as IngestOutcome,
)
from abx_schemas.generated.ingest import (
    Source as IngestSource,
)

__all__ = [
    "CanonicalEvent",
    "EventType",
    "IngestEvent",
    "IngestEventType",
    "IngestOperation",
    "IngestOutcome",
    "IngestSource",
    "Operation",
    "Outcome",
    "Source",
]
