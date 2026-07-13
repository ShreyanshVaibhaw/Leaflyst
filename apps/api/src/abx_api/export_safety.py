"""Keep untrusted values inert when opened in spreadsheet applications."""

from __future__ import annotations

from typing import Any


def csv_cell(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
