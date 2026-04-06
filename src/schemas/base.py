"""Base schema with automatic JSON string parsing for DB compatibility.

SQLAlchemy JSON columns store Python objects as JSON strings in some backends.
When Pydantic reads these via from_attributes, it gets strings like '["a","b"]'
instead of actual lists. This base model auto-parses them.
"""

import json
from typing import Any

from pydantic import BaseModel, model_validator


def _parse_value(value: Any) -> Any:
    """Parse a JSON string value to its Python equivalent."""
    if isinstance(value, str) and value and value[0] in ('[', '{'):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            pass
    return value


class DBModel(BaseModel):
    """Base model for DB response schemas that auto-parses JSON string fields.

    Handles both dict input and ORM objects (from_attributes).
    Automatically converts JSON strings to lists/dicts.
    """

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: _parse_value(v) for k, v in data.items()}

        # For ORM objects: convert to dict first, then parse
        if hasattr(data, "__dict__"):
            result = {}
            for key in cls.model_fields:
                try:
                    val = getattr(data, key, None)
                    result[key] = _parse_value(val)
                except Exception:
                    result[key] = None
            return result

        return data

    class Config:
        from_attributes = True
