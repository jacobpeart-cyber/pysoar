"""Base schema with automatic JSON string parsing for DB compatibility.

SQLAlchemy JSON columns sometimes store '[]' and '{}' as literal strings
instead of Python lists/dicts. This base model handles parsing them.
"""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Base model that auto-parses JSON string fields from both dicts and ORM objects."""

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        # Convert ORM object to dict so we can parse JSON strings
        if not isinstance(data, dict) and hasattr(data, "__dict__"):
            raw = {}
            for key in cls.model_fields:
                try:
                    raw[key] = getattr(data, key)
                except Exception:
                    pass  # Skip fields that trigger lazy loading errors
            data = raw

        if isinstance(data, dict):
            parsed = {}
            for key, value in data.items():
                if value is None:
                    # Skip None — let Pydantic field defaults apply
                    continue
                if isinstance(value, str) and len(value) >= 2 and value[0] in ('[', '{'):
                    try:
                        parsed[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        parsed[key] = value
                else:
                    parsed[key] = value
            return parsed

        return data

    class Config:
        from_attributes = True
