"""Base schema with automatic JSON string parsing for DB compatibility."""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Base model that auto-parses JSON string fields from ORM objects.

    Converts ORM objects to dicts, parses JSON strings like '[]' and '{}',
    and includes all field values (even None) so required fields don't fail.
    """

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        # Convert ORM object to dict
        if not isinstance(data, dict) and hasattr(data, "__dict__"):
            raw = {}
            for key in cls.model_fields:
                try:
                    val = getattr(data, key, None)
                    if isinstance(val, Exception):
                        raw[key] = None
                    else:
                        raw[key] = val
                except Exception:
                    raw[key] = None
            data = raw

        if isinstance(data, dict):
            for key in list(data.keys()):
                value = data[key]
                if isinstance(value, str) and len(value) >= 2 and value[0] in ('[', '{'):
                    try:
                        data[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass
                if isinstance(value, Exception):
                    data[key] = None

        return data

    class Config:
        from_attributes = True
