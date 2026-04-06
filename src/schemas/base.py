"""Base schema with automatic JSON string parsing for DB compatibility."""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Base model that auto-parses JSON string fields from ORM objects."""

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        # Convert ORM object to dict
        if not isinstance(data, dict) and hasattr(data, "__dict__"):
            raw = {}
            for key in cls.model_fields:
                try:
                    val = getattr(data, key, None)
                    # Ensure we never store exception objects as values
                    if isinstance(val, Exception):
                        continue
                    if val is not None:
                        raw[key] = val
                except Exception:
                    continue
            data = raw

        if isinstance(data, dict):
            for key, value in list(data.items()):
                if isinstance(value, str) and len(value) >= 2 and value[0] in ('[', '{'):
                    try:
                        data[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass
                # Safety: never allow exception objects in values
                if isinstance(data[key], Exception):
                    del data[key]

        return data

    class Config:
        from_attributes = True
