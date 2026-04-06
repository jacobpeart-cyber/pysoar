"""Base schema with automatic JSON string parsing for DB compatibility.

SQLAlchemy JSON columns store Python objects as JSON strings in some backends.
When Pydantic reads these via from_attributes, it gets strings like '["a","b"]'
instead of actual lists. This base model auto-parses them.
"""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Base model for DB response schemas that auto-parses JSON string fields.

    Use this instead of BaseModel for any Response schema with from_attributes = True.
    It automatically converts JSON strings to their Python equivalents (list, dict).
    """

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        if isinstance(data, dict):
            parsed = {}
            for key, value in data.items():
                if isinstance(value, str) and value and value[0] in ('[', '{'):
                    try:
                        parsed[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        parsed[key] = value
                else:
                    parsed[key] = value
            return parsed
        # For ORM objects, let Pydantic handle attribute access —
        # the field validators will catch JSON strings on individual fields
        return data

    class Config:
        from_attributes = True
