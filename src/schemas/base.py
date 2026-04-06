"""Base schema with automatic JSON string parsing for DB compatibility.

SQLAlchemy JSON columns sometimes return Python objects as JSON strings.
This base model handles parsing them back to native Python types.
"""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Base model that auto-parses JSON string fields when input is a dict.

    For ORM objects (from_attributes), Pydantic handles attribute access
    natively. The JSON parsing only applies to dict input.
    """

    @model_validator(mode="before")
    @classmethod
    def parse_json_strings(cls, data: Any) -> Any:
        # Only parse dict input — let Pydantic handle ORM objects via from_attributes
        if not isinstance(data, dict):
            return data

        parsed = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 1 and value[0] in ('[', '{'):
                try:
                    parsed[key] = json.loads(value)
                except (json.JSONDecodeError, ValueError, TypeError):
                    parsed[key] = value
            else:
                parsed[key] = value
        return parsed

    class Config:
        from_attributes = True
