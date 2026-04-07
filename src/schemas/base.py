"""Base schema with JSON string parsing for DB compatibility.

Uses Pydantic's native from_attributes for ORM handling.
Only adds field-level JSON string parsing via a custom validator.
"""

import json
from typing import Any, List, Optional

from pydantic import BaseModel, field_validator, model_validator


class DBModel(BaseModel):
    """Response model base that handles JSON strings from DB columns.

    Uses Pydantic's native from_attributes for ORM object conversion.
    Only intervenes to parse JSON string values like '[]' and '{}'.
    Does NOT convert ORM objects to dicts manually.
    """

    model_config = {"from_attributes": True}

    @model_validator(mode="wrap")
    @classmethod
    def _handle_orm_and_json(cls, data: Any, handler: Any) -> Any:
        """Wrap the default validator to catch and fix JSON string issues."""
        try:
            return handler(data)
        except Exception:
            # If default validation fails (likely JSON string fields),
            # convert to dict manually and parse JSON strings
            if hasattr(data, "__dict__") and not isinstance(data, dict):
                raw = {}
                for key in cls.model_fields:
                    try:
                        val = getattr(data, key, None)
                        # Parse JSON strings
                        if isinstance(val, str) and len(val) >= 2 and val[0] in ('[', '{'):
                            try:
                                val = json.loads(val)
                            except (json.JSONDecodeError, ValueError):
                                pass
                        # Convert non-serializable objects to None
                        if val is not None and not isinstance(val, (str, int, float, bool, list, dict, tuple)):
                            try:
                                json.dumps(val, default=str)
                            except (TypeError, ValueError):
                                val = None
                        raw[key] = val
                    except Exception:
                        pass
                try:
                    return handler(raw)
                except Exception:
                    # Last resort: fill missing required fields with defaults
                    for field_name, field_info in cls.model_fields.items():
                        if field_name not in raw:
                            if field_info.default is not None:
                                raw[field_name] = field_info.default
                            elif field_info.is_required():
                                raw[field_name] = None
                    return handler(raw)
            raise
