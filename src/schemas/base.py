"""Base schema with JSON string parsing and ORM compatibility."""

import json
from typing import Any

from pydantic import BaseModel, model_validator


class DBModel(BaseModel):
    """Response model base that handles ORM objects with JSON string fields
    and None values for fields that have defaults."""

    model_config = {"from_attributes": True}

    @model_validator(mode="wrap")
    @classmethod
    def _handle_orm_and_json(cls, data: Any, handler: Any) -> Any:
        try:
            return handler(data)
        except Exception:
            pass

        # Convert ORM to dict, use field defaults for None values
        if hasattr(data, "__dict__") and not isinstance(data, dict):
            raw = {}
            for field_name, field_info in cls.model_fields.items():
                try:
                    val = getattr(data, field_name, None)
                except Exception:
                    val = None

                # Use field default when ORM returns None
                if val is None:
                    if field_info.default is not None:
                        raw[field_name] = field_info.default
                    elif not field_info.is_required():
                        raw[field_name] = None
                    else:
                        raw[field_name] = None
                    continue

                # Parse JSON strings
                if isinstance(val, str) and len(val) >= 2 and val[0] in ('[', '{'):
                    try:
                        val = json.loads(val)
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Handle non-serializable objects
                if not isinstance(val, (str, int, float, bool, list, dict, tuple, type(None))):
                    try:
                        json.dumps(val, default=str)
                    except (TypeError, ValueError):
                        val = str(val) if val is not None else None

                raw[field_name] = val

            return handler(raw)

        # Dict input — just parse JSON strings
        if isinstance(data, dict):
            for key in list(data.keys()):
                val = data[key]
                if isinstance(val, str) and len(val) >= 2 and val[0] in ('[', '{'):
                    try:
                        data[key] = json.loads(val)
                    except (json.JSONDecodeError, ValueError):
                        pass
            return handler(data)

        raise ValueError(f"Cannot validate {type(data)}")
