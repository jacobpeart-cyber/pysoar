from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field, IPvAnyAddress


class HostEvent(BaseModel):
    event_type: str = Field(..., description="Type of host event, e.g., process_start, net_conn, file_mod")
    agent_id: Optional[str]
    hostname: Optional[str]
    ip: Optional[IPvAnyAddress]
    timestamp: Optional[str]
    message: Optional[str]
    meta: Optional[dict] = None


class HostEventsRequest(BaseModel):
    events: List[HostEvent]
