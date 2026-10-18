"""Splunk Enterprise / Splunk Cloud Platform REST API connector.

Written from the Splunk REST API Reference Manual (docs.splunk.com,
"REST API Reference": Search endpoints, Saved search endpoints, System
endpoints ``server/info``) and the HTTP Event Collector reference
("HTTP Event Collector REST API endpoints", ``services/collector/event``).
Not verified against a live Splunk deployment.

``base_url`` is the management port (``https://splunk.example.com:8089``).
The REST API authenticates with ``Authorization: Bearer <token>`` (a Splunk
authentication token) or HTTP basic with a Splunk user; the HTTP Event
Collector, on its own URL, with ``Authorization: Splunk <hec_token>``.

Splunk usually lives on a private network: its address must be inside the
operator setting ``OUTBOUND_PRIVATE_ALLOWLIST`` (src/integrations/netguard.py),
otherwise every request is refused before a connection is made and the
refusal names that setting.
"""

from __future__ import annotations

import base64
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlsplit

import httpx

from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)
from src.integrations.netguard import PinnedTransport

_TIME = {"type": "string", "description": "Splunk time modifier: relative (-24h, -15m@m), epoch seconds or ISO-8601"}
_SID = {"type": "string", "minLength": 1, "description": "search job id (sid)"}
_SAVED_NAME = {"type": "string", "minLength": 1, "description": "saved search name"}
_MAX_RESULTS = 10000


def https_origin(value: Any, field: str) -> str:
    """``https://host[:port]`` with no credentials, query, fragment or path; else ValueError."""
    text = str(value or "").strip().rstrip("/")
    parts = urlsplit(text)
    try:
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise ValueError(f"{field} has an invalid port") from None
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError(f"{field} must be an https:// URL")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ValueError(f"{field} must not carry credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError(f"{field} must be the scheme, host and port only")
    return f"https://{parts.netloc}"


def saved_search_segment(name: Any) -> str:
    """A saved-search name as one percent-encoded path segment.

    Splunk saved-search names commonly contain spaces, so the name is not put
    through ``path_segment``; a slash, backslash, ?, #, % or a dot-segment is
    refused and the rest is percent-encoded (no character can act as a path
    separator).
    """
    text = str(name or "").strip()
    if not text or text in (".", "..") or any(c in text for c in ("/", "\\", "?", "#", "%")) or len(text) > 255:
        raise ValueError("saved search name is not a plain name")
    return quote(text, safe="")


#: SPL commands the read-only ``search`` action accepts: searching, filtering,
#: shaping and aggregating commands only. Anything else (delete, collect,
#: outputlookup, sendemail, script, rest, savedsearch, map, custom commands,
#: and macros, which expand server-side to anything) is refused before any
#: request. A deny list would be bypassable; an allow list fails closed.
_READ_ONLY_SPL = frozenset({
    "search", "where", "stats", "eventstats", "streamstats", "tstats", "eval", "table", "fields",
    "sort", "head", "tail", "rex", "regex", "timechart", "chart", "top", "rare", "dedup", "lookup",
    "inputlookup", "transaction", "rename", "fillnull", "mvexpand", "mvcombine", "spath", "bin",
    "bucket", "join", "append", "appendcols", "makemv", "convert", "iplocation", "geostats",
    "addtotals", "reverse", "xyseries", "untable", "makeresults", "from", "datamodel", "metadata",
    "multisearch", "nomv", "replace", "rangemap", "strcat", "transpose", "uniq", "filldown",
    "addinfo", "localop", "noop", "fieldformat", "sitimechart", "timewrap", "predict", "trendline",
    "cluster", "kmeans", "anomalies", "outlier", "contingency", "correlate", "diff", "highlight",
    "iconify", "accum", "autoregress", "delta", "xmlkv", "kv", "extract", "erex", "multikv",
    "tags", "typer", "eventcount", "metasearch", "set", "history", "loadjob",
})


class SplunkConnector(BaseConnector):
    """Splunk REST API and HTTP Event Collector."""

    name = "splunk"
    timeout = 60

    CONFIG_FIELDS = [
        field_spec("base_url", "Management URL", "https URL of the Splunk management port, e.g. https://splunk.example.com:8089"),
        field_spec("hec_url", "HEC URL", "https URL of the HTTP Event Collector, e.g. https://splunk.example.com:8088 (for hec_send_event)", required=False),
        field_spec("search", "Poll search", "SPL the SIEM poller runs every poll (default: search index=*); the poll window is set with earliest_time / latest_time", required=False),
    ]
    CREDENTIAL_FIELDS = [
        field_spec("token", "Authentication token", "Splunk authentication token (Authorization: Bearer); or give username and password", required=False, secret=True),
        field_spec("username", "Username", "Splunk user for basic authentication (when no token is given)", required=False),
        field_spec("password", "Password", "Password of that user", required=False, secret=True),
        field_spec("hec_token", "HEC token", "HTTP Event Collector token (Authorization: Splunk), for hec_send_event", required=False, secret=True),
    ]
    TEST_CALL = "GET /services/server/info?output_mode=json"
    ACTIONS = {
        "search": ActionSpec(
            "Run a one-shot search and return its results "
            "(POST /services/search/v2/jobs, exec_mode=oneshot, output_mode=json; REST API Reference, search/v2/jobs).",
            object_schema({
                "search": {"type": "string", "minLength": 1, "description": "SPL; 'search ' is prefixed unless it starts with 'search' or '|'. Read-only: every pipeline segment must start with an allow-listed read-only command (search, where, stats, eval, table, timechart, tstats, lookup, ...); macros and any other command are refused before any request"},
                "earliest_time": _TIME,
                "latest_time": _TIME,
                "max_count": {"type": "integer", "minimum": 1, "maximum": _MAX_RESULTS, "description": "maximum results (default 100)"},
            }, ["search"]),
            "result count and the results array",
            idempotent=True, side_effect=False, action_type="query", display_name="Search",
        ),
        "list_saved_searches": ActionSpec(
            "List saved searches (GET /services/saved/searches?output_mode=json&count=; REST API Reference, saved/searches).",
            object_schema({"count": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "maximum entries (default 100)"}}),
            "saved searches (name, search, schedule, disabled)",
            idempotent=True, side_effect=False, action_type="query", display_name="List saved searches",
        ),
        "run_saved_search": ActionSpec(
            "Dispatch a saved search (POST /services/saved/searches/{name}/dispatch; REST API Reference, "
            "saved/searches/{name}/dispatch). Runs the search, and any alert actions it carries, on the Splunk side.",
            object_schema({"name": _SAVED_NAME}, ["name"]),
            "sid of the dispatched job",
            idempotent=False, side_effect=True, action_type="execute", display_name="Run saved search",
        ),
        "get_job_results": ActionSpec(
            "Results of a search job (GET /services/search/v2/jobs/{sid}/results?output_mode=json; REST API Reference, "
            "search/v2/jobs/{search_id}/results).",
            object_schema({
                "sid": _SID,
                "count": {"type": "integer", "minimum": 1, "maximum": _MAX_RESULTS, "description": "maximum results (default 100)"},
            }, ["sid"]),
            "result count and the results array",
            idempotent=True, side_effect=False, action_type="query", display_name="Get job results",
        ),
        "hec_send_event": ActionSpec(
            "Send one event to the HTTP Event Collector (POST {hec_url}/services/collector/event; HTTP Event Collector "
            "REST API reference). Needs hec_url and hec_token.",
            object_schema({
                "event": {"description": "the event: a string or a JSON object"},
                "sourcetype": {"type": "string"},
                "source": {"type": "string"},
                "index": {"type": "string"},
                "time": {"type": "number", "description": "event time, epoch seconds (default: now)"},
            }, ["event"]),
            "HEC acknowledgement (text, code)",
            idempotent=False, side_effect=True, action_type="create", display_name="Send event (HEC)",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        base = self.config.get("base_url")
        self.base_url = https_origin(base, "base_url") if base else ""

    # ------------------------------------------------------------------
    # Fields
    # ------------------------------------------------------------------

    @classmethod
    def missing_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        """``base_url``, plus a credential: ``token``, or ``username`` and ``password``."""
        missing = super().missing_fields(config, credentials)
        creds = credentials or {}

        def present(key: str) -> bool:
            return bool(str(creds.get(key) or "").strip())

        if not present("token"):
            if present("username") and not present("password"):
                missing.append("password")
            elif present("password") and not present("username"):
                missing.append("username")
            elif not present("username"):
                missing += ["token", "username", "password"]
        return missing

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        bad: List[str] = []
        for key in ("base_url", "hec_url"):
            value = (config or {}).get(key)
            if value:
                try:
                    https_origin(value, key)
                except ValueError:
                    bad.append(key)
        return bad

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # Pinned like every connector; private_hint makes a private
            # address outside the allow-list say which setting opens it.
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=float(self.timeout),
                transport=PinnedTransport(private_hint=True),
                follow_redirects=False,
            )
        return self._client

    def _get_headers(self) -> Dict[str, str]:
        headers = super()._get_headers()
        token = self.credentials.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            username, password = self.credentials.get("username"), self.credentials.get("password")
            if username and password:
                headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        return headers

    def _secret_values(self) -> List[str]:
        values = super()._secret_values()
        username, password = self.credentials.get("username"), self.credentials.get("password")
        if username and password:
            values.append(base64.b64encode(f"{username}:{password}".encode()).decode())
        return values

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> ConnectionTestResult:
        # REST API Reference, System endpoints: GET server/info
        body: Dict[str, Any] = {}

        async def _call() -> Any:
            data = await self._make_request("GET", "/services/server/info", params={"output_mode": "json"})
            body["data"] = data
            return data

        def _verdict(data: Any) -> Optional[str]:
            if not isinstance(data, dict) or not data.get("entry"):
                return "server/info answered without an entry"
            return None

        result = await self._probe(self.TEST_CALL, _call, _verdict)
        if result.healthy:
            content = ((body["data"].get("entry") or [{}])[0] or {}).get("content") or {}
            result.detail = self.sanitize(
                f"authenticated read-only call succeeded; Splunk {content.get('version') or 'version unknown'} "
                f"on {content.get('serverName') or 'unknown server'}",
            )
        return result

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    @staticmethod
    def _spl(search: str) -> str:
        text = str(search).strip()
        if not text:
            raise ValueError("search must not be empty")
        # The action is declared read-only (analysts may run it): every
        # pipeline segment, including those inside [subsearches], must start
        # with an allow-listed read-only command, and macros (`name`) are
        # refused because they expand server-side to anything.
        if "`" in text:
            raise ValueError("search is read-only: SPL macros (`...`) are not allowed")
        spl = text if text.startswith("|") or text.lower().startswith("search") else f"search {text}"
        for index, segment in enumerate(spl.split("|")):
            body = segment.strip()
            while body.startswith("["):
                body = body[1:].strip()
            if not body:
                if index == 0:
                    continue  # a leading "|" (generating command follows)
                raise ValueError("search is read-only: empty pipeline segment")
            command = body.split()[0].lower().rstrip("]")
            if command not in _READ_ONLY_SPL:
                raise ValueError(f"search is read-only: SPL command '{command}' is not allowed")
        return spl

    async def search(
        self,
        search: str,
        earliest_time: Optional[str] = None,
        latest_time: Optional[str] = None,
        max_count: int = 100,
    ) -> Dict[str, Any]:
        # REST API Reference, Search endpoints: POST search/v2/jobs (exec_mode=oneshot
        # returns the results in the response instead of a sid). count bounds the
        # results returned; max_count bounds the results the job keeps.
        form: Dict[str, Any] = {
            "search": self._spl(search),
            "exec_mode": "oneshot",
            "output_mode": "json",
            "max_count": int(max_count),
            "count": int(max_count),
        }
        if earliest_time:
            form["earliest_time"] = str(earliest_time)
        if latest_time:
            form["latest_time"] = str(latest_time)
        data = await self._make_request("POST", "/services/search/v2/jobs", form_data=form)
        results = data.get("results", []) if isinstance(data, dict) else []
        return {"count": len(results), "results": results}

    async def list_saved_searches(self, count: int = 100) -> Dict[str, Any]:
        # REST API Reference, Search endpoints: GET saved/searches
        data = await self._make_request("GET", "/services/saved/searches", params={"output_mode": "json", "count": int(count)})
        entries = data.get("entry", []) if isinstance(data, dict) else []
        saved = []
        for entry in entries:
            content = entry.get("content") or {}
            saved.append({
                "name": entry.get("name"),
                "search": content.get("search"),
                "is_scheduled": content.get("is_scheduled"),
                "cron_schedule": content.get("cron_schedule"),
                "disabled": content.get("disabled"),
            })
        return {"count": len(saved), "saved_searches": saved}

    async def run_saved_search(self, name: str) -> Dict[str, Any]:
        # REST API Reference, Search endpoints: POST saved/searches/{name}/dispatch
        segment = saved_search_segment(name)
        data = await self._make_request(
            "POST", f"/services/saved/searches/{segment}/dispatch", form_data={"output_mode": "json"},
        )
        sid = data.get("sid") if isinstance(data, dict) else None
        if not sid:
            return {"error": "Splunk answered the dispatch without a sid"}
        return {"name": str(name).strip(), "sid": sid}

    async def get_job_results(self, sid: str, count: int = 100) -> Dict[str, Any]:
        # REST API Reference, Search endpoints: GET search/v2/jobs/{search_id}/results
        data = await self._make_request(
            "GET", f"/services/search/v2/jobs/{path_segment(sid)}/results",
            params={"output_mode": "json", "count": int(count)},
        )
        results = data.get("results", []) if isinstance(data, dict) else []
        return {"sid": sid, "count": len(results), "results": results}

    async def hec_send_event(
        self,
        event: Any,
        sourcetype: Optional[str] = None,
        source: Optional[str] = None,
        index: Optional[str] = None,
        time: Optional[float] = None,  # the HEC field name
    ) -> Dict[str, Any]:
        # HTTP Event Collector REST API reference: POST services/collector/event
        hec_url, hec_token = self.config.get("hec_url"), self.credentials.get("hec_token")
        if not hec_url or not hec_token:
            raise ValueError("hec_send_event needs hec_url (config) and hec_token (credentials) on this integration")
        if event is None or event == "":
            raise ValueError("event must not be empty")
        payload: Dict[str, Any] = {"event": event, "time": float(time) if time is not None else _now()}
        for key, value in (("sourcetype", sourcetype), ("source", source), ("index", index)):
            if value:
                payload[key] = value
        data = await self._make_request(
            "POST", f"{https_origin(hec_url, 'hec_url')}/services/collector/event",
            json_data=payload, headers={"Authorization": f"Splunk {hec_token}"}, auth=False,
        )
        code = data.get("code") if isinstance(data, dict) else None
        if code not in (0, None):
            return {"error": f"HEC refused the event: {data.get('text') or 'code ' + str(code)}"}
        return {"text": (data or {}).get("text", "Success"), "code": code if code is not None else 0}

    # ------------------------------------------------------------------
    # SIEM poller (src/siem/cloud_poller.py)
    # ------------------------------------------------------------------

    async def fetch_events(self, since: datetime, until: datetime, limit: int = 1000) -> List[Dict[str, Any]]:
        """Events in [since, until) for the SIEM poller: the configured poll search, one-shot.

        Raises ConnectorHTTPError / IntegrationError / ValueError like an action.
        """
        try:
            out = await self.search(
                self.config.get("search") or "search index=*",
                earliest_time=str(int(since.timestamp())),
                latest_time=str(int(until.timestamp())),
                max_count=limit,
            )
        finally:
            await self.close()
        return out["results"]


def _now() -> float:
    return time.time()


__all__ = ["SplunkConnector", "https_origin", "saved_search_segment"]
