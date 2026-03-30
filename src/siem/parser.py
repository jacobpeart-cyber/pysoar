"""Log parsers for multiple log formats in SIEM engine"""

import asyncio
import json
import re
from datetime import datetime
from typing import Dict, Optional
from xml.etree import ElementTree as ET

from src.core.logging import get_logger

logger = get_logger(__name__)


class SyslogParser:
    """Parser for RFC 3164 and RFC 5424 syslog messages"""

    # RFC 3164: <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MESSAGE
    RFC3164_PATTERN = re.compile(
        r"^<(\d+)>"  # Priority
        r"(\w+ \s+\d+\s+\d+:\d+:\d+)\s+"  # Timestamp
        r"(\S+)\s+"  # Hostname
        r"([^\[\]]+)"  # Tag/App name
        r"(?:\[(\d+)\])?"  # Optional PID
        r":\s*(.*?)$",  # Message
        re.MULTILINE,
    )

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    RFC5424_PATTERN = re.compile(
        r"^<(\d+)>"  # Priority
        r"(\d+)\s+"  # Version
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"  # Timestamp
        r"(\S+)\s+"  # Hostname
        r"(\S+)\s+"  # App name
        r"(\S+)\s+"  # Process ID
        r"(\S+)"  # Message ID
        r"(?:\s+(\[.*?\]))?"  # Optional SD
        r"(?:\s+(.*))?$",  # Message
        re.MULTILINE,
    )

    def parse(self, raw_log: str) -> Optional[Dict]:
        """Parse syslog message"""
        # Try RFC 5424 first (more specific)
        match = self.RFC5424_PATTERN.match(raw_log)
        if match:
            return self._parse_rfc5424(match)

        # Fall back to RFC 3164
        match = self.RFC3164_PATTERN.match(raw_log)
        if match:
            return self._parse_rfc3164(match)

        return None

    def _parse_rfc3164(self, match) -> Dict:
        """Extract fields from RFC 3164 match"""
        priority = int(match.group(1))
        timestamp_str = match.group(2)
        hostname = match.group(3)
        app_name = match.group(4).strip()
        process_id = match.group(5)
        message = match.group(6)

        facility = (priority >> 3) & 0x1F
        severity = priority & 0x07

        return {
            "priority": priority,
            "facility": facility,
            "severity": severity,
            "timestamp": timestamp_str,
            "hostname": hostname,
            "app_name": app_name,
            "process_id": process_id,
            "message": message,
        }

    def _parse_rfc5424(self, match) -> Dict:
        """Extract fields from RFC 5424 match"""
        priority = int(match.group(1))
        version = int(match.group(2))
        timestamp = match.group(3)
        hostname = match.group(4)
        app_name = match.group(5)
        process_id = match.group(6)
        message_id = match.group(7)
        structured_data = match.group(8)
        message = match.group(9) or ""

        facility = (priority >> 3) & 0x1F
        severity = priority & 0x07

        return {
            "priority": priority,
            "version": version,
            "facility": facility,
            "severity": severity,
            "timestamp": timestamp,
            "hostname": hostname,
            "app_name": app_name,
            "process_id": process_id,
            "message_id": message_id,
            "structured_data": structured_data,
            "message": message,
        }


class JSONParser:
    """Parser for JSON-formatted logs"""

    def parse(self, raw_log: str) -> Optional[Dict]:
        """Parse JSON log"""
        try:
            data = json.loads(raw_log)
            if isinstance(data, dict):
                return self._flatten_dict(data)
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    def _flatten_dict(self, data: Dict, prefix: str = "", result: Optional[Dict] = None) -> Dict:
        """Flatten nested JSON using dot notation"""
        if result is None:
            result = {}

        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                self._flatten_dict(value, full_key, result)
            elif isinstance(value, list):
                result[full_key] = json.dumps(value)
            else:
                result[full_key] = value

        return result


class CEFParser:
    """Parser for Common Event Format (CEF) logs"""

    # CEF:0|device_vendor|device_product|device_version|signature_id|name|severity|[extensions]
    CEF_PATTERN = re.compile(
        r"^CEF:(\d+)\|"  # CEF version
        r"([^|]*)\|"  # Device vendor
        r"([^|]*)\|"  # Device product
        r"([^|]*)\|"  # Device version
        r"([^|]*)\|"  # Signature ID
        r"([^|]*)\|"  # Name
        r"(-?\d+)"  # Severity
        r"\|(.*?)$",  # Extensions
        re.MULTILINE,
    )

    def parse(self, raw_log: str) -> Optional[Dict]:
        """Parse CEF log"""
        match = self.CEF_PATTERN.match(raw_log)
        if not match:
            return None

        version = int(match.group(1))
        device_vendor = match.group(2)
        device_product = match.group(3)
        device_version = match.group(4)
        signature_id = match.group(5)
        name = match.group(6)
        severity = int(match.group(7))
        extensions_str = match.group(8)

        # Parse extensions key=value pairs
        extensions = self._parse_extensions(extensions_str)

        return {
            "cef_version": version,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
            **extensions,
        }

    def _parse_extensions(self, ext_str: str) -> Dict:
        """Parse CEF extension key=value pairs"""
        result = {}
        # Handle escaped equals and pipes in values
        pattern = re.compile(r'(\w+)=([^\s=]+(?:\\\S+)*)')
        for match in pattern.finditer(ext_str):
            key = match.group(1)
            value = match.group(2).replace(r"\=", "=").replace(r"\|", "|")
            result[key] = value

        return result


class LEEFParser:
    """Parser for Log Event Extended Format (LEEF) logs"""

    # LEEF:2.0|vendor|product|version|event_id|[key=value]
    LEEF_PATTERN = re.compile(
        r"^LEEF:(\d+\.\d+)\|"  # LEEF version
        r"([^|]*)\|"  # Vendor
        r"([^|]*)\|"  # Product
        r"([^|]*)\|"  # Version
        r"([^|]*)\|"  # Event ID
        r"(.*?)$",  # Key=value pairs
        re.MULTILINE,
    )

    def parse(self, raw_log: str) -> Optional[Dict]:
        """Parse LEEF log"""
        match = self.LEEF_PATTERN.match(raw_log)
        if not match:
            return None

        version = match.group(1)
        vendor = match.group(2)
        product = match.group(3)
        version_str = match.group(4)
        event_id = match.group(5)
        kv_str = match.group(6)

        # Parse key=value pairs (similar to CEF extensions)
        kv_pairs = self._parse_key_values(kv_str)

        return {
            "leef_version": version,
            "vendor": vendor,
            "product": product,
            "product_version": version_str,
            "event_id": event_id,
            **kv_pairs,
        }

    def _parse_key_values(self, kv_str: str) -> Dict:
        """Parse key=value pairs with tab delimiter"""
        result = {}
        # LEEF typically uses tab delimiters
        pairs = kv_str.split("\t")
        for pair in pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                result[key.strip()] = value.strip()

        return result


class WindowsEventParser:
    """Parser for Windows Event Log XML format"""

    def parse(self, raw_log: str) -> Optional[Dict]:
        """Parse Windows Event Log XML"""
        try:
            root = ET.fromstring(raw_log)
            return self._extract_event_fields(root)
        except ET.ParseError:
            return None

    def _extract_event_fields(self, root) -> Dict:
        """Extract fields from Event XML element"""
        result = {}

        # Define XML namespace
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # Extract System fields
        system = root.find("ns:System", ns)
        if system is not None:
            event_id_elem = system.find("ns:EventID", ns)
            if event_id_elem is not None:
                result["event_id"] = event_id_elem.text

            level_elem = system.find("ns:Level", ns)
            if level_elem is not None:
                result["level"] = level_elem.text

            task_elem = system.find("ns:Task", ns)
            if task_elem is not None:
                result["task"] = task_elem.text

            keywords_elem = system.find("ns:Keywords", ns)
            if keywords_elem is not None:
                result["keywords"] = keywords_elem.text

            time_created_elem = system.find("ns:TimeCreated", ns)
            if time_created_elem is not None:
                result["timestamp"] = time_created_elem.get("SystemTime")

            computer_elem = system.find("ns:Computer", ns)
            if computer_elem is not None:
                result["hostname"] = computer_elem.text

            channel_elem = system.find("ns:Channel", ns)
            if channel_elem is not None:
                result["channel"] = channel_elem.text

            security_elem = system.find("ns:Security", ns)
            if security_elem is not None:
                result["user_id"] = security_elem.get("UserID")

        # Extract EventData fields
        event_data = root.find("ns:EventData", ns)
        if event_data is not None:
            for data_elem in event_data.findall("ns:Data", ns):
                name = data_elem.get("Name")
                text = data_elem.text or ""
                if name:
                    result[f"data_{name}"] = text

        return result


class LogParserManager:
    """Registry and manager for log parsers with auto-detection"""

    def __init__(self):
        self.parsers = {
            "syslog": SyslogParser(),
            "json": JSONParser(),
            "cef": CEFParser(),
            "leef": LEEFParser(),
            "windows": WindowsEventParser(),
        }

    async def parse(self, raw_log: str, source_type: str = "auto") -> Dict:
        """
        Parse a log with optional auto-detection of format.

        Returns:
            Dict with keys: parsed_fields, source_type, timestamp, message
        """
        detected_type = source_type

        if source_type == "auto":
            detected_type = self._detect_format(raw_log)

        # Run parsing asynchronously
        result = await self._parse_async(raw_log, detected_type)

        return result

    def _detect_format(self, raw_log: str) -> str:
        """Auto-detect log format based on content"""
        raw_log = raw_log.strip()

        # Windows Event Log XML
        if "<Event xmlns" in raw_log:
            return "windows"

        # CEF format
        if raw_log.startswith("CEF:"):
            return "cef"

        # LEEF format
        if raw_log.startswith("LEEF:"):
            return "leef"

        # RFC Syslog (starts with <digit)
        if raw_log.startswith("<") and len(raw_log) > 1 and raw_log[1].isdigit():
            return "syslog"

        # JSON format
        if raw_log.startswith(("{", "[")):
            try:
                json.loads(raw_log)
                return "json"
            except (json.JSONDecodeError, ValueError):
                pass

        # Default to syslog
        return "syslog"

    async def _parse_async(self, raw_log: str, source_type: str) -> Dict:
        """Parse log asynchronously"""
        loop = asyncio.get_event_loop()

        # Run parsing in thread pool to avoid blocking
        parsed = await loop.run_in_executor(
            None, self._do_parse, raw_log, source_type
        )

        return parsed

    def _do_parse(self, raw_log: str, source_type: str) -> Dict:
        """Synchronous parsing logic"""
        parser = self.parsers.get(source_type)
        if not parser:
            logger.warning(f"Unknown source type: {source_type}, using syslog")
            parser = self.parsers["syslog"]

        parsed_fields = parser.parse(raw_log)

        if not parsed_fields:
            logger.debug(f"Failed to parse log with {source_type} parser")
            parsed_fields = {"raw_message": raw_log}

        # Extract timestamp and message
        timestamp = self._extract_timestamp(parsed_fields, source_type)
        message = self._extract_message(parsed_fields, source_type)

        return {
            "parsed_fields": parsed_fields,
            "source_type": source_type,
            "timestamp": timestamp,
            "message": message,
        }

    def _extract_timestamp(self, parsed_fields: Dict, source_type: str) -> Optional[str]:
        """Extract timestamp from parsed fields"""
        timestamp_keys = ["timestamp", "TimeCreated", "time", "eventTime"]

        for key in timestamp_keys:
            if key in parsed_fields:
                return parsed_fields[key]

        # Try nested timestamp fields
        for key, value in parsed_fields.items():
            if "time" in key.lower() and isinstance(value, str):
                return value

        return None

    def _extract_message(self, parsed_fields: Dict, source_type: str) -> str:
        """Extract main message from parsed fields"""
        message_keys = ["message", "msg", "Message", "data_Description", "name"]

        for key in message_keys:
            if key in parsed_fields and parsed_fields[key]:
                return str(parsed_fields[key])

        # Return raw message if available
        if "raw_message" in parsed_fields:
            return str(parsed_fields["raw_message"])[:200]

        return ""
