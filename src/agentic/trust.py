"""Trust layer: prompt-injection scanning and untrusted-data boundaries (design v2 section 4).

* :class:`Boundary` issues a fresh nonce per LLM turn and renders untrusted
  tool results as ``[[DATA <label> <nonce>]] ... [[/DATA <nonce>]]`` blocks
  (one sub-block per record for list results) after escaping any marker
  text the data itself contains.
* :func:`scan_for_injection` walks the *raw* payload recursively (decoding
  nested JSON strings and base64 blobs), normalizes each string through the
  pipeline (NFKC, zero-width/RTL/tag stripping, HTML-entity / percent /
  ``\\uXXXX`` decoding, homoglyph folding, spaced-letter collapse, lowercase)
  and matches the pattern families. Hits are stored as
  ``{family, start, length, sha256(snippet), preview}`` with a <= 40 char
  value-redacted preview; the raw match is never persisted.
* :class:`TrustScanner` accumulates scores into a sticky :class:`TrustState`
  across records and across the run: ``flagged`` at the low threshold,
  ``lockdown`` at the high threshold or on any marker-spoof / role-hijack /
  boundary-forge hit. The tier never goes down inside a run; an analyst
  acknowledgment (hash allow-list) downgrades a specific content hash to
  ``flagged`` org-wide.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import html
import json
import re
import secrets
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Optional
from urllib.parse import unquote

from src.agentic.decisions import TrustHit, TrustState, TrustTier
from src.core.logging import get_logger
from src.core.metrics import AGENT_INJECTION_EVENTS_TOTAL, increment as metric_increment
from src.core.redact import redact, redact_text

logger = get_logger(__name__)

__all__ = [
    "DATA_CLOSE",
    "DATA_OPEN",
    "FAMILY_WEIGHTS",
    "FLAGGED_THRESHOLD",
    "LOCKDOWN_FAMILIES",
    "LOCKDOWN_THRESHOLD",
    "PREVIEW_MAX_CHARS",
    "Boundary",
    "ScanResult",
    "TrustScanner",
    "WrappedBlock",
    "neutralize_markers",
    "normalize_text",
    "scan_for_injection",
    "trust_state_from_dict",
    "trust_state_to_dict",
    "wrap_untrusted",
]

DATA_OPEN: Final[str] = "[[DATA"
DATA_CLOSE: Final[str] = "[[/DATA"
PREVIEW_MAX_CHARS: Final[int] = 40

FLAGGED_THRESHOLD: Final[float] = 4.0
LOCKDOWN_THRESHOLD: Final[float] = 10.0
LOCKDOWN_FAMILIES: Final[frozenset[str]] = frozenset({"marker_spoof", "role_hijack", "boundary_forge"})

FAMILY_WEIGHTS: Final[dict[str, float]] = {
    "instruction_override": 6.0,
    "role_hijack": 10.0,
    "tool_coercion": 4.0,
    "exfiltration": 6.0,
    "marker_spoof": 10.0,
    "boundary_forge": 10.0,
    "obfuscation": 1.5,
}

_MAX_SCAN_DEPTH: Final[int] = 12
_MAX_STRINGS_PER_SCAN: Final[int] = 4000
_MAX_STRING_CHARS: Final[int] = 200_000

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE: Final[re.Pattern[str]] = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u034f\u180e"
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    "\U000e0000-\U000e007f]"
)
_PERCENT_RE: Final[re.Pattern[str]] = re.compile(r"%[0-9a-fA-F]{2}")
_UNICODE_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(r"\\u([0-9a-fA-F]{4})")
_HEX_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(r"\\x([0-9a-fA-F]{2})")
_SPACED_LETTERS_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:[a-z][ .\-_*]){3,}[a-z]\b", re.IGNORECASE)
_WS_RE: Final[re.Pattern[str]] = re.compile(r"[ \t\f\v]+")
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"(?<=[a-z])[*~]+(?=[a-z])")

# Common Cyrillic / Greek / fullwidth lookalikes folded to ASCII so
# "ignоre" (Cyrillic о) matches "ignore".
_HOMOGLYPHS: Final[dict[str, str]] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s",
    "\u0458": "j", "\u0501": "d", "\u0261": "g", "\u04bb": "h", "\u043a": "k", "\u0442": "t", "\u043c": "m", "\u043d": "h", "\u0432": "b",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "І": "I", "Ѕ": "S",
    "\u0408": "J", "\u041a": "K", "\u0422": "T", "\u041c": "M", "\u041d": "H", "\u0412": "B",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "ν": "v", "κ": "k", "τ": "t",
    "ⅰ": "i", "ⅼ": "l", "ｉ": "i",
}
_HOMOGLYPH_TABLE: Final[dict[int, str]] = {ord(k): v for k, v in _HOMOGLYPHS.items()}
_CYRILLIC_RE: Final[re.Pattern[str]] = re.compile(r"[\u0400-\u04ff]")
_LATIN_RE: Final[re.Pattern[str]] = re.compile(r"[a-zA-Z]")
_MIXED_SCRIPT_WORD_RE: Final[re.Pattern[str]] = re.compile(r"\b(?=\w*[a-zA-Z])(?=\w*[\u0400-\u04ff\u0370-\u03ff])\w+\b")
_BASE64_RE: Final[re.Pattern[str]] = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_BASE64_URL_RE: Final[re.Pattern[str]] = re.compile(r"(?<![A-Za-z0-9_\-=])[A-Za-z0-9_\-]{24,}={0,2}(?![A-Za-z0-9_\-=])")
_HEX_BLOB_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")


_WORD_RE = re.compile(r"\w+")


def _fold_homoglyphs(text: str) -> str:
    """Fold lookalike letters to ASCII only in words that mix scripts (or are
    made entirely of lookalikes), so genuine Cyrillic/Greek prose is untouched."""

    latin_dominant = len(_LATIN_RE.findall(text)) > len(_CYRILLIC_RE.findall(text))

    def _fold(match: re.Match[str]) -> str:
        word = match.group(0)
        has_latin = _LATIN_RE.search(word) is not None
        has_other = any(ord(ch) in _HOMOGLYPH_TABLE for ch in word)
        if not has_other:
            return word
        if has_latin or (latin_dominant and all(ord(ch) in _HOMOGLYPH_TABLE for ch in word)):
            return word.translate(_HOMOGLYPH_TABLE)
        return word

    return _WORD_RE.sub(_fold, text)


def normalize_text(text: str) -> str:
    """The normalization pipeline every scanned string goes through (lowercased)."""
    return _normalize_case_preserving(text).lower()


def _normalize_case_preserving(text: str) -> str:
    if len(text) > _MAX_STRING_CHARS:
        text = text[:_MAX_STRING_CHARS]
    out = unicodedata.normalize("NFKC", text)
    out = _ZERO_WIDTH_RE.sub("", out)
    # Decoding passes; each is bounded to one round so we terminate.
    if "&" in out and ";" in out:
        out = html.unescape(out)
    if _UNICODE_ESCAPE_RE.search(out):
        out = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    if _HEX_ESCAPE_RE.search(out):
        out = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), out)
    if _PERCENT_RE.search(out):
        out = unquote(out)
    if "&" in out and ";" in out:
        out = html.unescape(out)
    out = unicodedata.normalize("NFKC", out)
    out = _ZERO_WIDTH_RE.sub("", out)
    out = _fold_homoglyphs(out)
    out = _SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), out)
    out = _SEPARATOR_RE.sub("", out)
    out = _WS_RE.sub(" ", out)
    return out


# ---------------------------------------------------------------------------
# Pattern families (matched on normalized, lowercased text unless noted)
# ---------------------------------------------------------------------------

_TOOL_VERBS = r"(?:call|run|execute|invoke|use|trigger|perform|launch|fire|apply|initiate|please run|now run)"
_TOOL_NAMES = (
    r"(?:block_ip|isolate_host|disable_user|disable_account|reset_credentials|quarantine_file|quarantine_host|"
    r"execute_playbook|execute_integration_action|queue_endpoint_command|remediate_incident|run_script|"
    r"kill_process|delete_[a-z_]+|create_ticket|update_incident_findings|add_incident_note|submit_verdict|"
    r"simulate_attack|run_threat_hunt|unblock_ip|whitelist_ip|allowlist_ip|[a-z]+_(?:ip|host|user|account|file|playbook|command))"
)
_ACTION_VERBS = r"(?:block|isolate|disable|delete|quarantine|reset|wipe|terminate|kill|unblock|allowlist|whitelist|escalate|close|dismiss|suppress)"

_FAMILY_PATTERNS: Final[dict[str, list[re.Pattern[str]]]] = {
    "instruction_override": [
        re.compile(r"\b(?:ignore|disregard|forget|discard|bypass|skip|abandon|override|overrule)\b[^.\n]{0,40}?\b(?:instructions?|rules?|guidelines?|policy|policies|guardrails?|restrictions?|constraints?|directives?|prompt|training|programming)\b"),
        re.compile(r"\b(?:new|updated|revised|real|true|actual|actual|secret|hidden|priority|override)\s+(?:instructions?|directives?|orders?|rules?|task|objective|mission)\s*[:\-]"),
        re.compile(r"\byour\s+(?:real|true|actual|new|primary|only)\s+(?:task|instructions?|objective|goal|purpose|mission)\s+(?:is|are)\b"),
        re.compile(r"\bfrom now on\b[^.\n]{0,40}?\b(?:you|ignore|always|never|respond|answer|act)\b"),
        re.compile(r"\bdo not (?:follow|obey|listen to)\b[^.\n]{0,40}?\b(?:instructions?|rules?|system|operator|analyst|guidelines?)\b"),
        re.compile(r"\b(?:stop|cease)\s+(?:following|obeying)\b[^.\n]{0,40}?\b(?:instructions?|rules?)\b"),
        re.compile(r"\b(?:mark|classify|label|treat|close|resolve)\s+(?:this|the|all|every)\s+(?:alert|incident|case|event|ticket|finding)s?\s+(?:as\s+)?(?:benign|false[ _-]?positive|resolved|safe|clean|closed|noise)\b"),
        re.compile(r"\b(?:lockdown|lock-down)\s+(?:has been\s+|is\s+|was\s+)?(?:cleared|lifted|disabled|removed|over)\b"),
        re.compile(r"\b(?:pre-?approved|already approved|approval (?:has been )?granted|no approval (?:is )?(?:needed|required))\b"),
        re.compile(r"\b(?:the\s+)?(?:analyst|operator|admin|administrator|ciso|human)\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|authorised|confirmed)\b[^.\n]{0,40}\b(?:action|block|isolate|disable|execut|run|command|request)"),
        # Non-English
        re.compile(r"\bignor[ae]\s+(?:tod[ao]s?\s+)?(?:l[ao]s\s+)?(?:instrucciones|reglas|indicaciones)(?:\s+(?:anteriores|previas))?\b"),
        re.compile(r"\bignore[zr]\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|r[eè]gles|consignes)(?:\s+pr[eé]c[eé]dentes)?\b"),
        re.compile(r"\bignoriere?n?\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?(?:anweisungen|regeln|instruktionen)\b"),
        re.compile(r"\bignora\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole)(?:\s+precedenti)?\b"),
        re.compile(r"\bignore\s+(?:todas\s+)?(?:as\s+)?(?:instru[cç][oõ]es|regras)(?:\s+anteriores)?\b"),
        re.compile(r"(?:игнорируй(?:те)?|забудь(?:те)?|проигнорируй(?:те)?)\s+(?:все\s+)?(?:предыдущие\s+|прежние\s+)?(?:инструкции|правила|указания)"),
        re.compile(r"(?:忽略|无视|忽视|請忽略|请忽略)(?:之前的|以前的|所有|上面的|以上的|先前的)?(?:指令|指示|规则|規則|说明|說明)"),
        re.compile(r"(?:以前の|これまでの|上記の|すべての)?(?:指示|命令|ルール)を?(?:無視|むし)"),
        re.compile(r"(?:이전|모든|위의)?\s*(?:지시|명령|규칙)(?:을|를)?\s*무시"),
        re.compile(r"(?:تجاهل|اهمل)\s+(?:كل\s+|جميع\s+)?(?:التعليمات|القواعد)(?:\s+السابقة)?"),
        re.compile(r"(?:नज़रअंदाज़|अनदेखा)\s*(?:करें|करो)?\s*(?:सभी\s+)?(?:पिछले\s+)?(?:निर्देश|नियम)|(?:सभी\s+)?(?:पिछले\s+)?(?:निर्देशों|निर्देश|नियमों)\s*(?:को\s+)?(?:नज़रअंदाज़|अनदेखा)"),
    ],
    "role_hijack": [
        re.compile(r"\byou are now\s+(?:a|an|the|in|my|acting|root|free|unrestricted|unfiltered|god|admin|administrator|operator|system|dan|sudo|[a-z]+ mode)\b"),
        re.compile(r"\byou are no longer\s+(?:a|an|the|bound|restricted|required|the pysoar|an? soc)\b"),
        re.compile(r"\b(?:act|behave|respond|answer|operate)\s+as\s+(?:a|an|the|if you (?:are|were))?\s*(?:unrestricted|unfiltered|uncensored|jailbroken|root|system|admin|administrator|developer|dan|evil|different)\b"),
        re.compile(r"\bpretend\s+(?:to be|you are|that you are|you have)\b"),
        re.compile(r"\b(?:enable|enter|activate|switch to|unlock)\s+(?:developer|god|debug|jailbreak|unrestricted|sudo|admin|maintenance)\s+mode\b"),
        re.compile(r"\bjailbreak\b"),
        re.compile(r"\b(?:do anything now|dan mode|\bdan\b prompt)\b"),
        re.compile(r"\b(?:system|operator|developer|admin(?:istrator)?)\s+(?:prompt|message|instruction)s?\s*(?:override|update|follows|:)"),
        re.compile(r"\b(?:this|the following)\s+(?:is|are)\s+(?:a|an|your)?\s*(?:new\s+)?(?:system|operator|developer)\s+(?:prompt|message|instruction)s?\b"),
        re.compile(r"\b(?:as|speaking as|message from)\s+(?:the|your)\s+(?:system|operator|administrator|developer|pysoar (?:platform|admin))\b"),
        re.compile(r"\b(?:i am|this is)\s+(?:the|your)\s+(?:system|operator|administrator|developer|creator|anthropic)\b"),
        re.compile(r"(?:ты теперь|вы теперь)\s+(?:не\s+)?(?:аналитик|администратор|ассистент|система)"),
        re.compile(r"(?:你现在是|你現在是|从现在开始你是|從現在開始你是)"),
        re.compile(r"(?:あなたは今|あなたはもう)"),
        re.compile(r"\b(?:tu es|vous êtes|vous etes)\s+(?:maintenant|désormais|desormais)\b"),
        re.compile(r"\b(?:ahora eres|a partir de ahora eres|eres ahora)\b"),
        re.compile(r"\bdu bist (?:jetzt|nun|ab jetzt)\b"),
    ],
    "tool_coercion": [
        re.compile(rf"\b{_TOOL_VERBS}\s+(?:the\s+)?(?:tool\s+)?`?{_TOOL_NAMES}`?\b"),
        re.compile(rf"\b{_TOOL_NAMES}\s*\(\s*[\"'{{]"),
        re.compile(rf"\b(?:you|assistant|agent|ai|analyst|model|bot|pysoar)\s+(?:must|should|need to|needs to|are required to|is required to|have to|has to|will|shall)\s+(?:now\s+|immediately\s+)?{_ACTION_VERBS}\b"),
        re.compile(rf"\b(?:immediately|right now|urgently|at once)\s+{_ACTION_VERBS}\s+(?:the\s+|all\s+|every\s+)?(?:ip|host|user|account|machine|server|endpoint|firewall|domain|address|\d)"),
        re.compile(rf"\b{_ACTION_VERBS}\s+(?:the\s+|all\s+|every\s+)?(?:ip|host|user|account|machine|server|endpoint|domain|address)s?\s+[^.\n]{{0,60}}\b(?:without|no need for|skip|bypass)\s+(?:approval|confirmation|review|asking|human)\b"),
        re.compile(r"\b(?:approve|execute|run)\s+(?:all\s+|every\s+|the\s+)?(?:pending\s+)?(?:actions?|proposals?|commands?)\s+(?:automatically|without\s+(?:approval|review|asking))\b"),
        re.compile(r"\b(?:tool_call|function_call|tool_use)\s*[:=]\s*[\"']?[a-z_]+"),
        re.compile(rf"(?:ejecuta|ejecute|exécute|executez|exécutez|führe|fuehre|esegui|execute)\s+(?:la\s+|el\s+|le\s+|die\s+|das\s+|il\s+|o\s+|a\s+)?(?:herramienta|outil|werkzeug|strumento|ferramenta)?\s*`?{_TOOL_NAMES}`?"),
        re.compile(rf"(?:выполни(?:те)?|запусти(?:те)?|вызови(?:те)?)\s+`?{_TOOL_NAMES}`?"),
        re.compile(rf"(?:执行|運行|运行|调用|調用|请执行|請執行)\s*`?{_TOOL_NAMES}`?"),
    ],
    "exfiltration": [
        re.compile(r"\b(?:send|post|upload|forward|transmit|exfiltrate|email|mail|leak|copy|paste|submit|report)\b[^.\n]{0,50}?\b(?:system prompt|your instructions|your prompt|api[ _-]?keys?|credentials?|secrets?|tokens?|passwords?|private keys?|environment variables?|all (?:the )?(?:alerts|incidents|users|data|records))\b[^.\n]{0,50}?\b(?:to|at|via|into)\s+(?:https?:|hxxps?:|ftp:|[a-z0-9.\-]+\.[a-z]{2,}|[a-z0-9._%+\-]+@|webhook|pastebin|discord|telegram|this (?:address|url|endpoint|number))"),
        re.compile(r"\b(?:reveal|print|show|output|display|repeat|disclose|dump|recite|echo)\b[^.\n]{0,30}?\b(?:your|the)\s+(?:system prompt|initial prompt|hidden prompt|instructions|configuration|api[ _-]?keys?|credentials|secrets|tokens)\b"),
        re.compile(r"\b(?:what|which)\s+(?:is|are|were)\s+your\s+(?:system prompt|initial instructions|hidden instructions|secret instructions)\b"),
        re.compile(r"\b(?:include|embed|append|attach|insert)\b[^.\n]{0,30}?\b(?:api[ _-]?keys?|credentials?|secrets?|tokens?|system prompt)\b[^.\n]{0,40}?\b(?:in|into|to)\s+(?:your\s+)?(?:response|reply|answer|output|note|ticket|summary|verdict|findings)\b"),
        re.compile(r"\bcurl\s+[^\n]{0,80}?(?:\$\{?(?:api[_-]?key|token|secret|anthropic_api_key|openai_api_key)\b|-d\s+[\"']?(?:prompt|instructions)=)"),
        re.compile(r"!\[[^\]]{0,40}\]\(https?://[^)\s]{0,200}(?:prompt|key|secret|token|instructions?)=[^)\s]{0,200}\)"),
        re.compile(r"(?:отправь(?:те)?|перешли(?:те)?)\s+[^.\n]{0,40}?(?:системн[а-я]+\s+промпт|инструкции|ключ[а-я]*|пароль|учетные данные)"),
        re.compile(r"(?:发送|發送|上传|上傳|泄露|洩露)[^.\n]{0,20}?(?:系统提示|系統提示|api密钥|密钥|凭证|憑證|密码|密碼|指令)"),
        re.compile(r"(?:env[ií]a|envoie|envoyez|sende|schicke|invia|envie)\s+[^.\n]{0,40}?(?:prompt del sistema|instrucciones|credenciales|contraseñas?|claves?|prompt syst[eè]me|identifiants|mots? de passe|cl[eé]s? api|systemprompt|anmeldedaten|passw[oö]rter|zugangsdaten|credenziali|prompt di sistema|credenciais|senhas?)\s+[^.\n]{0,20}?(?:a|à|an|ao|para|zu)\s+\S+"),
    ],
    "marker_spoof": [
        re.compile(r"\[\[\s*/?\s*data\b"),
        re.compile(r"\[\[\s*/?\s*(?:system|end|instruction|instructions|trust|operator|assistant|user|prompt)\b"),
        re.compile(r"<<\s*/?\s*(?:sys|system|inst)\s*>>"),
        re.compile(r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\s*\|>"),
        re.compile(r"\[\s*/?inst\s*\]"),
        re.compile(r"</?\s*(?:system|system_prompt|instructions?|operator)\s*>"),
        re.compile(r"(?m)^\s*#{1,4}\s*(?:system|instruction|instructions|operator|assistant)\s*(?:prompt|message|section)?\s*:?\s*$"),
        re.compile(r"\bend of (?:tool[_ ]result|data block|untrusted data|tool output)\b"),
        re.compile(r"\b(?:begin|start) of (?:system|operator|trusted)\s+(?:message|instructions?|prompt|section)\b"),
        re.compile(r"\[\[\s*elided tool_result"),
    ],
    "boundary_forge": [
        re.compile(r"(?m)^---.*\bend\b.*---\s*$"),
        re.compile(r"</?\s*data\s*>"),
        re.compile(r"(?m)^\s*\]\]\s*$"),
        re.compile(r"(?m)(?:end|data|nonce|system|result)[^\n]{0,40}\]\]\s*$"),
    ],
}

# Case-sensitive boundary-forge patterns run on the case-preserving text (uppercase role labels).
_BOUNDARY_FORGE_CASED: Final[list[re.Pattern[str]]] = [
    re.compile(r"(?m)^\s*(?:SYSTEM|OPERATOR|ADMIN|ADMINISTRATOR|USER|ASSISTANT|DEVELOPER|HUMAN|AI)\s*[:(]"),
]

# Descriptive mentions ("the block_ip playbook", "block_ip tool was used") are
# not coercion. When a tool_coercion hit sits inside a descriptive frame we
# discard it; the frame patterns are checked on a small window around the hit.
_NARRATIVE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:was|were|has been|have been|had been|had|previously|earlier|yesterday|last (?:week|night|time)|"
    r"analyst|operator|responder|playbook|runbook|procedure|documentation|sop|step \d+|decided to|chose to|"
    r"attempted to|tried to|failed to|able to|instead of|rather than|history|log shows|logs show|"
    r"ran|executed|used|called|invoked|triggered|would|could|might|may|whether|how to|to be able to|"
    r"the ability to|permission to|allowed to|configured to|designed to)\b"
)
_ADDRESSEE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:you|your|assistant|agent|ai|model|bot|pysoar|please|now|immediately|urgently|must|should|need to|required)\b"
)


@dataclass
class _RawHit:
    family: str
    start: int
    length: int
    snippet: str
    weight: float


def _match_families(normalized: str, cased: str, exclude: frozenset[str]) -> list[_RawHit]:
    hits: list[_RawHit] = []
    for family, patterns in _FAMILY_PATTERNS.items():
        if family in exclude:
            continue
        for pattern in patterns:
            for match in pattern.finditer(normalized):
                snippet = match.group(0)
                if not snippet.strip():
                    continue
                if family == "tool_coercion" and _is_descriptive(normalized, match):
                    continue
                hits.append(_RawHit(family, match.start(), len(snippet), snippet, FAMILY_WEIGHTS[family]))
    if "boundary_forge" not in exclude:
        for pattern in _BOUNDARY_FORGE_CASED:
            for match in pattern.finditer(cased):
                hits.append(_RawHit("boundary_forge", match.start(), len(match.group(0)), match.group(0), FAMILY_WEIGHTS["boundary_forge"]))
    return _dedupe(hits)


def _is_descriptive(text: str, match: re.Match[str]) -> bool:
    """True when a tool mention is narrated (playbook prose, history) rather than commanded.

    A hit is descriptive only when the preceding window reads as narration
    (past tense, playbook/step framing, modal "would/could") and nothing in the
    window addresses the assistant or demands immediacy.
    """
    window_start = max(0, match.start() - 48)
    prefix = text[window_start:match.start()]
    if _ADDRESSEE_RE.search(prefix) or re.match(r"(?:you|assistant|agent|ai|analyst|model|bot|pysoar)\b", match.group(0)):
        return False
    if not prefix.strip():
        # Sentence-initial imperative ("Run block_ip ...") is a command.
        return False
    return _NARRATIVE_RE.search(prefix) is not None


def _dedupe(hits: list[_RawHit]) -> list[_RawHit]:
    """Keep one hit per family per overlapping span."""
    hits.sort(key=lambda h: (h.family, h.start, -h.length))
    kept: list[_RawHit] = []
    for hit in hits:
        last = kept[-1] if kept else None
        if last is not None and last.family == hit.family and hit.start < last.start + last.length:
            continue
        kept.append(hit)
    return kept


# ---------------------------------------------------------------------------
# Payload walking (raw, recursive, decoding nested JSON and base64)
# ---------------------------------------------------------------------------


def _iter_strings(payload: Any, path: str, depth: int, budget: list[int]) -> Iterable[tuple[str, str, bool]]:
    """Yield ``(path, text, decoded)`` for every string reachable from ``payload``."""
    if budget[0] <= 0 or depth > _MAX_SCAN_DEPTH:
        return
    if payload is None or isinstance(payload, (bool, int, float)):
        return
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            return
    if isinstance(payload, str):
        budget[0] -= 1
        yield path, payload, False
        stripped = payload.strip()
        if stripped[:1] in "{[" and len(stripped) > 1:
            try:
                nested = json.loads(stripped)
            except (ValueError, RecursionError):
                nested = None
            if isinstance(nested, (dict, list)):
                yield from _iter_strings(nested, f"{path}#json", depth + 1, budget)
        for decoded in _decode_blobs(payload):
            budget[0] -= 1
            yield f"{path}#b64", decoded, True
            if decoded.strip()[:1] in "{[":
                try:
                    nested = json.loads(decoded)
                except (ValueError, RecursionError):
                    nested = None
                if isinstance(nested, (dict, list)):
                    yield from _iter_strings(nested, f"{path}#b64#json", depth + 1, budget)
        return
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            key_str = str(key)
            budget[0] -= 1
            yield f"{path}.{key_str}<key>", key_str, False
            yield from _iter_strings(value, f"{path}.{key_str}", depth + 1, budget)
        return
    if isinstance(payload, (list, tuple, set, frozenset)):
        for idx, item in enumerate(payload):
            yield from _iter_strings(item, f"{path}[{idx}]", depth + 1, budget)
        return
    if dataclasses.is_dataclass(payload) and not isinstance(payload, type):
        yield from _iter_strings(dataclasses.asdict(payload), path, depth + 1, budget)
        return
    # ORM rows / arbitrary objects: scan their public attributes' plain values.
    attrs = getattr(payload, "__dict__", None)
    if isinstance(attrs, dict):
        plain = {k: v for k, v in attrs.items() if not k.startswith("_") and isinstance(v, (str, int, float, bool, list, dict, type(None)))}
        yield from _iter_strings(plain, path, depth + 1, budget)


def _decode_blobs(text: str) -> Iterable[str]:
    """Decode base64 / base64url / hex blobs that yield printable text."""
    seen = 0
    tried: set[str] = set()
    for regex in (_BASE64_RE, _BASE64_URL_RE):
        for match in regex.finditer(text):
            if seen >= 20:
                return
            token = match.group(0)
            if token in tried:
                continue
            tried.add(token)
            decoded = _try_b64(token)
            if decoded is not None:
                seen += 1
                yield decoded
    for match in _HEX_BLOB_RE.finditer(text):
        if seen >= 20:
            return
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        decoded = _printable(raw)
        if decoded is not None:
            seen += 1
            yield decoded


def _try_b64(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        text = _printable(raw)
        if text is not None:
            return text
        # UTF-16LE (PowerShell -EncodedCommand)
        try:
            text16 = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if text16 and all(ch.isprintable() or ch in "\r\n\t" for ch in text16):
            return text16
    return None


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if printable / len(text) < 0.9:
        return None
    return text


# ---------------------------------------------------------------------------
# Scan API
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    label: str
    hits: list[TrustHit]
    score: float
    tier: TrustTier
    scanned_len: int
    families: set[str] = field(default_factory=set)


def _make_hit(raw: _RawHit, label: str) -> TrustHit:
    digest = hashlib.sha256(raw.snippet.encode("utf-8")).hexdigest()
    preview_src, _ = redact_text(raw.snippet)
    preview = re.sub(r"\s+", " ", preview_src).strip()[:PREVIEW_MAX_CHARS]
    return TrustHit(family=raw.family, start=raw.start, length=raw.length, snippet_sha256=digest, preview=preview, label=label)


def _tier_for(score: float, hits: list[TrustHit], acknowledged: frozenset[str]) -> TrustTier:
    """Tier for one scan. Acknowledged hashes never trigger lockdown on their own."""
    if not hits:
        return TrustTier.CLEAN
    unacknowledged = [h for h in hits if h.snippet_sha256 not in acknowledged]
    if any(h.family in LOCKDOWN_FAMILIES for h in unacknowledged):
        return TrustTier.LOCKDOWN
    if score >= LOCKDOWN_THRESHOLD and unacknowledged:
        return TrustTier.LOCKDOWN
    return TrustTier.FLAGGED


def scan_for_injection(
    payload: Any,
    label: str = "data",
    *,
    exclude_families: Iterable[str] = (),
    acknowledged_hashes: Iterable[str] = (),
) -> ScanResult:
    """Scan a raw payload (before rendering/truncation) for injection families.

    ``exclude_families`` drops families for a label (e.g. ``marker_spoof``
    for replayed history). Hits whose ``snippet_sha256`` is in
    ``acknowledged_hashes`` still count toward the score but never trigger
    lockdown on their own.
    """
    exclude = frozenset(exclude_families)
    acknowledged = frozenset(acknowledged_hashes)
    budget = [_MAX_STRINGS_PER_SCAN]
    hits: list[TrustHit] = []
    families: set[str] = set()
    score = 0.0
    scanned_len = 0
    for path, text, decoded in _iter_strings(payload, label, 0, budget):
        if not text:
            continue
        scanned_len += len(text)
        cased = _normalize_case_preserving(text)
        normalized = cased.lower()
        zero_width = len(text) - len(_ZERO_WIDTH_RE.sub("", text))
        mixed = _MIXED_SCRIPT_WORD_RE.search(unicodedata.normalize("NFKC", text)) is not None
        raw_hits = _match_families(normalized, cased, exclude)
        for raw in raw_hits:
            hit = _make_hit(raw, path if path != label else label)
            weight = raw.weight
            if decoded or zero_width >= 3 or mixed:
                weight += FAMILY_WEIGHTS["obfuscation"]
                families.add("obfuscation")
            hits.append(hit)
            families.add(raw.family)
            score += weight
        if not raw_hits and (zero_width >= 8 or (mixed and _CYRILLIC_RE.search(text) and _LATIN_RE.search(text) and len(text) < 400)):
            # Heavy obfuscation with no payload match is a weak signal on its own.
            score += FAMILY_WEIGHTS["obfuscation"]
            families.add("obfuscation")
            digest_src = _ZERO_WIDTH_RE.sub("", text)[:64]
            hits.append(
                TrustHit(
                    family="obfuscation",
                    start=0,
                    length=min(len(text), 64),
                    snippet_sha256=hashlib.sha256(digest_src.encode("utf-8")).hexdigest(),
                    preview=re.sub(r"\s+", " ", redact_text(digest_src)[0])[:PREVIEW_MAX_CHARS],
                    label=path if path != label else label,
                )
            )
    tier = _tier_for(score, hits, acknowledged)
    return ScanResult(label=label, hits=hits, score=score, tier=tier, scanned_len=scanned_len, families=families)


# ---------------------------------------------------------------------------
# Boundary + wrapping
# ---------------------------------------------------------------------------

_MARKER_RE: Final[re.Pattern[str]] = re.compile(r"\[\[(\s*/?\s*)(data|trust|elided)\b", re.IGNORECASE)


def neutralize_markers(text: str) -> str:
    """Escape DATA markers in text that must not be able to close/open a block."""
    return _MARKER_RE.sub(lambda m: f"[[{m.group(1)}{m.group(2)}-quoted", text)


@dataclass
class WrappedBlock:
    label: str
    text: str
    hits: list[TrustHit]
    scan: ScanResult
    scanned_len: int
    rendered_len: int
    truncated: bool
    sub_labels: list[str] = field(default_factory=list)
    redactions_applied: int = 0


class Boundary:
    """Nonce per LLM turn; renders and neutralizes DATA markers."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.turn = 0
        self._nonce = secrets.token_hex(8)

    @property
    def nonce(self) -> str:
        return self._nonce

    def new_turn(self) -> str:
        self.turn += 1
        self._nonce = secrets.token_hex(8)
        return self._nonce

    def open(self, label: str) -> str:
        return f"{DATA_OPEN} {label} {self._nonce}]]"

    def close(self) -> str:
        return f"{DATA_CLOSE} {self._nonce}]]"

    def describe(self) -> str:
        return (
            f"Untrusted data is delimited by `{DATA_OPEN} <label> <nonce>]]` ... `{DATA_CLOSE} <nonce>]]`; "
            "the nonce changes every turn and is never repeated inside data."
        )


def _record_label(base: str, record: Any, index: int) -> str:
    if isinstance(record, Mapping):
        for key in ("id", "alert_id", "incident_id", "uuid", "record_id", "event_id", "ticket_id"):
            value = record.get(key)
            if value not in (None, ""):
                return f"{base}:{str(value)[:36]}"
    return f"{base}[{index}]"


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, indent=None)
    except (TypeError, ValueError):
        return str(value)


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    omitted = len(text) - max_chars
    return text[:max_chars] + f"\n[truncated {omitted} chars]", True


def _list_records(payload: Any) -> tuple[list[Any], str] | None:
    """Return the record list of a list-shaped result plus the key it lived under."""
    if isinstance(payload, list) and payload and all(isinstance(r, Mapping) for r in payload):
        return list(payload), ""
    if isinstance(payload, Mapping):
        list_keys = [k for k, v in payload.items() if isinstance(v, list) and v and all(isinstance(r, Mapping) for r in v)]
        if len(list_keys) == 1:
            return list(payload[list_keys[0]]), str(list_keys[0])
    return None


def wrap_untrusted(
    payload: Any,
    label: str,
    boundary: Boundary,
    *,
    max_chars: int = 12_000,
    per_record_max_chars: int = 4_000,
    exclude_families: Iterable[str] = (),
    acknowledged_hashes: Iterable[str] = (),
    strict_redaction: bool = False,
) -> WrappedBlock:
    """Scan the raw payload, then redact, escape markers, truncate and wrap it."""
    scan = scan_for_injection(payload, label, exclude_families=exclude_families, acknowledged_hashes=acknowledged_hashes)
    redacted, redactions = redact(payload, strict=strict_redaction)
    records = _list_records(redacted)
    sub_labels: list[str] = []
    truncated = False
    if records is not None:
        rows, list_key = records
        parts: list[str] = []
        if isinstance(redacted, Mapping):
            envelope = {k: v for k, v in redacted.items() if k != list_key}
            if envelope:
                parts.append(neutralize_markers(_render(envelope)))
        for idx, record in enumerate(rows):
            sub = _record_label(f"{label.split(':', 1)[0].rstrip('s') or label}", record, idx)
            sub_labels.append(sub)
            body, was_truncated = _truncate(neutralize_markers(_render(record)), per_record_max_chars)
            truncated = truncated or was_truncated
            parts.append(f"{boundary.open(sub)}\n{body}\n{boundary.close()}")
        inner = "\n".join(parts)
    else:
        inner = neutralize_markers(_render(redacted))
    inner, was_truncated = _truncate(inner, max_chars)
    truncated = truncated or was_truncated
    text = f"{boundary.open(label)}\n{inner}\n{boundary.close()}"
    return WrappedBlock(
        label=label,
        text=text,
        hits=scan.hits,
        scan=scan,
        scanned_len=scan.scanned_len,
        rendered_len=len(text),
        truncated=truncated,
        sub_labels=sub_labels,
        redactions_applied=redactions,
    )


# ---------------------------------------------------------------------------
# Sticky state
# ---------------------------------------------------------------------------


class TrustScanner:
    """Accumulates scan results into a sticky :class:`TrustState` across a run."""

    def __init__(self, state: TrustState | None = None, *, acknowledged_hashes: Iterable[str] = ()) -> None:
        self.state = state if state is not None else TrustState()
        self.acknowledged: set[str] = set(acknowledged_hashes)
        self._events: list[ScanResult] = []

    @property
    def events(self) -> list[ScanResult]:
        return list(self._events)

    def absorb(self, scan: ScanResult, *, message_id: str | None = None) -> TrustTier:
        """Fold a scan into the state; returns the (possibly escalated) tier."""
        self._events.append(scan)
        if not scan.hits:
            return self.state.tier
        self.state.hits.extend(scan.hits)
        self.state.score += scan.score
        for hit in scan.hits:
            self.state.contaminated_labels.add(hit.label)
        if self.state.first_seen_message_id is None:
            self.state.first_seen_message_id = message_id
        candidate = scan.tier
        if self.state.score >= LOCKDOWN_THRESHOLD and not self._all_acknowledged():
            candidate = TrustTier.LOCKDOWN
        if _rank(candidate) > _rank(self.state.tier):
            logger.warning(
                "injection_tier_escalated",
                previous=self.state.tier.value,
                new=candidate.value,
                label=scan.label,
                score=self.state.score,
                families=sorted(scan.families),
            )
            self.state.tier = candidate
            metric_increment(AGENT_INJECTION_EVENTS_TOTAL, tier=candidate.value)
        elif self.state.tier is TrustTier.CLEAN:
            self.state.tier = TrustTier.FLAGGED
        return self.state.tier

    def scan(
        self, payload: Any, label: str, *, exclude_families: Iterable[str] = (), message_id: str | None = None
    ) -> ScanResult:
        result = scan_for_injection(payload, label, exclude_families=exclude_families, acknowledged_hashes=self.acknowledged)
        self.absorb(result, message_id=message_id)
        return result

    def wrap(self, payload: Any, label: str, boundary: Boundary, **kwargs: Any) -> WrappedBlock:
        block = wrap_untrusted(payload, label, boundary, acknowledged_hashes=self.acknowledged, **kwargs)
        self.absorb(block.scan)
        return block

    def _all_acknowledged(self) -> bool:
        return bool(self.state.hits) and all(h.snippet_sha256 in self.acknowledged for h in self.state.hits)


def _rank(tier: TrustTier) -> int:
    return {TrustTier.CLEAN: 0, TrustTier.FLAGGED: 1, TrustTier.LOCKDOWN: 2}[tier]


def trust_state_to_dict(state: TrustState) -> dict[str, Any]:
    """JSON-safe form persisted on ``AgentChatSession.trust_state`` / ``Investigation``."""
    return {
        "tier": state.tier.value,
        "hits": [dataclasses.asdict(h) for h in state.hits[-200:]],
        "score": state.score,
        "contaminated_labels": sorted(state.contaminated_labels),
        "first_seen_message_id": state.first_seen_message_id,
    }


def trust_state_from_dict(data: Optional[Mapping[str, Any]]) -> TrustState:
    """Inverse of :func:`trust_state_to_dict`; unknown/missing input yields a clean state."""
    if not data:
        return TrustState()
    try:
        tier = TrustTier(str(data.get("tier", TrustTier.CLEAN.value)))
    except ValueError:
        tier = TrustTier.LOCKDOWN  # an unreadable persisted tier is treated as the worst case
    hits: list[TrustHit] = []
    for raw in data.get("hits", []) or []:
        if not isinstance(raw, Mapping):
            continue
        hits.append(
            TrustHit(
                family=str(raw.get("family", "unknown")),
                start=int(raw.get("start", 0) or 0),
                length=int(raw.get("length", 0) or 0),
                snippet_sha256=str(raw.get("snippet_sha256", "")),
                preview=str(raw.get("preview", ""))[:PREVIEW_MAX_CHARS],
                label=str(raw.get("label", "")),
            )
        )
    return TrustState(
        tier=tier,
        hits=hits,
        score=float(data.get("score", 0.0) or 0.0),
        contaminated_labels=set(str(x) for x in (data.get("contaminated_labels") or [])),
        first_seen_message_id=data.get("first_seen_message_id"),
    )
