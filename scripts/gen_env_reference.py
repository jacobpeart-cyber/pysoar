"""Generate docs/install/environment.md, the environment-variable reference.

Sources, all read from the code rather than written by hand:

1. ``Settings`` in ``src/core/config.py`` (pydantic-settings): every field,
   its environment name(s), type, default, whether it is a secret, and the
   validators that apply to it.
2. Direct ``os.environ`` / ``os.getenv`` reads under ``src/`` and
   ``alembic/`` (found with ``ast``), with their in-code defaults.
3. ``${NAME}`` interpolations in ``docker-compose.yml``.

The production rules in ``PRODUCTION_RULES`` are prose, so each one names an
anchor string that must still appear in the file it cites; generation fails
when the code no longer contains it. A field whose name looks secret-bearing
must be classified in ``SECRET_FIELDS`` or ``NOT_SECRET_DESPITE_NAME``, and
every field validator must have a description, so a new setting cannot slip
into the reference unclassified.

Usage:
    python scripts/gen_env_reference.py           # rewrite the doc
    python scripts/gen_env_reference.py --check   # exit 1 when it is stale

tests/unit/test_env_reference_doc.py runs the same check.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import typing
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = REPO_ROOT / "docs" / "install" / "environment.md"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
SCAN_ROOTS = ("src", "alembic")

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Settings fields holding credentials, or URLs that normally embed them.
SECRET_FIELDS = {
    "secret_key": "signs sessions and internal tokens",
    "jwt_secret_key": "signs access and refresh tokens",
    "encryption_master_key": "encrypts stored credentials; losing it loses them",
    "first_admin_password": "initial password of the first administrator",
    "database_url": "contains the database password",
    "redis_url": "contains the Redis password when Redis requires one",
    "celery_broker_url": "contains the Redis password when Redis requires one",
    "celery_result_backend": "contains the Redis password when Redis requires one",
    "virustotal_api_key": "provider API key",
    "abuseipdb_api_key": "provider API key",
    "shodan_api_key": "provider API key",
    "greynoise_api_key": "provider API key",
    "urlscan_api_key": "provider API key",
    "hibp_api_key": "provider API key",
    "smtp_user": "SMTP login",
    "smtp_password": "SMTP password",
    "slack_webhook_url": "the URL is the credential",
    "teams_webhook_url": "the URL is the credential",
    "elasticsearch_api_key": "provider API key",
    "splunk_token": "provider token",
    "aws_access_key_id": "AWS credential",
    "aws_secret_access_key": "AWS credential",
    "anthropic_api_key": "provider API key",
    "openai_api_key": "provider API key",
    "gemini_api_key": "provider API key",
}

# Names that match the secret heuristic but hold no secret.
NOT_SECRET_DESPITE_NAME = {
    "jwt_algorithm",
    "access_token_expire_minutes",
    "refresh_token_expire_days",
    "llm_daily_token_budget",
    "llm_autonomous_daily_token_budget",
    "password_min_length",
}

SECRET_NAME_RE = re.compile(r"key|password|secret|token|_url$|_user$")

# Direct environment reads that are secrets (section 2).
SECRET_DIRECT = {"OTX_API_KEY", "ABUSECH_AUTH_KEY", "NVD_API_KEY"}

# Compose-only interpolation variables that are secrets (section 3).
SECRET_COMPOSE = {"REDIS_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "POSTGRES_PASSWORD"}

# Every @field_validator on Settings, described. Generation fails when a
# validator is added without a description here.
VALIDATOR_DESCRIPTIONS = {
    "parse_debug": (
        "Strings `release`, `prod`, `production` mean false; `debug`, `dev`, "
        "`development` mean true; other values are parsed as a boolean."
    ),
    "parse_cors_origins": (
        "A JSON list, or a comma-separated string."
    ),
    "parse_ot_discovery_allowed_cidrs": (
        "A JSON list, or a comma-separated string; empty means `[]`."
    ),
    "parse_outbound_private_allowlist": (
        "A JSON list, or a comma-separated string, of CIDRs; empty means `[]`. "
        "Each entry is normalised to its network (host bits dropped); an entry "
        "that is not a CIDR fails settings load."
    ),
    "validate_database_ssl_mode": (
        "When `APP_ENV=production`, must be `require`, `verify-full` or "
        "`disable`, or the settings fail to load (every process that imports "
        "them exits)."
    ),
    "parse_llm_prices": "A JSON object; an empty string means `{}`.",
    "validate_reserve_pct": "Must be between 0 and 100.",
}


@dataclass(frozen=True)
class ProductionRule:
    fields: tuple[str, ...]
    text: str
    source: str  # repo-relative path
    anchor: str  # must appear verbatim in source
    production: bool = True  # False: a behaviour note that applies everywhere


PRODUCTION_RULES = (
    ProductionRule(
        ("outbound_private_allowlist",),
        "Outbound integration calls (connectors, the SIEM pollers for Splunk, "
        "Elastic and QRadar, and every other caller of the netguard) refuse a "
        "target that resolves to a private address (RFC 1918, IPv6 ULA, "
        "100.64/10 and other non-global unicast) unless the address is inside "
        "one of these networks. Loopback, link-local (169.254/16, fe80::/10), "
        "the cloud metadata addresses (169.254.169.254, fd00:ec2::254), "
        "multicast, unspecified and reserved addresses stay refused whatever "
        "the list says. Operator-level: tenants cannot change it. Read on "
        "every call.",
        "src/integrations/netguard.py",
        'getattr(settings, "outbound_private_allowlist", None)',
        production=False,
    ),
    ProductionRule(
        ("app_env",),
        "`production` (exact string) arms every rule marked Production in this "
        "table. The backend image sets `APP_ENV=production`; a value in `.env` "
        "or the container environment overrides it.",
        "src/core/config.py",
        'return self.app_env == "production"',
        production=False,
    ),
    ProductionRule(
        ("database_ssl_mode",),
        "On PostgreSQL the value is passed to asyncpg as its `ssl` argument, "
        "unless `DATABASE_URL` already carries `ssl=` or `sslmode=`, which then "
        "wins.",
        "src/core/database.py",
        'args["ssl"] = settings.database_ssl_mode',
        production=False,
    ),
    ProductionRule(
        ("secret_key", "jwt_secret_key"),
        "The api refuses to start when the value's Shannon entropy is below "
        "3.0 bits per character or it contains `change`, `default`, "
        "`password`, `secret`, `admin`, `test`, `example` or `placeholder` "
        "(case-insensitive). The defaults fail this check.",
        "src/core/config.py",
        'weak_patterns = ["change", "default", "password", "secret", "admin", "test", "example", "placeholder"]',
    ),
    ProductionRule(
        ("encryption_master_key",),
        "Required: the api refuses to start without it. It must be the "
        "base64 encoding of exactly 32 bytes (`openssl rand -base64 32`).",
        "src/main.py",
        "ENCRYPTION_MASTER_KEY must be set in production environment",
    ),
    ProductionRule(
        ("database_url",),
        "For a PostgreSQL URL the api refuses to start when the password is "
        "empty, the bundled default `pysoar`, shorter than 12 characters or "
        "contains a weak word; `deploy/configure-env.sh` generates a random "
        "`POSTGRES_PASSWORD` and writes it into both.",
        "src/core/config.py",
        'db_password == "pysoar"',
    ),
    ProductionRule(
        ("first_admin_email",),
        "The api refuses to start when the address is one the sign-in form "
        "refuses (email-validator rejects special-use domains such as .local, "
        ".test and .invalid), because the administrator it creates could never "
        "sign in. Read only while the `users` table is empty.",
        "src/core/config.py",
        "TypeAdapter(EmailStr).validate_python(self.first_admin_email)",
    ),
    ProductionRule(
        ("first_admin_password",),
        "The api refuses to start when its Shannon entropy is below 3.0 bits "
        "per character or it contains a weak word (change, default, password, "
        "secret, admin, test, example, placeholder), so the default "
        "`changeme123` is refused. The account is created only when the "
        "`users` table is empty, and must change its password at first login.",
        "src/core/config.py",
        '("first_admin_password", self.first_admin_password),',
    ),
    ProductionRule(
        ("cors_origins",),
        "Origins containing `localhost` or `127.0.0.1` are dropped.",
        "src/main.py",
        'cors_origins = [origin for origin in cors_origins if "localhost" not in origin and "127.0.0.1" not in origin]',
    ),
    ProductionRule(
        ("sim_agent_seed_enabled",),
        "Unset means off in production and on elsewhere.",
        "src/core/config.py",
        "return not self.is_production",
    ),
)


# --------------------------------------------------------------- settings --


def _type_name(annotation) -> str:
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Annotated:
        return _type_name(args[0])
    if origin is typing.Literal:
        return " \\| ".join(f"`{a}`" for a in args)
    if origin is typing.Union:
        non_none = [a for a in args if a is not type(None)]
        inner = " \\| ".join(_type_name(a) for a in non_none)
        return f"{inner} (optional)" if len(non_none) < len(args) else inner
    if origin in (list, typing.List):
        return f"list[{_type_name(args[0])}]" if args else "list"
    if origin is dict:
        return f"dict[{', '.join(_type_name(a) for a in args)}]" if args else "dict"
    if isinstance(annotation, type):
        return annotation.__name__
    return str(annotation)


def _is_json_type(annotation) -> bool:
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        return _is_json_type(typing.get_args(annotation)[0])
    return origin in (list, typing.List, dict)


def _default_text(value) -> str:
    if value is None:
        return "unset"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, (list, dict)):
        return f"`{json.dumps(value, separators=(',', ':'))}`"
    if isinstance(value, str) and value == "":
        return '`""`'
    return f"`{value}`"


def _env_names(name: str, field) -> list[str]:
    alias = field.validation_alias
    names: list[str] = []
    if alias is not None and hasattr(alias, "choices"):
        for choice in alias.choices:
            if isinstance(choice, str):
                upper = choice.upper()
                if upper not in names:
                    names.append(upper)
    if name.upper() not in names:
        names.append(name.upper())
    return names


def _validators_by_field(settings_cls) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    decorators = settings_cls.__pydantic_decorators__.field_validators
    for vname, dec in decorators.items():
        if vname not in VALIDATOR_DESCRIPTIONS:
            raise SystemExit(
                f"Settings validator {vname!r} has no entry in VALIDATOR_DESCRIPTIONS "
                "(scripts/gen_env_reference.py); describe it before regenerating.",
            )
        for f in dec.info.fields:
            out.setdefault(f, []).append(vname)
    stale = set(VALIDATOR_DESCRIPTIONS) - set(decorators)
    if stale:
        raise SystemExit(f"VALIDATOR_DESCRIPTIONS names validators that no longer exist: {sorted(stale)}")
    return out


def _check_rules(field_names: set[str]) -> None:
    for rule in PRODUCTION_RULES:
        for f in rule.fields:
            if f not in field_names:
                raise SystemExit(f"production rule cites unknown setting {f!r}")
        text = (REPO_ROOT / rule.source).read_text(encoding="utf-8")
        if rule.anchor not in text:
            raise SystemExit(
                f"production rule for {rule.fields} cites {rule.source}, which no longer "
                f"contains {rule.anchor!r}; re-read the code and update PRODUCTION_RULES.",
            )


def _classify(field_names: set[str]) -> None:
    unknown = set(SECRET_FIELDS) - field_names
    if unknown:
        raise SystemExit(f"SECRET_FIELDS names settings that no longer exist: {sorted(unknown)}")
    unclassified = sorted(
        n for n in field_names
        if SECRET_NAME_RE.search(n) and n not in SECRET_FIELDS and n not in NOT_SECRET_DESPITE_NAME
    )
    # URLs without credentials in them are declared here rather than as secrets.
    unclassified = [n for n in unclassified if n not in _PLAIN_URLS]
    if unclassified:
        raise SystemExit(
            "settings whose names look secret-bearing are unclassified: "
            f"{unclassified}; add each to SECRET_FIELDS or NOT_SECRET_DESPITE_NAME.",
        )


_PLAIN_URLS = {"ollama_base_url", "openai_base_url", "elasticsearch_url", "darkweb_marketplace_feed_url"}


def _settings_section() -> list[str]:
    from src.core.config import Settings

    fields = Settings.model_fields
    names = set(fields)
    _classify(names)
    _check_rules(names)
    validators = _validators_by_field(Settings)
    rules_by_field: dict[str, list[ProductionRule]] = {}
    for rule in PRODUCTION_RULES:
        for f in rule.fields:
            rules_by_field.setdefault(f, []).append(rule)

    lines = [
        "## 1. Application settings (`src/core/config.py`)",
        "",
        "Read by every backend process (api, worker, scheduler, flower and the "
        "migration command) from the process environment, and from a `.env` "
        "file in the working directory (`/app` in the backend image). Names are "
        "case-insensitive; unknown names are ignored. List and object settings "
        "take JSON.",
        "",
        "| Variable | Type | Default | Secret | Validation and production rules |",
        "|---|---|---|---|---|",
    ]
    for name, field in fields.items():
        env = "<br>".join(f"`{n}`" for n in _env_names(name, field))
        type_text = _type_name(field.annotation)
        if _is_json_type(field.annotation):
            type_text += " (JSON)"
        secret = "yes" if name in SECRET_FIELDS else "no"
        notes: list[str] = []
        for v in validators.get(name, []):
            notes.append(VALIDATOR_DESCRIPTIONS[v])
        for rule in rules_by_field.get(name, []):
            label = "**Production:** " if rule.production else ""
            notes.append(f"{label}{rule.text} (`{rule.source}`)")
        if name in SECRET_FIELDS:
            notes.append(f"Secret: {SECRET_FIELDS[name]}.")
        lines.append(
            f"| {env} | {type_text} | {_default_text(field.default)} | {secret} | "
            f"{' '.join(notes) if notes else ''} |",
        )
    lines += [""]
    return lines


# --------------------------------------------------------- direct reads --


@dataclass
class DirectRead:
    name: str
    default: str
    where: str
    subscript: bool = False


def _env_call_key(node: ast.AST) -> ast.AST | None:
    """The key expression of os.environ.get(k) / os.getenv(k) / os.environ[k]."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        func = node.func
        if func.attr == "getenv" and node.args:
            return node.args[0]
        if (
            func.attr == "get"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "environ"
            and node.args
        ):
            return node.args[0]
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
        if isinstance(node.ctx, ast.Load):
            return node.slice
    return None


def _int_product(node: ast.AST) -> int | None:
    """Value of an integer product such as ``50 * 1024 * 1024``; None otherwise."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left, right = _int_product(node.left), _int_product(node.right)
        if left is not None and right is not None:
            return left * right
    return None


def _default_of(node: ast.AST, constants: dict[str, object]) -> str:
    if isinstance(node, ast.Call) and len(node.args) > 1:
        arg = node.args[1]
        if isinstance(arg, ast.Constant):
            return _default_text(arg.value)
        if isinstance(arg, ast.Name) and arg.id in constants:
            return _default_text(constants[arg.id])
        product = _int_product(arg)
        if product is not None:
            return f"`{product}`"
        return f"`{ast.unparse(arg)}`"
    if isinstance(node, ast.Subscript):
        return "none (KeyError when unset)"
    return "unset"


def _scan_file(path: Path) -> tuple[list[DirectRead], list[str]]:
    rel = path.relative_to(REPO_ROOT).as_posix()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    module_dicts: dict[str, list[str]] = {}
    constants: dict[str, object] = {}
    for stmt in tree.body:
        target = None
        value = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            target, value = stmt.target, stmt.value
        if isinstance(target, ast.Name) and isinstance(value, ast.Constant):
            constants[target.id] = value.value
        if isinstance(target, ast.Name) and isinstance(value, ast.Dict):
            vals = [v.value for v in value.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            if vals and len(vals) == len(value.values):
                module_dicts[target.id] = vals

    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def enclosing_function(node: ast.AST):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return None

    reads: list[DirectRead] = []
    dynamic: list[str] = []
    for node in ast.walk(tree):
        key = _env_call_key(node)
        if key is None:
            continue
        fn = enclosing_function(node)
        where = f"`{rel}`" + (f" `{fn.name}()`" if fn else "")
        default = _default_of(node, constants)
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            reads.append(DirectRead(key.value, default, where, isinstance(node, ast.Subscript)))
            continue
        if isinstance(key, ast.Subscript) and isinstance(key.value, ast.Name) and key.value.id in module_dicts:
            for v in module_dicts[key.value.id]:
                reads.append(DirectRead(v, default, where))
            continue
        if isinstance(key, ast.Name):
            params = [a.arg for a in fn.args.args] if fn else []
            if fn and key.id in params:
                pos = params.index(key.id)
                found = False
                for call in ast.walk(tree):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Name)
                        and call.func.id == fn.name
                        and len(call.args) > pos
                        and isinstance(call.args[pos], ast.Constant)
                        and isinstance(call.args[pos].value, str)
                    ):
                        caller = enclosing_function(call)
                        via = f" `{caller.name}()`" if caller else ""
                        reads.append(DirectRead(call.args[pos].value, default, f"`{rel}`{via} via `{fn.name}()`"))
                        found = True
                if found and fn.name in functions:
                    continue
        dynamic.append(where)
    return reads, dynamic


def _direct_section(settings_env: set[str]) -> list[str]:
    reads: list[DirectRead] = []
    dynamic: list[str] = []
    for root in SCAN_ROOTS:
        for path in sorted((REPO_ROOT / root).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            r, d = _scan_file(path)
            reads += r
            dynamic += d
    by_name: dict[str, list[DirectRead]] = {}
    for r in reads:
        by_name.setdefault(r.name, []).append(r)

    lines = [
        "## 2. Variables read directly from the environment",
        "",
        "These are read with `os.environ` / `os.getenv` outside `Settings`, so they "
        "come from the process environment only: a `.env` file is not read for them "
        "unless docker compose passes it (`env_file:`), as it does for the api, "
        "worker, scheduler and flower. Where a name is also a setting in section 1, "
        "the `Settings` value is used first.",
        "",
        "| Variable | In-code default | Secret | Read at |",
        "|---|---|---|---|",
    ]
    for name in sorted(by_name):
        items = [i for i in by_name[name] if not i.subscript] or by_name[name]
        defaults = sorted({i.default for i in items})
        wheres = "<br>".join(sorted({i.where for i in items}))
        also = " (also a setting)" if name in settings_env else ""
        secret = "yes" if name in SECRET_DIRECT or name in {n.upper() for n in SECRET_FIELDS} else "no"
        lines.append(f"| `{name}`{also} | {' / '.join(defaults)} | {secret} | {wheres} |")
    lines += [""]
    if dynamic:
        lines += [
            "Reads whose variable name is computed at runtime (not a fixed name, so "
            "not listed above):",
            "",
        ]
        lines += [f"- {w}" for w in sorted(set(dynamic))]
        lines += [""]
    return lines


# ----------------------------------------------------------------- compose --

COMPOSE_VAR_RE = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^}]*))?\}")


def _compose_section(settings_env: set[str]) -> list[str]:
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    found: dict[str, set[str]] = {}
    services_of: dict[str, set[str]] = {}
    section = ""
    service = ""
    for line in text.splitlines():
        top = re.match(r"^([A-Za-z][\w-]*):", line)
        if top:
            section, service = top.group(1), ""
        svc = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if svc and section == "services":
            service = svc.group(1)
        if line.lstrip().startswith("#"):
            continue
        for m in COMPOSE_VAR_RE.finditer(line):
            name, op, arg = m.group(1), m.group(2), m.group(3)
            if op in (":-", "-"):
                desc = f"default `{arg}`"
            elif op in (":?", "?"):
                desc = "required (compose refuses to start)"
            else:
                desc = "no default (empty when unset)"
            found.setdefault(name, set()).add(desc)
            services_of.setdefault(name, set()).add(service or section)
    out = [
        "## 3. docker compose interpolation (`docker-compose.yml`)",
        "",
        "docker compose substitutes these into `docker-compose.yml` itself, from the "
        "shell environment or the `.env` file next to the compose file. They configure "
        "the stack, not the application, unless the compose file also passes them to a "
        "container.",
        "",
        "| Variable | Behaviour when unset | Secret | Used by services |",
        "|---|---|---|---|",
    ]
    for name in sorted(found):
        also = " (also a setting)" if name in settings_env else ""
        secret = "yes" if name in SECRET_COMPOSE else "no"
        lns = ", ".join(f"`{n}`" for n in sorted(services_of[name]))
        out.append(f"| `{name}`{also} | {'; '.join(sorted(found[name]))} | {secret} | {lns} |")
    out += [""]
    return out


# ------------------------------------------------------------------ render --


def render() -> str:
    from src.core.config import Settings

    settings_env = set()
    for name, field in Settings.model_fields.items():
        settings_env.update(_env_names(name, field))
    parts = [
        "# Environment variable reference",
        "",
        "<!-- GENERATED by scripts/gen_env_reference.py. Do not edit by hand: run",
        "     `python scripts/gen_env_reference.py` and commit the result.",
        "     tests/unit/test_env_reference_doc.py fails when this file is stale. -->",
        "",
        "Every variable PySOAR's backend reads, generated from the code. Install guides: "
        "[compose](compose.md), [Kubernetes](kubernetes.md).",
        "",
        "Secret = yes means the value is a credential or contains one: keep it out of "
        "git, out of ConfigMaps and out of logs (on Kubernetes it belongs in the "
        "Secret named by `secret.existingSecret`).",
        "",
    ]
    parts += _settings_section()
    parts += _direct_section(settings_env)
    parts += _compose_section(settings_env)
    return "\n".join(parts).rstrip("\n") + "\n"


def _shown(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the doc is stale")
    args = parser.parse_args(argv)
    content = render()
    if args.check:
        current = DOC_PATH.read_text(encoding="utf-8") if DOC_PATH.exists() else ""
        if current.replace("\r\n", "\n") != content:
            print(f"{_shown(DOC_PATH)} is stale: run python scripts/gen_env_reference.py")
            return 1
        print(f"{_shown(DOC_PATH)} is current")
        return 0
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DOC_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    print(f"wrote {_shown(DOC_PATH)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
