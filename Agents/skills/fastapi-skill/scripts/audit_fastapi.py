#!/usr/bin/env python3
"""Deterministic AST architecture & security scanner for FastAPI projects.

Run by the Coder (pre-handoff), the Reviewer (Phase 1) and the Orchestrator
(sign-off gate).  Standard library only; Python 3.10+.

Usage:
    python audit_fastapi.py [paths ...] [--format text|json] [--root DIR]
                            [--exclude DIRNAME ...] [--allow-empty]
    python audit_fastapi.py --list-rules

Exit codes:  0 = clean   1 = violations found   2 = usage / target error
(A mistyped path or an empty scan is exit 2 -- never a silent pass.)

Rules (see RULES below for the authoritative list):
  ASYNC001/002  blocking I/O or CPU-bound work inside `async def`
  ARCH001-003   layer-boundary violations (routes / services / repositories)
  SEC001-011    output filtering, error leaks, secrets, JWT, SQL building,
                dangerous calls, unbounded uploads, CORS/debug, hard-coded secrets
  AUTH001       route with no visible authentication dependency (default-deny)
  LIFE001       stateful client created at import time or inside a route
  PYD001-004    Pydantic v2 input strictness, bounds, pagination caps, float money
  ERR001        swallowed / bare exceptions
  SUP001        invalid suppression comment

Suppression (only with a rule id AND a reason of >= 10 characters):
    risky_call()  # audit: ignore[SEC008] -- reads static schema at startup only
A blanket `# audit: ignore` is itself a violation (SUP001).

Layer override (first 10 lines of a file):   # audit: layer=service
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

__version__ = "2.1.0"

RULES: dict[str, str] = {
    "ASYNC001": "Blocking I/O call inside `async def` (blocks the event loop)",
    "ASYNC002": "CPU-bound call inside `async def` (use a threadpool / process pool)",
    "ARCH001": "Service/domain layer imports `fastapi` or `starlette`",
    "ARCH002": "Route layer runs queries or touches the DB session / transaction",
    "ARCH003": "Repository/adapter layer calls `.commit()` (use `.flush()`)",
    "SEC001": "Route has neither `response_model` nor a return type annotation",
    "SEC002": "Raw exception text / interpolated detail leaks into an HTTP response",
    "SEC003": "`os.getenv` / `os.environ` used outside the config module",
    "SEC004": "Route returns untyped `dict` / `Any` (no output filtering)",
    "SEC005": "JWT decode misconfigured (algorithms / aud / iss / required claims)",
    "SEC006": "Secret / token / signature compared with `==` (use `secrets.compare_digest`)",
    "SEC007": "SQL built from a dynamic string (f-string, `+`, `%`, `.format`)",
    "SEC008": "Dangerous call (eval/exec/pickle/unsafe yaml/shell=True/verify=False/...)",
    "SEC009": "Unbounded `UploadFile.read()` (memory exhaustion)",
    "SEC010": "Insecure app configuration (wildcard CORS, `debug=True`)",
    "SEC011": "Hard-coded secret literal",
    "AUTH001": "Route has no visible authentication/authorization dependency",
    "LIFE001": "Stateful client created at import time or inside a route function",
    "PYD001": "Input schema missing `extra='forbid'` + `str_strip_whitespace=True`",
    "PYD002": "Input schema `str`/collection field without `max_length`",
    "PYD003": "Pagination parameter (`limit`/`page_size`/`per_page`) without an upper bound",
    "PYD004": "`float` used for a monetary / financial field (use `Decimal`)",
    "ERR001": "Bare `except:` or an exception handler that silently swallows errors",
    "SUP001": "Invalid suppression: needs `ignore[RULE] -- reason (>=10 chars)`",
    "SYNTAX001": "File could not be read or parsed",
}

ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "api_route"}

BLOCKING_CALLS: dict[str, str] = {
    "time.sleep": "Use `await asyncio.sleep(...)`",
    "requests.get": "Use `httpx.AsyncClient`",
    "requests.post": "Use `httpx.AsyncClient`",
    "requests.put": "Use `httpx.AsyncClient`",
    "requests.patch": "Use `httpx.AsyncClient`",
    "requests.delete": "Use `httpx.AsyncClient`",
    "requests.head": "Use `httpx.AsyncClient`",
    "requests.request": "Use `httpx.AsyncClient`",
    "urllib.request.urlopen": "Use `httpx.AsyncClient`",
    "subprocess.run": "Use `asyncio.create_subprocess_exec`",
    "subprocess.call": "Use `asyncio.create_subprocess_exec`",
    "subprocess.check_call": "Use `asyncio.create_subprocess_exec`",
    "subprocess.check_output": "Use `asyncio.create_subprocess_exec`",
    "subprocess.Popen": "Use `asyncio.create_subprocess_exec`",
    "os.system": "Use `asyncio.create_subprocess_exec`",
    "os.popen": "Use `asyncio.create_subprocess_exec`",
    "shutil.copy": "Wrap in `run_in_threadpool`",
    "shutil.copy2": "Wrap in `run_in_threadpool`",
    "shutil.copyfile": "Wrap in `run_in_threadpool`",
    "shutil.copytree": "Wrap in `run_in_threadpool`",
    "shutil.move": "Wrap in `run_in_threadpool`",
    "shutil.rmtree": "Wrap in `run_in_threadpool`",
    "sqlite3.connect": "Use an async driver (aiosqlite) or a threadpool",
    "psycopg2.connect": "Use `asyncpg` / `psycopg` async",
    "pymysql.connect": "Use an async MySQL driver",
    "socket.create_connection": "Use `asyncio.open_connection`",
    "input": "Never read stdin in a request path",
}
BLOCKING_PATH_METHODS = {"read_text", "write_text", "read_bytes", "write_bytes"}
CPU_CALLS: dict[str, str] = {
    "bcrypt.hashpw": "Run password hashing via `run_in_threadpool`",
    "bcrypt.checkpw": "Run password hashing via `run_in_threadpool`",
    "hashlib.pbkdf2_hmac": "Run via `run_in_threadpool`",
    "hashlib.scrypt": "Run via `run_in_threadpool`",
    "pandas.read_csv": "Run via `run_in_threadpool`",
    "pandas.read_excel": "Run via `run_in_threadpool`",
    "pandas.read_parquet": "Run via `run_in_threadpool`",
    "pandas.read_json": "Run via `run_in_threadpool`",
}

STATEFUL_CLIENTS = {
    "httpx.AsyncClient", "httpx.Client", "aiohttp.ClientSession",
    "sqlalchemy.create_engine", "sqlalchemy.ext.asyncio.create_async_engine",
    "redis.Redis", "redis.StrictRedis", "redis.from_url", "redis.ConnectionPool",
    "redis.asyncio.Redis", "redis.asyncio.from_url", "redis.asyncio.ConnectionPool",
    "openai.OpenAI", "openai.AsyncOpenAI", "anthropic.Anthropic", "anthropic.AsyncAnthropic",
    "boto3.client", "boto3.resource", "aioboto3.Session",
    "pymongo.MongoClient", "motor.motor_asyncio.AsyncIOMotorClient", "asyncpg.create_pool",
}

QUERY_BUILDERS = {
    "sqlalchemy.select", "sqlalchemy.insert", "sqlalchemy.update", "sqlalchemy.delete",
    "sqlalchemy.text", "sqlmodel.select",
}
SESSION_METHODS = {
    "execute", "scalars", "scalar", "add", "add_all", "merge", "flush", "rollback",
    "refresh", "delete", "exec", "begin", "query", "commit",
}
SESSION_RECEIVER = re.compile(r"(?i)(^|\.|_)(session|db|conn|connection)$")

RESPONSE_SINKS = {
    "HTTPException", "JSONResponse", "ORJSONResponse", "UJSONResponse", "PlainTextResponse",
    "HTMLResponse", "Response", "ProblemDetail",
}
UNTYPED_RETURNS = {
    "dict", "Dict", "Any", "object", "typing.Any", "typing.Dict", "dict[str, Any]",
    "Dict[str, Any]", "dict[str, typing.Any]", "dict[str, object]", "Mapping[str, Any]",
}
PUBLIC_PATHS = {"/health", "/healthz", "/livez", "/readyz", "/ready", "/live", "/ping"}
AUTH_HINT = re.compile(
    r"(?i)(principal|current_?user|authenticated|auth|token|security|oauth|api_?key|bearer|"
    r"permission|require_|get_current|identity|claims)"
)
PAGINATION_NAMES = {"limit", "page_size", "per_page", "pagesize"}
UPPER_BOUND = re.compile(r"\b(le|lt)\s*=")
REQUEST_SUFFIX = re.compile(r"(Create|Update|Patch|Request|Input|Payload|Command|Params|Filter|Body)$")
MONEY_NAME = re.compile(r"(?i)(price|amount|cost|total|balance|fee|rate|salary|tax|discount|payment|revenue)")
SECRET_NAME = re.compile(
    r"(?i)(secret|password|passwd|api_?key|private_?key|secret_?key|access_?key|_token|^token)$"
)
SENSITIVE_PARTS = {"secret", "token", "signature", "sig", "apikey", "hmac", "digest",
                   "password", "passwd", "csrf", "otp", "nonce"}
BENIGN_SUFFIX = {"type", "url", "len", "length", "count", "id", "ttl", "exp", "expires", "name",
                 "field", "header", "prefix", "scheme", "algorithm", "alg", "kind", "size", "uri"}
SUPPRESS_RE = re.compile(r"#\s*audit:\s*ignore(?:\[(?P<rules>[A-Za-z0-9_,\s]+)\])?(?P<rest>.*)$")
LAYER_PRAGMA = re.compile(r"#\s*audit:\s*layer=(route|service|repository|config|test|other)\b")

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".nox", "site-packages", "build", "dist",
    "migrations", "alembic",
}


@dataclass(frozen=True, order=True)
class Violation:
    file: str
    line: int
    rule_id: str
    message: str

    def format(self) -> str:
        return f"[FAIL] {self.file}:{self.line} - [{self.rule_id}] {self.message}"


# --------------------------------------------------------------------------- helpers
def dotted(node: ast.AST) -> str:
    """`a.b.c` for a pure Name/Attribute chain, else ''."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def detect_layer(path: Path, root: Path | None, lines: list[str]) -> str:
    for line in lines[:10]:
        m = LAYER_PRAGMA.search(line)
        if m:
            return m.group(1)
    try:
        rel = path.resolve().relative_to((root or Path.cwd()).resolve())
    except ValueError:
        rel = Path(path.name)
    dirs = [p.lower() for p in rel.parts[:-1]]
    stem = rel.stem.lower()
    if (set(dirs) & {"tests", "test"} or stem.startswith("test_") or stem.endswith("_test")
            or stem == "conftest"):
        return "test"
    if stem in {"config", "settings", "env"}:
        return "config"
    if stem.endswith(("_service", "_usecase", "_use_case")):
        return "service"
    if stem.endswith(("_repository", "_repo", "_adapter")):
        return "repository"
    if stem.endswith(("_router", "_routes", "_endpoints")):
        return "route"
    mapping = {
        "route": {"routes", "routers", "router", "api", "endpoints"},
        "service": {"services", "service", "domain", "domains", "ports", "use_cases", "usecases"},
        "repository": {"repositories", "repository", "adapters", "adapter", "ai_adapters", "crud", "dal"},
        "other": {"models", "model", "schemas", "schema"},
    }
    for part in [stem, *reversed(dirs)]:  # deepest match wins
        for layer, names in mapping.items():
            if part in names:
                return layer
    return "other"


def parse_suppressions(lines: list[str]) -> tuple[dict[int, set[str]], list[tuple[int, str]]]:
    valid: dict[int, set[str]] = {}
    invalid: list[tuple[int, str]] = []
    for i, line in enumerate(lines, start=1):
        m = SUPPRESS_RE.search(line)
        if not m:
            continue
        rules_raw, rest = m.group("rules"), m.group("rest") or ""
        reason = rest.strip().lstrip("-—:– ").strip()
        if not rules_raw:
            invalid.append((i, "blanket `audit: ignore` is not allowed; name the rule(s)"))
        elif len(reason) < 10:
            invalid.append((i, "suppression needs a justification of at least 10 characters"))
        else:
            valid[i] = {r.strip().upper() for r in rules_raw.split(",") if r.strip()}
    return valid, invalid


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                return True
        return is_dynamic_string(node.left) or is_dynamic_string(node.right)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format" and isinstance(node.func.value, (ast.Constant, ast.JoinedStr))):
        return True
    return False


def sensitive_identifier(name: str) -> bool:
    parts = name.lower().split("_")
    if parts[-1] in BENIGN_SUFFIX:
        return False
    if "api" in parts and "key" in parts:
        return True
    return any(p in SENSITIVE_PARTS for p in parts)


def terminal_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return terminal_name(node.value)
    return ""


# --------------------------------------------------------------------------- auditor
class FastAPIAuditor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str, root: Path | None = None) -> None:
        self.file_path = file_path
        self.lines = source.splitlines()
        self.layer = detect_layer(file_path, root, self.lines)
        self.violations: set[Violation] = set()
        self.aliases: dict[str, str] = {}
        self.suppressions, invalid = parse_suppressions(self.lines)
        self._invalid_suppressions = invalid
        self._fn_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._exc_names: list[str] = []
        self._awaited: set[int] = set()
        self._global_auth_deps = False
        self._local_models: set[str] = set()
        self._compliant_models: set[str] = set()
        self._request_class: list[bool] = []

    # ---- reporting
    def _add(self, line: int, rule: str, message: str, end: int | None = None,
             start: int | None = None) -> None:
        for ln in range(start or line, (end or line) + 1):
            if rule in self.suppressions.get(ln, set()):
                return
        self.violations.add(Violation(str(self.file_path), line, rule, message))

    # ---- name resolution
    def _collect_aliases(self, tree: ast.AST) -> None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        root = a.name.split(".")[0]
                        self.aliases.setdefault(root, root)
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                for a in n.names:
                    self.aliases[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.Call):
                name = self.resolve(n.func)
                if name.endswith(("APIRouter", "FastAPI", "include_router")) and any(
                    kw.arg == "dependencies" for kw in n.keywords
                ):
                    self._global_auth_deps = True

    def resolve(self, node: ast.AST) -> str:
        d = dotted(node)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        base = self.aliases.get(head, head)
        return f"{base}.{rest}" if rest else base

    # ---- context
    @property
    def _in_async(self) -> bool:
        return bool(self._fn_stack) and isinstance(self._fn_stack[-1], ast.AsyncFunctionDef)

    def run(self, tree: ast.AST) -> list[Violation]:
        self._collect_aliases(tree)
        for line, why in self._invalid_suppressions:
            self.violations.add(Violation(str(self.file_path), line, "SUP001", why))
        self.visit(tree)
        return sorted(self.violations)

    # ---- imports (ARCH001)
    def visit_Import(self, node: ast.Import) -> None:
        if self.layer == "service":
            for a in node.names:
                if a.name.split(".")[0] in {"fastapi", "starlette"}:
                    self._add(node.lineno, "ARCH001",
                              f"Service/domain layer must not import '{a.name}'. Raise domain exceptions instead.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self.layer == "service" and node.module and node.level == 0:
            if node.module.split(".")[0] in {"fastapi", "starlette"}:
                self._add(node.lineno, "ARCH001",
                          f"Service/domain layer must not import from '{node.module}'. Keep HTTP concerns in routes.")
        self.generic_visit(node)

    # ---- functions / routes
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_fn(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_fn(node)

    def _visit_fn(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        pushed_exc = False
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "exception_handler" and len(node.args.args) >= 2):
                self._exc_names.append(node.args.args[1].arg)
                pushed_exc = True
            info = self._route_info(dec)
            if info and self.layer != "test":
                self._check_route(node, *info)
        self._fn_stack.append(node)
        self.generic_visit(node)
        self._fn_stack.pop()
        if pushed_exc:
            self._exc_names.pop()

    @staticmethod
    def _route_info(dec: ast.AST) -> tuple[str, str | None, ast.Call] | None:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return None
        method = dec.func.attr.lower()
        if method not in ROUTE_METHODS:
            return None
        path: str | None = None
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            path = dec.args[0].value
        else:
            for kw in dec.keywords:
                if kw.arg == "path" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    path = kw.value.value
        receiver = dotted(dec.func.value).lower()
        if path is None and not re.search(r"(router|app|api)$", receiver):
            return None
        return method, path, dec

    def _check_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef, method: str,
                     path: str | None, dec: ast.Call) -> None:
        kws = {kw.arg: kw.value for kw in dec.keywords if kw.arg}
        is_204 = False
        sc = kws.get("status_code")
        if isinstance(sc, ast.Constant) and sc.value == 204:
            is_204 = True
        elif isinstance(sc, (ast.Attribute, ast.Name)) and "204" in terminal_name(sc):
            is_204 = True
        rm = kws.get("response_model")
        rm_present = rm is not None and not (isinstance(rm, ast.Constant) and rm.value is None)
        has_response_class = "response_class" in kws
        span = {"start": dec.lineno, "end": node.lineno}  # suppression window: decorator..def
        ret = ast.unparse(node.returns) if node.returns is not None else ""
        has_return = bool(ret) and ret != "None"

        # SEC001 / SEC004: output filtering
        if not (is_204 or has_response_class):
            if not rm_present and not has_return:
                self._add(node.lineno, "SEC001",
                          f"Route '{node.name}' (@{method}) has neither `response_model=...` nor a return annotation.", **span)
            elif rm_present and ast.unparse(rm) in UNTYPED_RETURNS:
                self._add(node.lineno, "SEC004", f"Route '{node.name}' uses an untyped response_model ({ast.unparse(rm)}).", **span)
            elif not rm_present and ret in UNTYPED_RETURNS:
                self._add(node.lineno, "SEC004",
                          f"Route '{node.name}' returns untyped `{ret}`; declare a typed response schema.", **span)

        # AUTH001: default-deny
        if not self._global_auth_deps and "dependencies" not in kws and "security" not in kws \
                and (path or "").rstrip("/") not in PUBLIC_PATHS:
            texts: list[str] = []
            for arg, default in self._params(node):
                if arg.annotation is not None:
                    texts.append(ast.unparse(arg.annotation))
                if default is not None:
                    texts.append(ast.unparse(default))
            if not any(AUTH_HINT.search(t) for t in texts):
                self._add(node.lineno, "AUTH001",
                          f"Route '{node.name}' ({method.upper()} {path or '?'}) has no visible auth dependency. "
                          "Add one, or suppress with a justification if the route is intentionally public.", **span)

        # PYD003: unbounded pagination on query params
        for arg, default in self._params(node):
            if arg.arg.lower() in PAGINATION_NAMES:
                text = " ".join(ast.unparse(x) for x in (arg.annotation, default) if x is not None)
                if not UPPER_BOUND.search(text):
                    self._add(arg.lineno, "PYD003",
                              f"Pagination param '{arg.arg}' needs an upper bound, e.g. Query(default=20, ge=1, le=100).")

    @staticmethod
    def _params(node: ast.FunctionDef | ast.AsyncFunctionDef):
        a = node.args
        pos = [*a.posonlyargs, *a.args]
        defaults: list[ast.expr | None] = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
        yield from zip(pos, defaults)
        yield from zip(a.kwonlyargs, a.kw_defaults)

    # ---- await tracking
    def visit_Await(self, node: ast.Await) -> None:
        self._awaited.add(id(node.value))
        self.generic_visit(node)

    # ---- exception handlers (ERR001 + leak tracking)
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if self.layer != "test":
            body_trivial = all(
                isinstance(s, (ast.Pass, ast.Continue)) or
                (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                for s in node.body
            )
            if node.type is None:
                self._add(node.lineno, "ERR001", "Bare `except:` catches SystemExit/KeyboardInterrupt; name the exception.")
            elif body_trivial:
                self._add(node.lineno, "ERR001", "Exception silently swallowed; log it with a request_id or re-raise a domain error.")
        if node.name:
            self._exc_names.append(node.name)
        self.generic_visit(node)
        if node.name:
            self._exc_names.pop()

    # ---- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        receiver = dotted(node.func.value) if isinstance(node.func, ast.Attribute) else ""
        end = node.end_lineno
        non_test = self.layer != "test"

        if self._in_async and non_test:
            if name in BLOCKING_CALLS:
                self._add(node.lineno, "ASYNC001", f"Blocking call '{name}()' inside `async def`. {BLOCKING_CALLS[name]}.", end)
            elif name == "open" or (isinstance(node.func, ast.Name) and node.func.id == "open"):
                self._add(node.lineno, "ASYNC001", "Synchronous `open()` inside `async def`. Use `aiofiles` or `run_in_threadpool`.", end)
            elif attr in BLOCKING_PATH_METHODS and id(node) not in self._awaited:
                self._add(node.lineno, "ASYNC001", f"Synchronous `.{attr}()` inside `async def`. Use `run_in_threadpool`.", end)
            elif name in CPU_CALLS:
                self._add(node.lineno, "ASYNC002", f"CPU-bound '{name}()' inside `async def`. {CPU_CALLS[name]}.", end)

        if self.layer == "route":
            if name in QUERY_BUILDERS:
                self._add(node.lineno, "ARCH002", f"Query construction ('{name}') in route layer. Delegate to a repository.", end)
            elif attr in SESSION_METHODS and SESSION_RECEIVER.search(receiver):
                self._add(node.lineno, "ARCH002", f"DB session call '{receiver}.{attr}()' in route layer. Services own transactions; repositories own queries.", end)
        if self.layer == "repository" and attr == "commit":
            self._add(node.lineno, "ARCH003", "Repository calls `.commit()`. Use `.flush()`; the service layer owns commit/rollback.", end)

        if non_test:
            self._check_leaks(node, name, end)
            self._check_security_calls(node, name, attr, receiver, end)
            self._check_lifespan(node, name, end)

        if name in {"os.getenv", "os.environ.get", "os.environ.setdefault", "os.environ.pop"} \
                and self.layer not in {"config", "test"}:
            self._add(node.lineno, "SEC003", f"Direct '{name}()' outside the config module. Use centralized `pydantic-settings`.", end)
        self.generic_visit(node)

    def _check_leaks(self, node: ast.Call, name: str, end: int | None) -> None:
        if name.rsplit(".", 1)[-1] not in RESPONSE_SINKS:
            return
        is_http_exc = name.endswith("HTTPException")
        values = [kw.value for kw in node.keywords if kw.arg in {"detail", "content", "message", "title"}]
        values += list(node.args[1:2]) if is_http_exc else list(node.args[:1])
        for v in values:
            for sub in ast.walk(v):
                leak = False
                if isinstance(sub, ast.Name) and sub.id in self._exc_names:
                    leak = True
                elif isinstance(sub, ast.Call) and dotted(sub.func) in {"str", "repr", "traceback.format_exc"}:
                    leak = True
                elif is_http_exc and isinstance(sub, ast.JoinedStr) and any(
                        isinstance(p, ast.FormattedValue) for p in sub.values):
                    leak = True
                if leak:
                    self._add(node.lineno, "SEC002",
                              "Possible internal error text in a client response. Use a constant message, "
                              "log the exception with a request_id, and map domain exceptions in a global handler.", end)
                    return

    def _check_security_calls(self, node: ast.Call, name: str, attr: str, receiver: str, end: int | None) -> None:
        kws = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        # SEC005 JWT
        if name in {"jwt.decode", "jose.jwt.decode"}:
            problems: list[str] = []
            algs = kws.get("algorithms")
            if algs is None:
                problems.append("no explicit `algorithms=[...]`")
            elif isinstance(algs, ast.Constant) and isinstance(algs.value, str):
                problems.append("`algorithms` must be a 1-element list/tuple, not a bare str")
            elif isinstance(algs, (ast.List, ast.Tuple, ast.Set)):
                if not algs.elts:
                    problems.append("empty `algorithms` sequence")
                if any(isinstance(e, ast.Constant) and str(e.value).lower() == "none" for e in algs.elts):
                    problems.append("algorithm 'none' allowed")
                if len(algs.elts) > 1:
                    problems.append("multiple algorithms accepted (pin exactly one)")
            if "audience" not in kws:
                problems.append("no `audience=`")
            if "issuer" not in kws:
                problems.append("no `issuer=`")
            opts = kws.get("options")
            opts_text = ast.unparse(opts) if opts is not None else ""
            if re.search(r"verify_(signature|exp|aud|iss)['\"]\s*:\s*False", opts_text):
                problems.append("signature/claim verification disabled")
            if "require" not in opts_text:
                problems.append("no `options={'require': [...]}`")
            if isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False:
                problems.append("verify=False")
            if problems:
                self._add(node.lineno, "SEC005", "JWT decode: " + "; ".join(problems) + ".", end)

        # SEC007 SQL building
        first = node.args[0] if node.args else None
        if first is not None and is_dynamic_string(first) and (
                name in {"sqlalchemy.text"} or attr in {"execute", "exec_driver_sql", "executescript", "executemany"}):
            self._add(node.lineno, "SEC007", "SQL built from a dynamic string. Use bound parameters: text('... :id').bindparams(id=value).", end)

        # SEC008 dangerous calls
        danger = {
            "eval": "eval()", "exec": "exec()", "pickle.loads": "pickle deserialization",
            "pickle.load": "pickle deserialization", "marshal.loads": "marshal deserialization",
            "yaml.unsafe_load": "unsafe YAML load", "tempfile.mktemp": "insecure tempfile.mktemp",
            "ssl._create_unverified_context": "TLS verification disabled",
        }
        if name in danger or (isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}):
            label = danger.get(name) or f"{node.func.id}()"  # type: ignore[union-attr]
            self._add(node.lineno, "SEC008", f"Dangerous call: {label}.", end)
        if name == "yaml.load":
            loader = ast.unparse(kws["Loader"]) if "Loader" in kws else ""
            if "Safe" not in loader:
                self._add(node.lineno, "SEC008", "yaml.load without SafeLoader. Use yaml.safe_load.", end)
        if isinstance(kws.get("shell"), ast.Constant) and kws["shell"].value is True:
            self._add(node.lineno, "SEC008", "subprocess with shell=True enables command injection.", end)
        if isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False and name != "jwt.decode":
            self._add(node.lineno, "SEC008", "TLS verification disabled (verify=False).", end)
        if isinstance(kws.get("autoescape"), ast.Constant) and kws["autoescape"].value is False:
            self._add(node.lineno, "SEC008", "Template autoescape disabled (XSS risk).", end)

        # SEC009 unbounded upload read
        if attr == "read" and not node.args and not node.keywords:
            tn = terminal_name(node.func.value).lower() if isinstance(node.func, ast.Attribute) else ""
            if "upload" in tn or tn in {"file", "upload_file"} or tn.endswith("_file"):
                self._add(node.lineno, "SEC009", "Unbounded `.read()` on an upload. Read in chunks and enforce a cumulative byte limit.", end)

        # SEC010 CORS / debug
        if attr == "add_middleware" and node.args and self.resolve(node.args[0]).endswith("CORSMiddleware"):
            origins = kws.get("allow_origins")
            if origins is not None and any(
                    isinstance(e, ast.Constant) and e.value == "*"
                    for e in ast.walk(origins)):
                self._add(node.lineno, "SEC010", "Wildcard CORS origin. List explicit origins (never combine '*' with credentials).", end)
        if name.endswith(("FastAPI", "Starlette")) and isinstance(kws.get("debug"), ast.Constant) \
                and kws["debug"].value is True:
            self._add(node.lineno, "SEC010", "`debug=True` must never ship to production.", end)

        # SEC011 SecretStr("literal")
        if name.endswith("SecretStr") and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str) and len(node.args[0].value) >= 8:
            self._add(node.lineno, "SEC011", "Hard-coded secret passed to SecretStr. Load it from the environment.", end)

    def _check_lifespan(self, node: ast.Call, name: str, end: int | None) -> None:
        if name not in STATEFUL_CLIENTS:
            return
        if not self._fn_stack:
            self._add(node.lineno, "LIFE001", f"'{name}' created at import time. Create it in the `lifespan` context manager and close it on shutdown.", end)
        elif self.layer == "route" and not any(f.name in {"lifespan", "create_app"} for f in self._fn_stack):
            self._add(node.lineno, "LIFE001", f"'{name}' created inside a route function. Share one instance created in `lifespan`.", end)

    # ---- subscript / compare / assign
    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.resolve(node.value) == "os.environ" and self.layer not in {"config", "test"}:
            self._add(node.lineno, "SEC003", "Direct `os.environ[...]` outside the config module.", node.end_lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if self.layer != "test" and all(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            operands = [node.left, *node.comparators]
            if not any(isinstance(o, ast.Constant) for o in operands):
                for o in operands:
                    tn = terminal_name(o)
                    if tn and sensitive_identifier(tn):
                        self._add(node.lineno, "SEC006", f"'{tn}' compared with ==/!=. Use `secrets.compare_digest` (constant time).", node.end_lineno)
                        break
        self.generic_visit(node)

    def _check_secret_literal(self, target: ast.AST, value: ast.AST | None, lineno: int) -> None:
        if self.layer == "test" or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        tn = terminal_name(target)
        v = value.value
        if (tn and SECRET_NAME.search(tn) and len(v) >= 8 and not v.startswith(("/", "http", "$", "<", "{"))
                and not re.fullmatch(r"[A-Z0-9_]+", v) and " " not in v):
            self._add(lineno, "SEC011", f"Hard-coded secret in '{tn}'. Load it from the environment via pydantic-settings (SecretStr).")

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._check_secret_literal(t, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_secret_literal(node.target, node.value, node.lineno)
        self.generic_visit(node)

    # ---- Pydantic classes
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = [self.resolve(b) or dotted(b) for b in node.bases]
        is_model = any(b.endswith("BaseModel") or b in self._local_models for b in bases)
        if is_model and self.layer != "test":
            self._local_models.add(node.name)
            own_ok = self._has_strict_config(node)
            inherits_ok = any(b in self._compliant_models for b in bases)
            unknown_base = any(
                not (b.endswith("BaseModel") or b in self._local_models) for b in bases)
            if own_ok or inherits_ok:
                self._compliant_models.add(node.name)
            is_request = bool(REQUEST_SUFFIX.search(node.name)) and not node.name.endswith("Response")
            if is_request:
                if not (own_ok or inherits_ok) and not unknown_base:
                    self._add(node.lineno, "PYD001",
                              f"Input schema '{node.name}' must set model_config = ConfigDict(extra='forbid', str_strip_whitespace=True).")
                for stmt in node.body:
                    if isinstance(stmt, ast.ClassDef) and stmt.name == "Config":
                        self._add(stmt.lineno, "PYD001", f"'{node.name}' uses Pydantic v1 `class Config`; use `model_config = ConfigDict(...)`.")
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    self._check_field(node, stmt, is_request)
        self.generic_visit(node)

    @staticmethod
    def _has_strict_config(node: ast.ClassDef) -> bool:
        for stmt in node.body:
            value = None
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "model_config" for t in stmt.targets):
                value = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "model_config":
                value = stmt.value
            if value is not None:
                txt = ast.unparse(value)
                if re.search(r"""['"]forbid['"]""", txt) and re.search(r"str_strip_whitespace['\"]?\s*[=:]\s*True", txt):
                    return True
        return False

    def _check_field(self, cls: ast.ClassDef, stmt: ast.AnnAssign, is_request: bool) -> None:
        fname = stmt.target.id  # type: ignore[union-attr]
        ann = ast.unparse(stmt.annotation)
        val = ast.unparse(stmt.value) if stmt.value is not None else ""
        if fname == "model_config" or "ClassVar" in ann:
            return
        if re.search(r"\bfloat\b", ann) and MONEY_NAME.search(fname):
            self._add(stmt.lineno, "PYD004", f"Field '{fname}' looks monetary but is `float`. Use `Decimal` with max_digits/decimal_places.")
        if not is_request:
            return
        if fname.lower() in PAGINATION_NAMES and not UPPER_BOUND.search(ann + " " + val):
            self._add(stmt.lineno, "PYD003", f"Pagination field '{fname}' needs an upper bound (le=100).")
        if "Literal[" in ann or re.search(r"\bmax_length\s*=|\bmax_items\s*=|\bconstr\(|\bconlist\(|StringConstraints", ann + " " + val):
            return
        if re.search(r"\b(list|List|set|Set|frozenset|Sequence|tuple|Tuple|dict|Dict|Mapping)\b", ann):
            self._add(stmt.lineno, "PYD002", f"Collection field '{fname}' in '{cls.name}' needs `max_length`.")
        elif re.search(r"\b(str|bytes)\b", ann):
            self._add(stmt.lineno, "PYD002", f"String field '{fname}' in '{cls.name}' needs `max_length`.")


# --------------------------------------------------------------------------- driver
def audit_source(source: str, path: Path, root: Path | None = None) -> list[Violation]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [Violation(str(path), exc.lineno or 1, "SYNTAX001", f"SyntaxError: {exc.msg}")]
    return FastAPIAuditor(path, source, root).run(tree)


def collect_python_files(targets: list[str], extra_excludes: set[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    excluded = EXCLUDED_DIRS | extra_excludes
    self_dir = Path(__file__).resolve().parent
    for target in targets:
        p = Path(target)
        if p.is_file():
            if p.suffix == ".py":
                files.append(p)
            else:
                errors.append(f"not a Python file: {target}")
        elif p.is_dir():
            for child in p.rglob("*.py"):
                rel_parts = child.relative_to(p).parts
                if any(part in excluded for part in rel_parts[:-1]):
                    continue
                files.append(child)
        else:
            errors.append(f"path does not exist: {target}")
    unique = {f.resolve(): f for f in files if self_dir not in f.resolve().parents}
    return sorted(unique.values()), errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="FastAPI production AST audit")
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--root", type=Path, default=None, help="project root used for layer detection (default: cwd)")
    ap.add_argument("--exclude", nargs="*", default=[], help="extra directory names to skip")
    ap.add_argument("--allow-empty", action="store_true", help="exit 0 when no Python files are found")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.list_rules:
        for rid, desc in RULES.items():
            print(f"{rid:10} {desc}")
        return 0

    files, errors = collect_python_files(args.paths, set(args.exclude))
    if errors:
        for e in errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    if not files:
        print("No Python files found to audit.", file=sys.stderr)
        return 0 if args.allow_empty else 2

    violations: list[Violation] = []
    for f in files:
        try:
            source = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            violations.append(Violation(str(f), 1, "SYNTAX001", f"Cannot read file: {exc}"))
            continue
        violations.extend(audit_source(source, f, args.root))
    violations.sort()

    if args.format == "json":
        print(json.dumps({
            "version": __version__, "files_scanned": len(files), "passed": not violations,
            "counts": dict(Counter(v.rule_id for v in violations)),
            "violations": [asdict(v) for v in violations],
        }, indent=2))
    elif violations:
        print(f"FastAPI Production Audit FAILED: {len(violations)} violation(s) in {len(files)} file(s)\n")
        for v in violations:
            print(v.format())
        print("\nBy rule: " + ", ".join(f"{r}={n}" for r, n in sorted(Counter(v.rule_id for v in violations).items())))
    else:
        print(f"FastAPI Production Audit PASSED ({len(files)} files scanned, 0 violations).")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
