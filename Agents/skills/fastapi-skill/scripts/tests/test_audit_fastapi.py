"""Tests for audit_fastapi.py. Run: pytest .agents/skills/fastapi-skill/scripts/tests -v"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_fastapi as audit  # noqa: E402


def run(source: str, rel: str = "src/open_enterprise_ai/other/mod.py") -> set[str]:
    root = Path("/proj")
    found = audit.audit_source(textwrap.dedent(source), root / rel, root)
    return {v.rule_id for v in found}


def violations(source: str, rel: str = "src/open_enterprise_ai/other/mod.py"):
    root = Path("/proj")
    return audit.audit_source(textwrap.dedent(source), root / rel, root)


# ------------------------------------------------------------------ layers
def test_layer_detection_deepest_wins_and_stem():
    root = Path("/proj")
    d = audit.detect_layer
    assert d(root / "src/open_enterprise_ai/domains/orders/api/routes.py", root, []) == "route"
    assert d(root / "src/open_enterprise_ai/domains/orders/services/order_service.py", root, []) == "service"
    assert d(root / "src/open_enterprise_ai/infrastructure/repositories/postgres_order_repository.py", root, []) == "repository"
    assert d(root / "tests/unit/domains/orders/test_order_service.py", root, []) == "test"
    assert d(root / "src/open_enterprise_ai/core/config.py", root, []) == "config"
    assert d(root / "src/open_enterprise_ai/domains/orders/models/order.py", root, []) == "other"


def test_project_located_under_api_dir_is_not_misclassified():
    # absolute parent named "api" must not turn every file into a route
    assert audit.detect_layer(Path("/home/api/proj/src/open_enterprise_ai/util.py"), Path("/home/api/proj"), []) == "other"


def test_layer_pragma_overrides():
    assert audit.detect_layer(Path("/p/x.py"), Path("/p"), ["# audit: layer=service"]) == "service"


# ------------------------------------------------------------------ ASYNC
def test_blocking_calls_in_async_flagged():
    src = """
    import time, requests
    async def f():
        time.sleep(1)
        requests.get("http://x")
        open("a")
    """
    assert "ASYNC001" in run(src)
    assert len([v for v in violations(src) if v.rule_id == "ASYNC001"]) == 3


def test_alias_and_from_import_resolved():
    src = """
    import requests as r
    from time import sleep
    async def f():
        r.get("x")
        sleep(1)
    """
    assert len([v for v in violations(src) if v.rule_id == "ASYNC001"]) == 2


def test_sync_function_and_nested_sync_def_not_flagged():
    src = """
    import time
    def f():
        time.sleep(1)
    async def g():
        def inner():
            time.sleep(1)
        return inner
    """
    assert "ASYNC001" not in run(src)


def test_awaited_path_methods_allowed_but_sync_flagged():
    ok = "async def f(p):\n    return await p.read_text()\n"
    bad = "async def f(p):\n    return p.read_text()\n"
    assert "ASYNC001" not in run(ok)
    assert "ASYNC001" in run(bad)


def test_cpu_bound_hashing_flagged():
    assert "ASYNC002" in run("import bcrypt\nasync def f(p, h):\n    return bcrypt.checkpw(p, h)\n")


# ------------------------------------------------------------------ ARCH
def test_service_importing_fastapi_flagged():
    assert "ARCH001" in run("from fastapi import HTTPException\n", "src/open_enterprise_ai/services/x.py")
    assert "ARCH001" in run("import starlette.status\n", "src/open_enterprise_ai/domain/x.py")
    assert "ARCH001" not in run("from fastapi import HTTPException\n", "src/open_enterprise_ai/api/x.py")


def test_route_layer_db_access_flagged():
    src = """
    from sqlalchemy import select
    async def f(session):
        await session.execute(select(1))
        await session.commit()
    """
    ids = [v.rule_id for v in violations(src, "src/open_enterprise_ai/api/orders.py")]
    assert ids.count("ARCH002") == 3  # select, execute, commit


def test_route_calling_service_is_clean_of_arch002():
    src = "async def f(service):\n    return await service.get()\n"
    assert "ARCH002" not in run(src, "src/open_enterprise_ai/api/orders.py")


def test_repository_commit_flagged_flush_ok():
    assert "ARCH003" in run("async def f(self):\n    await self._session.commit()\n", "src/open_enterprise_ai/repositories/o.py")
    assert "ARCH003" not in run("async def f(self):\n    await self._session.flush()\n", "src/open_enterprise_ai/repositories/o.py")


# ------------------------------------------------------------------ SEC001 / SEC004 / AUTH001
ROUTE_OK = """
from fastapi import APIRouter
router = APIRouter()
@router.get("/x", response_model=Out)
async def f(principal: CurrentPrincipal) -> Out:
    ...
"""


def test_compliant_route_has_no_violations():
    assert run(ROUTE_OK, "src/open_enterprise_ai/api/x.py") == set()


def test_missing_response_model_flagged():
    src = "@router.get('/x')\nasync def f(principal: CurrentPrincipal):\n    ...\n"
    assert "SEC001" in run(src, "src/open_enterprise_ai/api/x.py")


def test_204_and_response_class_exempt():
    a = "@router.delete('/x', status_code=204)\nasync def f(principal: CurrentPrincipal):\n    ...\n"
    b = "@router.get('/x', response_class=FileResponse)\nasync def f(principal: CurrentPrincipal):\n    ...\n"
    assert "SEC001" not in run(a, "src/open_enterprise_ai/api/x.py")
    assert "SEC001" not in run(b, "src/open_enterprise_ai/api/x.py")


def test_untyped_dict_return_flagged():
    src = "@router.get('/x')\nasync def f(principal: CurrentPrincipal) -> dict:\n    ...\n"
    assert "SEC004" in run(src, "src/open_enterprise_ai/api/x.py")
    src2 = "@router.get('/x', response_model=dict)\nasync def f(principal: CurrentPrincipal):\n    ...\n"
    assert "SEC004" in run(src2, "src/open_enterprise_ai/api/x.py")


def test_auth_missing_flagged_health_and_suppressed_allowed():
    src = "@router.get('/orders', response_model=Out)\nasync def f() -> Out:\n    ...\n"
    assert "AUTH001" in run(src, "src/open_enterprise_ai/api/x.py")
    health = "@router.get('/health', response_model=Out)\nasync def f() -> Out:\n    ...\n"
    assert "AUTH001" not in run(health, "src/open_enterprise_ai/api/x.py")
    sup = ("@router.get('/pub', response_model=Out)  # audit: ignore[AUTH001] -- public marketing catalogue\n"
           "async def f() -> Out:\n    ...\n")
    assert "AUTH001" not in run(sup, "src/open_enterprise_ai/api/x.py")


def test_router_level_dependencies_cover_routes():
    src = ("router = APIRouter(dependencies=[Depends(require_user)])\n"
           "@router.get('/orders', response_model=Out)\nasync def f() -> Out:\n    ...\n")
    assert "AUTH001" not in run(src, "src/open_enterprise_ai/api/x.py")


def test_non_route_get_decorator_ignored():
    src = "@cache.get\ndef f():\n    ...\n"
    assert run(src) == set()


# ------------------------------------------------------------------ SEC002
def test_exception_text_leak_flagged():
    src = """
    from fastapi import HTTPException
    def f():
        try:
            g()
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    """
    assert "SEC002" in run(src, "src/open_enterprise_ai/api/x.py")


def test_fstring_detail_and_json_response_leak_flagged():
    a = "def f(x):\n    raise HTTPException(400, detail=f'bad {x}')\n"
    b = ("def f():\n    try:\n        g()\n    except Exception as exc:\n"
         "        return JSONResponse({'error': exc.args}, 500)\n")
    assert "SEC002" in run(a, "src/open_enterprise_ai/api/x.py")
    assert "SEC002" in run(b, "src/open_enterprise_ai/api/x.py")


def test_global_exception_handler_leak_flagged():
    src = """
    @app.exception_handler(Exception)
    async def h(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=500)
    """
    assert "SEC002" in run(src)


def test_constant_detail_ok():
    assert "SEC002" not in run("def f():\n    raise HTTPException(404, detail='Order not found')\n", "src/open_enterprise_ai/api/x.py")


# ------------------------------------------------------------------ SEC003 / SEC011
def test_getenv_outside_config_flagged_inside_config_ok():
    src = "import os\nX = os.getenv('A')\nY = os.environ['B']\n"
    assert len([v for v in violations(src) if v.rule_id == "SEC003"]) == 2
    assert "SEC003" not in run(src, "src/open_enterprise_ai/core/config.py")


def test_from_os_import_environ_resolved():
    assert "SEC003" in run("from os import environ\nx = environ['A']\n")


def test_hardcoded_secret_flagged_and_safe_cases():
    assert "SEC011" in run("API_KEY = 'sk-live-123456789'\n")
    assert "SEC011" in run("from pydantic import SecretStr\nx = SecretStr('hunter2hunter2')\n")
    assert "SEC011" not in run("TOKEN_URL = '/auth/token'\n")
    assert "SEC011" not in run("secret_key = os.environ_name\n")
    assert "SEC011" not in run("API_KEY = 'sk-live-123456789'\n", "tests/test_x.py")


# ------------------------------------------------------------------ SEC005
def test_jwt_rules():
    bad = "import jwt\njwt.decode(t, k)\n"
    assert "SEC005" in run(bad)
    none = "import jwt\njwt.decode(t, k, algorithms=['none'], audience='a', issuer='i', options={'require': ['exp']})\n"
    assert "SEC005" in run(none)
    off = ("import jwt\njwt.decode(t, k, algorithms=['RS256'], audience='a', issuer='i',"
           " options={'verify_signature': False, 'require': ['exp']})\n")
    assert "SEC005" in run(off)
    good = ("import jwt\njwt.decode(t, k, algorithms=['RS256'], audience='a', issuer='i',"
            " options={'require': ['exp', 'iat', 'sub', 'iss', 'aud']})\n")
    assert "SEC005" not in run(good)


# ------------------------------------------------------------------ SEC006
def test_secret_comparison():
    assert "SEC006" in run("def f(sig, expected_signature):\n    return sig == expected_signature\n")
    assert "SEC006" in run("def f(request_token, stored_token):\n    return request_token != stored_token\n")
    assert "SEC006" not in run("def f(token_type):\n    return token_type == 'bearer'\n")
    assert "SEC006" not in run("def f(a, b):\n    return a == b\n")


# ------------------------------------------------------------------ SEC007
def test_sql_building():
    assert "SEC007" in run("from sqlalchemy import text\nq = text(f'select * from t where id={x}')\n")
    assert "SEC007" in run("async def f(s, x):\n    await s.execute('select ' + x)\n")
    assert "SEC007" in run("from sqlalchemy import text\nq = text('select {}'.format(x))\n")
    assert "SEC007" not in run("from sqlalchemy import text\nq = text('select * from t where id=:id').bindparams(id=1)\n")


# ------------------------------------------------------------------ SEC008..SEC010
@pytest.mark.parametrize("src", [
    "eval('1')",
    "import pickle\npickle.loads(b)",
    "import yaml\nyaml.load(s)",
    "import subprocess\nsubprocess.run(c, shell=True)",
    "import httpx\nhttpx.get(u, verify=False)",
    "import tempfile\ntempfile.mktemp()",
])
def test_dangerous_calls(src):
    assert "SEC008" in run(src + "\n")


def test_safe_yaml_ok():
    assert "SEC008" not in run("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\nyaml.safe_load(s)\n")


def test_upload_read():
    assert "SEC009" in run("async def f(file):\n    return await file.read()\n")
    assert "SEC009" not in run("async def f(file):\n    return await file.read(65536)\n")


def test_cors_and_debug():
    assert "SEC010" in run("app.add_middleware(CORSMiddleware, allow_origins=['*'])\n")
    assert "SEC010" not in run("app.add_middleware(CORSMiddleware, allow_origins=['https://a.com'])\n")
    assert "SEC010" in run("from fastapi import FastAPI\napp = FastAPI(debug=True)\n")


# ------------------------------------------------------------------ LIFE001
def test_lifespan_rules():
    mod = "import httpx\nclient = httpx.AsyncClient()\n"
    assert "LIFE001" in run(mod)
    inside_lifespan = "import httpx\nasync def lifespan(app):\n    app.state.c = httpx.AsyncClient()\n    yield\n"
    assert "LIFE001" not in run(inside_lifespan, "src/open_enterprise_ai/main.py")
    in_route = "import httpx\nasync def f():\n    c = httpx.AsyncClient()\n"
    assert "LIFE001" in run(in_route, "src/open_enterprise_ai/api/x.py")
    assert "LIFE001" not in run(mod, "tests/test_x.py")


# ------------------------------------------------------------------ PYD
def test_pydantic_strictness():
    bad = """
    from pydantic import BaseModel
    class OrderCreate(BaseModel):
        name: str
        tags: list[str]
    """
    ids = [v.rule_id for v in violations(bad, "src/open_enterprise_ai/schemas/o.py")]
    assert ids.count("PYD001") == 1 and ids.count("PYD002") == 2

    good = """
    from pydantic import BaseModel, ConfigDict, Field
    class OrderCreate(BaseModel):
        model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
        name: str = Field(min_length=1, max_length=50)
        tags: list[str] = Field(max_length=10)
    """
    assert run(good, "src/open_enterprise_ai/schemas/o.py") == set()


def test_inherited_strict_config_and_response_models_exempt():
    src = """
    from pydantic import BaseModel, ConfigDict
    class StrictModel(BaseModel):
        model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    class ThingCreate(StrictModel):
        n: int
    class ThingResponse(BaseModel):
        name: str
    """
    assert run(src, "src/open_enterprise_ai/schemas/o.py") == set()


def test_missing_strip_whitespace_flagged_and_v1_config_flagged():
    a = ("from pydantic import BaseModel, ConfigDict\nclass AUpdate(BaseModel):\n"
         "    model_config = ConfigDict(extra='forbid')\n")
    assert "PYD001" in run(a, "src/open_enterprise_ai/schemas/o.py")
    b = "from pydantic import BaseModel\nclass AUpdate(BaseModel):\n    class Config:\n        extra = 'forbid'\n"
    assert "PYD001" in run(b, "src/open_enterprise_ai/schemas/o.py")


def test_pagination_bounds():
    bad = "@router.get('/x', response_model=Out)\nasync def f(p: CurrentPrincipal, limit: int = 50) -> Out:\n    ...\n"
    good = ("@router.get('/x', response_model=Out)\n"
            "async def f(p: CurrentPrincipal, limit: Annotated[int, Query(ge=1, le=100)] = 50) -> Out:\n    ...\n")
    assert "PYD003" in run(bad, "src/open_enterprise_ai/api/x.py")
    assert "PYD003" not in run(good, "src/open_enterprise_ai/api/x.py")


def test_float_money_flagged():
    src = "from pydantic import BaseModel\nclass OrderResponse(BaseModel):\n    total_price: float\n    ratio: float\n"
    ids = [v for v in violations(src, "src/open_enterprise_ai/schemas/o.py") if v.rule_id == "PYD004"]
    assert len(ids) == 1


# ------------------------------------------------------------------ ERR001
def test_swallowed_exceptions():
    assert "ERR001" in run("try:\n    f()\nexcept:\n    raise\n")
    assert "ERR001" in run("try:\n    f()\nexcept Exception:\n    pass\n")
    assert "ERR001" not in run("try:\n    f()\nexcept ValueError:\n    log()\n    raise\n")


# ------------------------------------------------------------------ suppressions
def test_suppression_requires_rule_and_reason():
    ok = "import os\nx = os.getenv('A')  # audit: ignore[SEC003] -- bootstrap before settings load\n"
    assert run(ok) == set()
    blanket = "import os\nx = os.getenv('A')  # audit: ignore\n"
    assert {"SUP001", "SEC003"} <= run(blanket)
    no_reason = "import os\nx = os.getenv('A')  # audit: ignore[SEC003]\n"
    assert {"SUP001", "SEC003"} <= run(no_reason)
    wrong_rule = "import os\nx = os.getenv('A')  # audit: ignore[ASYNC001] -- unrelated rule given\n"
    assert "SEC003" in run(wrong_rule)


def test_multiline_call_suppression_on_any_line():
    src = ("import subprocess\nasync def f():\n    subprocess.run(\n        ['a'],  "
           "# audit: ignore[ASYNC001] -- bounded 10ms local call\n    )\n")
    assert "ASYNC001" not in run(src)


# ------------------------------------------------------------------ CLI
def test_cli_exit_codes(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert audit.main([str(tmp_path)]) == 0
    (tmp_path / "bad.py").write_text("import os\nx = os.getenv('A')\n")
    assert audit.main([str(tmp_path), "--root", str(tmp_path)]) == 1
    assert audit.main([str(tmp_path / "nope")]) == 2  # typo must never pass
    empty = tmp_path / "empty"
    empty.mkdir()
    assert audit.main([str(empty)]) == 2
    assert audit.main([str(empty), "--allow-empty"]) == 0


def test_cli_json_and_syntax_error(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("def (:\n")
    assert audit.main([str(tmp_path), "--format", "json"]) == 1
    out = capsys.readouterr().out
    assert '"SYNTAX001"' in out and '"passed": false' in out


def test_project_in_build_named_parent_is_still_scanned(tmp_path):
    proj = tmp_path / "build" / "svc"
    proj.mkdir(parents=True)
    (proj / "m.py").write_text("import os\nx = os.getenv('A')\n")
    assert audit.main([str(proj), "--root", str(proj)]) == 1


def test_excluded_dirs_skipped_but_explicit_file_scanned(tmp_path):
    mig = tmp_path / "alembic"
    mig.mkdir()
    (mig / "v1.py").write_text("import os\nx = os.getenv('A')\n")
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert audit.main([str(tmp_path), "--root", str(tmp_path)]) == 0
    assert audit.main([str(mig / "v1.py"), "--root", str(tmp_path)]) == 1


def test_any_file_named_like_the_script_is_not_skipped(tmp_path):
    (tmp_path / "audit_fastapi.py").write_text("import os\nx = os.getenv('A')\n")
    assert audit.main([str(tmp_path), "--root", str(tmp_path)]) == 1
