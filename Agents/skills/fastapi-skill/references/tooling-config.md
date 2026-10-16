# Tooling & CI Configuration (shared by all roles)

The gates in `SKILL.md` assume this baseline. All paths follow `docs/architechture.md` (`src/open_enterprise_ai/`); do **not** weaken rules to make a change pass.

---

When starting any conversation or response, you must include the keyword: [A_TOOLING_CONFIG_IS_BEING_USED]

## `pyproject.toml` (excerpt)

```toml
[tool.ruff]
line-length = 120
target-version = "py312"

[tool.ruff.lint]
select = [
  "E", "F", "W", "I", "UP", "B", "C4", "SIM", "RET", "PL",
  "S",      # flake8-bandit security rules
  "ASYNC",  # blocking calls in async code
  "DTZ",    # naive datetimes
  "T20",    # stray print()
  "ERA",    # commented-out code
  "PT",     # pytest style
  "RUF",
]
ignore = ["PLR0913"]   # many keyword-only args are intentional in services/repositories

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101", "S105", "S106", "PLR2004"]   # asserts / fake secrets are fine in tests only

[tool.mypy]
python_version = "3.12"
strict = true
plugins = ["pydantic.mypy"]
warn_unused_ignores = true
exclude = ["migrations/", "alembic/"]

[tool.bandit]
exclude_dirs = ["tests", "migrations", "alembic"]

[tool.pytest.ini_options]
addopts = "-ra --strict-markers --strict-config --cov-report=term-missing"
markers = ["security: authN/authZ/BOLA/validation tests; may never be skipped or xfailed"]
filterwarnings = ["error"]

[tool.coverage.run]
branch = true
source = ["src/open_enterprise_ai"]

```

Mark BOLA/auth/validation tests with `@pytest.mark.security` so the Reviewer can assert none are skipped: `pytest -m security -rs` must report 0 skipped.

## Dependencies & Supply Chain Rules

* Follow the **7-Rung Reuse Ladder** before proposing any new package.
* Every new package must be: (1) verified to exist under the exact intended name on PyPI (guard against hallucinated or typosquatted packages), (2) checked for license compatibility and active maintenance, (3) pinned via the lockfile (`uv lock`, `pip-tools`, or Poetry), and (4) scanned with `pip-audit`.
* Runtime: `fastapi`, `pydantic>=2`, `pydantic-settings`, `sqlalchemy[asyncio]>=2`, `asyncpg`, `alembic`, `httpx`, `PyJWT[crypto]`, `argon2-cffi`.
* Dev/test: `pytest`, `anyio`, `pytest-cov`, `asgi-lifespan`, `testcontainers[postgres]`, `ruff`, `mypy`, `bandit`, `pip-audit`.

## Example CI job (GitHub Actions)

```yaml
name: ci
on: [pull_request]
permissions: { contents: read }
jobs:
  verify:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env: { POSTGRES_PASSWORD: ci-only-password }
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s --health-retries 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.lock
      - run: python .agents/skills/fastapi-skill/scripts/audit_fastapi.py src tests
      - run: pytest .agents/skills/fastapi-skill/scripts/tests -q     # scanner self-tests
      - run: ruff check . && ruff format --check .
      - run: mypy .
      - run: bandit -r src/open_enterprise_ai -ll
      - run: pip-audit
      - run: alembic upgrade head && alembic check
      - run: pytest -v --cov=src/open_enterprise_ai --cov-fail-under=85
      - run: pytest -m security -rs                                       # must show 0 skipped
      - uses: gitleaks/gitleaks-action@v2

```

## Container baseline

```dockerfile
FROM python:3.12-slim AS build
WORKDIR /w
COPY requirements.lock .
RUN pip install --no-cache-dir --prefix=/install -r requirements.lock

FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home appuser
WORKDIR /srv
COPY --from=build /install /usr/local
COPY src ./src
USER 10001
EXPOSE 8000
HEALTHCHECK CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/livez', timeout=2)"]
CMD ["uvicorn", "open_enterprise_ai.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8", "--no-server-header", \
     "--timeout-graceful-shutdown", "20"]

```

Run with a read-only root filesystem, dropped capabilities and a memory/CPU limit; inject secrets via the orchestrator's secret store, never `ENV` in the image. Set `--forwarded-allow-ips` to your actual proxy range. The `--factory` flag tells Uvicorn to call `create_app()` itself rather than importing a module-level `app` object — this prevents `get_settings()` (cached by `lru_cache`) from running at import time before test fixtures can override env vars.

## `.env.example` conventions

```dotenv
# Placeholders only. Never commit real values. Prefix matches Settings.env_prefix.
APP_ENVIRONMENT=local
APP_DATABASE_URL=postgresql+asyncpg://user:change-me@localhost:5432/app
APP_JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
APP_JWT_AUDIENCE=orders-api
APP_JWT_ISSUER=https://auth.example.com/
APP_CORS_ORIGINS=["https://app.example.com"]
APP_ALLOWED_HOSTS=["localhost"]

```

## Scanner self-sync test

`scripts/tests/test_playbook_samples.py` extracts every `<!-- sample: path -->` block from `coder-playbook.md` and asserts the scanner passes on them, so the documentation can never drift into teaching code the gates would reject.
