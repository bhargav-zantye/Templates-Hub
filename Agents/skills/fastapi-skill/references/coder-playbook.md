# Coder Playbook — Production FastAPI Implementation & Security Standards

You are the **Coder (Maker)** (`.agents/coder.md`). You turn the Orchestrator's approved Task Specification into production-hardened code, tests, and documentation. You do not invent unrequested features, widen scope, or bypass layers for convenience. You never approve your own work.


When starting any conversation or response, you must include the keyword: [A_CODER_PLAYBOOK_IS_BEING_USED]

## 0. Before You Code
1. **Read `docs/architechture.md` in full** before creating, moving, or renaming any file or folder. Source code strictly lives under `src/open_enterprise_ai/` following a domain-oriented, hexagonal structure (`src/open_enterprise_ai/domains/<domain>/{api,services,ports,models}`, `src/open_enterprise_ai/infrastructure/`, `src/open_enterprise_ai/core/`, `src/open_enterprise_ai/shared/`, and `src/open_enterprise_ai/api/`). If it conflicts with your task, stop and ask the Orchestrator.
2. **Apply the 7-Rung Reuse Ladder** and stop at the first rung that holds: (1) YAGNI; (2) existing codebase helper; (3) standard library; (4) native platform/DB feature; (5) installed dependency; (6) popular, maintained premade library; (7) minimum custom code.
3. **Vet any new dependency:** justify why Rungs 1–5 do not suffice, verify the exact package name exists on PyPI (guard against hallucinated or typosquatted packages), check its license and maintenance, pin it in the lockfile, and flag it to the Orchestrator.

> Code blocks marked `<!-- sample: path -->` form one coherent reference slice (`orders`) illustrating the layer boundaries under `src/open_enterprise_ai/`. They are audited by `audit_fastapi.py` as part of this skill's own test run, so they are guaranteed to pass the scanner. Adapt directory paths to `docs/architechture.md`.

---

## 1. Layer Architecture

### A. Schemas (`src/open_enterprise_ai/domains/<domain>/api/schemas.py`) — separate Create / Update / Response

<!-- sample: src/open_enterprise_ai/domains/orders/api/schemas.py -->
```python
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictInput(BaseModel):
    """Base for every request body: reject unknown fields, trim strings."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OrderItemInput(StrictInput):
    sku: str = Field(min_length=3, max_length=64, pattern=r"^[A-Z0-9\-]+$")
    quantity: int = Field(ge=1, le=1000)
    unit_price: Decimal = Field(gt=Decimal("0.00"), le=Decimal("1000000.00"), max_digits=10, decimal_places=2)


class OrderCreate(StrictInput):
    idempotency_key: str = Field(min_length=16, max_length=64)
    notes: str | None = Field(default=None, max_length=500)
    items: list[OrderItemInput] = Field(min_length=1, max_length=100)


class OrderItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    sku: str
    quantity: int
    unit_price: Decimal


class OrderResponse(BaseModel):
    """Explicit allow-list of fields. tenant_id, created_by, idempotency_key stay internal."""

    model_config = ConfigDict(from_attributes=True)
    id: UUID
    status: str
    notes: str | None
    items: list[OrderItemResponse]
    created_at: datetime


class OrderPage(BaseModel):
    items: list[OrderResponse]
    limit: int
    offset: int

```

<!-- sample: src/open_enterprise_ai/api/schemas.py -->
```python
from typing import Any

from pydantic import BaseModel


class ProblemDetail(BaseModel):
    """RFC 7807 payload. Constant, client-safe text only."""

    type: str
    title: str
    status: int
    request_id: str | None = None
    errors: list[dict[str, Any]] | None = None

```

### B. Domain exceptions (`src/open_enterprise_ai/domains/<domain>/exceptions.py` or `src/open_enterprise_ai/core/exceptions.py`) — HTTP-agnostic

<!-- sample: src/open_enterprise_ai/domains/orders/exceptions.py -->
```python
class DomainError(Exception):
    """Each subclass carries a CONSTANT public code/title. Never put user data or driver text in them."""

    status_code: int = 400
    code: str = "domain_error"
    title: str = "Request could not be processed"


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"
    title = "Resource not found"


class ConflictError(DomainError):
    status_code = 409
    code = "conflict"
    title = "Resource conflict"


class ForbiddenError(DomainError):
    status_code = 403
    code = "forbidden"
    title = "Forbidden"


class OrderNotFoundError(NotFoundError):
    code = "order_not_found"
    title = "Order not found"


class OrderConflictError(ConflictError):
    code = "order_conflict"
    title = "An order with this idempotency key already exists"

```

### C. Repository (`src/open_enterprise_ai/infrastructure/repositories/`) — queries + tenant isolation, `flush()` only

Repositories take the tenant/owner scope as a **required keyword argument** so a forgotten filter is a `TypeError`, not a breach.

<!-- sample: src/open_enterprise_ai/infrastructure/repositories/postgres_order_repository.py -->
```python
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from open_enterprise_ai.domains.orders.models.order import OrderItemModel, OrderModel
from open_enterprise_ai.domains.orders.api.schemas import OrderCreate


class OrderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, *, tenant_id: UUID, order_id: UUID) -> OrderModel | None:
        stmt = select(OrderModel).where(
            OrderModel.id == order_id,
            OrderModel.tenant_id == tenant_id,  # mandatory BOLA guard
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_page(self, *, tenant_id: UUID, limit: int, offset: int) -> list[OrderModel]:
        stmt = (
            select(OrderModel)
            .where(OrderModel.tenant_id == tenant_id)  # list endpoints are scoped too
            .order_by(OrderModel.created_at.desc(), OrderModel.id)
            .limit(limit)
            .offset(offset)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def create(self, *, tenant_id: UUID, actor_id: UUID, data: OrderCreate) -> OrderModel:
        order = OrderModel(
            tenant_id=tenant_id,  # from the principal, NEVER from the request body
            created_by=actor_id,
            idempotency_key=data.idempotency_key,
            notes=data.notes,
            items=[OrderItemModel(**item.model_dump()) for item in data.items],
        )
        self._session.add(order)
        await self._session.flush()  # surfaces constraint violations; the service owns commit
        return order

```

Model essentials (idempotency is enforced by the **database**, not by a check-then-insert race):

```python
class OrderModel(Base):
    __tablename__ = "orders"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_orders_tenant_idem"),
        Index("ix_orders_tenant_created", "tenant_id", "created_at"),
    )

```

### D. Service (`src/open_enterprise_ai/domains/<domain>/services/`) — rules + transaction ownership, zero HTTP

<!-- sample: src/open_enterprise_ai/domains/orders/services/order_service.py -->
```python
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from open_enterprise_ai.domains.orders.exceptions import OrderConflictError, OrderNotFoundError
from open_enterprise_ai.domains.orders.models.order import OrderModel
from open_enterprise_ai.infrastructure.repositories.postgres_order_repository import OrderRepository
from open_enterprise_ai.domains.orders.api.schemas import OrderCreate


class OrderService:
    def __init__(self, session: AsyncSession, repo: OrderRepository) -> None:
        self._session = session
        self._repo = repo

    async def create_order(self, *, tenant_id: UUID, actor_id: UUID, data: OrderCreate) -> OrderModel:
        try:
            order = await self._repo.create(tenant_id=tenant_id, actor_id=actor_id, data=data)
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            if "uq_orders_tenant_idem" not in str(exc.orig):  # internal use only; never sent to clients
                raise
            raise OrderConflictError() from exc
        return order  # sessionmaker uses expire_on_commit=False, so attributes stay loaded

    async def get_order(self, *, tenant_id: UUID, order_id: UUID) -> OrderModel:
        order = await self._repo.get_by_id(tenant_id=tenant_id, order_id=order_id)
        if order is None:  # same answer for "missing" and "someone else's": no existence oracle
            raise OrderNotFoundError()
        return order

    async def list_orders(self, *, tenant_id: UUID, limit: int, offset: int) -> list[OrderModel]:
        return await self._repo.list_page(tenant_id=tenant_id, limit=limit, offset=offset)

```

### E. Dependencies & auth (`src/open_enterprise_ai/api/dependencies.py`)

<!-- sample: src/open_enterprise_ai/api/dependencies.py -->
```python
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import IntEnum
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from open_enterprise_ai.domains.orders.exceptions import ForbiddenError
from open_enterprise_ai.infrastructure.repositories.postgres_order_repository import OrderRepository
from open_enterprise_ai.domains.orders.services.order_service import OrderService

logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)


class Role(IntEnum):
    VIEWER = 1
    EDITOR = 2
    ADMIN = 3


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    role: Role


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",  # constant text
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if creds is None:
        raise _unauthorized()
    settings = request.app.state.settings
    try:
        claims = jwt.decode(
            creds.credentials,
            settings.jwt_public_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],  # pin exactly one asymmetric algorithm
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            leeway=10,
        )
        return Principal(
            user_id=UUID(claims["sub"]),
            tenant_id=UUID(claims["tid"]),
            role=Role[claims["role"].upper()],
        )
    except (jwt.PyJWTError, KeyError, ValueError):
        logger.info("auth_rejected", extra={"request_id": getattr(request.state, "request_id", None)})
        raise _unauthorized() from None


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_role(minimum: Role):
    """Authorization (not just authentication). Usage: Depends(require_role(Role.EDITOR))."""

    async def checker(principal: CurrentPrincipal) -> Principal:
        if principal.role < minimum:
            raise ForbiddenError()
        return principal

    return checker


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def get_order_service(session: SessionDep) -> OrderService:
    return OrderService(session, OrderRepository(session))


OrderServiceDep = Annotated[OrderService, Depends(get_order_service)]

```

### F. Routes (`src/open_enterprise_ai/domains/<domain>/api/routes.py`) — thin HTTP translators

<!-- sample: src/open_enterprise_ai/domains/orders/api/routes.py -->
```python
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from open_enterprise_ai.api.dependencies import OrderServiceDep, Principal, Role, require_role
from open_enterprise_ai.api.schemas import ProblemDetail
from open_enterprise_ai.domains.orders.api.schemas import OrderCreate, OrderPage, OrderResponse

router = APIRouter(prefix="/api/v1/orders", tags=["orders"])

EditorPrincipal = Annotated[Principal, Depends(require_role(Role.EDITOR))]
ViewerPrincipal = Annotated[Principal, Depends(require_role(Role.VIEWER))]


@router.post(
    "",
    response_model=OrderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a tenant-scoped order",
    description="Idempotent per (tenant, idempotency_key). Repeating a key returns 409.",
    responses={
        401: {"model": ProblemDetail},
        403: {"model": ProblemDetail},
        409: {"model": ProblemDetail},
        422: {"model": ProblemDetail},
    },
)
async def create_order(payload: OrderCreate, principal: EditorPrincipal, service: OrderServiceDep) -> OrderResponse:
    order = await service.create_order(tenant_id=principal.tenant_id, actor_id=principal.user_id, data=payload)
    return OrderResponse.model_validate(order)


@router.get(
    "/{order_id}",
    response_model=OrderResponse,
    summary="Get one order",
    responses={401: {"model": ProblemDetail}, 404: {"model": ProblemDetail}},
)
async def get_order(order_id: UUID, principal: ViewerPrincipal, service: OrderServiceDep) -> OrderResponse:
    order = await service.get_order(tenant_id=principal.tenant_id, order_id=order_id)
    return OrderResponse.model_validate(order)


@router.get(
    "",
    response_model=OrderPage,
    summary="List orders for the caller's tenant",
    responses={401: {"model": ProblemDetail}},
)
async def list_orders(
    principal: ViewerPrincipal,
    service: OrderServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> OrderPage:
    rows = await service.list_orders(tenant_id=principal.tenant_id, limit=limit, offset=offset)
    return OrderPage(items=[OrderResponse.model_validate(r) for r in rows], limit=limit, offset=offset)

```

Rules for routes: no query construction, no `session` calls, no `try/except` that builds responses (global handlers do that), `tenant_id`/`user_id` **only** from the `Principal`, never from the body, path or query. Intentionally public routes (health, login, webhooks with their own signature auth) need `# audit: ignore[AUTH001] -- <reason>` and Orchestrator approval.

---

## 2. Application Bootstrap (`src/open_enterprise_ai/core/config.py`, `src/open_enterprise_ai/main.py`, `src/open_enterprise_ai/api/errors.py`)

### Settings — the only place that reads the environment

<!-- sample: src/open_enterprise_ai/core/config.py -->
```python
from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # extra="ignore": a shared .env/CI environment legitimately holds unrelated variables
    model_config = SettingsConfigDict(env_file=".env", env_prefix="APP_", extra="ignore")

    environment: Literal["local", "test", "staging", "production"] = "local"
    database_url: SecretStr
    jwt_public_key: SecretStr
    jwt_algorithm: Literal["RS256", "ES256"] = "RS256"
    jwt_audience: str
    jwt_issuer: str
    cors_origins: list[AnyHttpUrl] = []
    allowed_hosts: list[str] = ["localhost"]
    max_body_bytes: int = 1_048_576

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.environment == "production":
            if "*" in self.allowed_hosts:
                raise ValueError("wildcard allowed_hosts is forbidden in production")
            if not self.cors_origins:
                raise ValueError("explicit cors_origins required in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # fails fast at startup if anything required is missing

```

Every new setting gets a placeholder in `.env.example` (never a real value) and a note in the README.

### Global error mapping — one place, constant messages

<!-- sample: src/open_enterprise_ai/api/errors.py -->
```python
import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from open_enterprise_ai.domains.orders.exceptions import DomainError
from open_enterprise_ai.api.schemas import ProblemDetail

logger = logging.getLogger(__name__)


def _problem(
    request: Request,
    status_code: int,
    code: str,
    title: str,
    errors: list[dict] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ProblemDetail(
        type=f"urn:problem:{code}",
        title=title,
        status=status_code,
        request_id=getattr(request.state, "request_id", None),
        errors=errors,
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json", exclude_none=True),
        media_type="application/problem+json",
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        status_code, code, title = exc.status_code, exc.code, exc.title  # class constants only
        return _problem(request, status_code, code, title)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        status_code = exc.status_code
        headers = dict(exc.headers or {})
        return _problem(request, status_code, f"http_{status_code}", HTTPStatus(status_code).phrase, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # loc + type only: never echo `input`/`ctx`, they can contain the secret the client just sent
        errors = [{"loc": [str(p) for p in e["loc"]], "type": e["type"]} for e in exc.errors()]
        return _problem(request, 422, "validation_error", "Request validation failed", errors=errors)

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error", extra={"request_id": getattr(request.state, "request_id", None)})
        return _problem(request, 500, "internal_error", "Internal server error")

```

### Application factory, lifespan, edge hardening

<!-- sample: src/open_enterprise_ai/main.py -->
```python
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from open_enterprise_ai.domains.orders.api import routes as orders
from open_enterprise_ai.api.errors import register_exception_handlers
from open_enterprise_ai.core.config import get_settings
from open_enterprise_ai.api.middleware import BodySizeLimitMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    engine = create_async_engine(
        settings.database_url.get_secret_value(),
        pool_size=10, max_overflow=5, pool_timeout=5, pool_recycle=1800, pool_pre_ping=True,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    app.state.http = httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=3.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=False,
    )
    try:
        yield
    finally:
        await app.state.http.aclose()
        await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    prod = settings.environment == "production"
    app = FastAPI(
        title="Orders API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None if prod else "/docs",
        redoc_url=None,
        openapi_url=None if prod else "/openapi.json",
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        inbound = request.headers.get("x-request-id", "")
        request.state.request_id = inbound if 8 <= len(inbound) <= 64 and inbound.isascii() and inbound.isalnum() \
            else uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if prod:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # add_middleware: the LAST one added is the OUTERMOST.
    # BodySizeLimitMiddleware wraps request_context so oversized bodies are rejected before buffering,
    # while CORSMiddleware and TrustedHostMiddleware remain outermost.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(o).rstrip("/") for o in settings.cors_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    register_exception_handlers(app)
    app.include_router(orders.router)
    return app

```

Notes: do **not** call `create_app()` at module import time (run Uvicorn with `--factory open_enterprise_ai.main:create_app`); calling `create_app()` at import time triggers `get_settings()` before test fixtures can override env vars. Put the `request_id` value into logging via a `contextvars`-based filter; sanitize inbound IDs (done above) to prevent log injection. Run behind a reverse proxy/ingress that terminates TLS, set `--forwarded-allow-ips` to the proxy only, and apply rate limiting at the gateway **and** (for auth/write/expensive routes) in-app with a Redis-backed limiter keyed by principal, falling back to client IP. Health endpoints: `/livez` (process up) and `/readyz` (dependencies reachable) return only a status, never versions or stack details.

<!-- sample: src/open_enterprise_ai/api/middleware.py -->
```python
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Pure-ASGI body cap that also works for chunked uploads with no Content-Length."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return
        received = 0
        responded = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal responded
            responded = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not responded:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"type":"urn:problem:payload_too_large","title":"Payload too large","status":413}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/problem+json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(BaseException):
    """Subclasses BaseException so app-level `except Exception:` handlers never swallow a 413 abort."""

```

---

## 3. Concurrency & Lifespan Rules

1. **`async def` only if every I/O inside is non-blocking** (`AsyncSession`, `httpx.AsyncClient`, `redis.asyncio`, `aiofiles`). For a sync library either declare the route/dependency as plain `def` (FastAPI runs it in a threadpool) or `await run_in_threadpool(fn, *args)`.
2. **CPU-heavy work** (password hashing, image/PDF processing, big `pandas`/JSON parsing, crypto KDFs) goes to a threadpool, or to a process pool/queue if it holds the GIL for long.
3. **Shared clients live in `lifespan**` and are reached via `request.app.state` (see `main.py`). One `httpx.AsyncClient` per upstream-pool, never per request.
4. **Never hold a DB transaction across an external call.** Use the 3-phase flow: commit `PENDING` → call the external service outside the session → new transaction to record `COMPLETED`/`FAILED`. Make the external call idempotent (send your idempotency key).
5. **Long/critical work** is not a `BackgroundTasks` job (no persistence, no retry). Use a durable queue (ARQ/Celery/Taskiq) or an outbox table.
6. **Graceful shutdown:** every resource opened in `lifespan` is closed in `finally`. Set `timeout_graceful_shutdown` for the server.
7. **Async SQLAlchemy:** `expire_on_commit=False`, no lazy loading in async context (use `selectinload`/`joinedload`), `pool_pre_ping=True`, bounded pool, statement/lock timeouts set at the database role level.

---

## 4. Pydantic v2 & Input Hardening

* Every request schema inherits `StrictInput` (or sets `extra="forbid"` + `str_strip_whitespace=True` itself). The scanner enforces this by class-name suffix (`Create|Update|Patch|Request|Input|Payload|Command|Params|Filter|Body`), so name request models accordingly.
* **Every** `str`/`list`/`dict` field has `max_length`; numbers have `ge/le`; free-form `dict` is avoided (model it). Use `Literal`/`Enum` for closed sets, `pattern=` for identifiers, `EmailStr`/`AnyHttpUrl` for those types. Nested models are bounded too.
* Update schemas are all-optional **and** reject empty bodies; never reuse the Create schema for PATCH, and never accept `id`, `tenant_id`, `role`, `is_admin`, `created_by`, `status` transitions from the client unless the spec says so (mass assignment).
* **No I/O in validators.** Uniqueness/foreign-key/authorization checks belong in the service.
* **Money = `Decimal**` with `max_digits`/`decimal_places`; never `float`. Timestamps are timezone-aware UTC (`datetime.now(UTC)`).
* Response schemas use `from_attributes=True` and list fields explicitly; do not `exclude=` your way to safety, **allow-list** instead.

---

## 5. Security Primitives

**JWT** — see `deps.py`: `algorithms=[one pinned algorithm]`, `audience`, `issuer`, `options={"require": [...]}` (PyJWT takes `require` inside `options`, not as a keyword). Asymmetric keys for multi-service setups; fetch JWKS via a cached client and select by `kid`. Never accept `none`, never mix HS/RS families, never decode without verification to "peek" at claims for authorization.

**Passwords** — argon2id (or bcrypt cost >= 12); hashing runs in a threadpool; verify with constant-time library calls; rehash on login when parameters change; same error and similar latency for unknown user vs wrong password (verify against a precomputed dummy hash when the user lookup returns `None`).

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from starlette.concurrency import run_in_threadpool

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("dummy-password-for-constant-time-user-miss")

async def verify_password(stored_hash: str | None, password: str) -> bool:
    target = stored_hash if stored_hash is not None else _DUMMY_HASH
    try:
        matched = await run_in_threadpool(_hasher.verify, target, password)
        return matched and (stored_hash is not None)
    except VerifyMismatchError:
        return False

```

**Webhooks & signatures** — HMAC over `timestamp + "." + raw_body`, reject stale timestamps, compare in constant time via `secrets.compare_digest`, and de-duplicate by event ID (replay protection).

```python
import hashlib, hmac, secrets, time

def verify_webhook(*, secret: bytes, body: bytes, timestamp: str, signature: str, tolerance_s: int = 300) -> bool:
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > tolerance_s:
        return False
    expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return secrets.compare_digest(expected, signature)

```

**File uploads** — never `await file.read()` unbounded. Read in chunks with a cumulative cap, verify magic bytes (not `content_type`/filename), store under a generated UUID name outside the web root, scan if required, serve with `Content-Disposition: attachment` and `nosniff`.

```python
async def read_limited(file: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := await file.read(65536):
        size += len(chunk)
        if size > max_bytes:
            raise PayloadTooLargeError()
        chunks.append(chunk)
    return b"".join(chunks)

```

**SQL** — ORM/Core expressions first. If `text()` is unavoidable: `text("... WHERE id = :id").bindparams(id=value)`. Identifiers (column/table/sort fields) come from an allow-list mapping, never from input.

**Outbound HTTP & SSRF** — shared client with explicit timeouts, `follow_redirects=False`, bounded retries (idempotent verbs only, exponential backoff + jitter), response size caps (stream and count), TLS verification on. For any user-influenced URL, validate scheme + resolve DNS and reject non-global IPs; add network egress policy as defense in depth (DNS rebinding can defeat check-then-fetch).

```python
import asyncio, ipaddress, socket
from urllib.parse import urlsplit

async def assert_public_https_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise UnsafeUrlError()
    infos = await asyncio.get_running_loop().getaddrinfo(parts.hostname, parts.port or 443, type=socket.SOCK_STREAM)
    if not infos or any(not ipaddress.ip_address(info[4][0]).is_global for info in infos):
        raise UnsafeUrlError()  # blocks loopback, RFC1918, link-local/metadata (169.254.169.254), etc.

```

**Logging** — structured JSON, `request_id` on every line, `logger.exception` for unexpected errors, never log request bodies, `Authorization`, cookies, tokens, passwords or full PII. Write an audit record for logins, permission changes, deletes and exports (who, what, tenant, when, request_id).

**Cookies/CSRF** — if auth uses cookies: `HttpOnly; Secure; SameSite=Lax|Strict`, CSRF token (double-submit or synchronizer) on state-changing routes. Bearer-header APIs are not CSRF-prone but are XSS/token-storage concerns of the client.

**Multi-tenancy depth** — application-level `tenant_id` filters are mandatory; where the database supports it (PostgreSQL), add Row-Level Security as a second layer and set the tenant per transaction (`SET LOCAL`).

---

## 6. Database & Migrations

* Alembic migrations ship in the same change as model changes, are reviewed like code, and are **expand/contract**: add nullable/new column + backfill → deploy code → later release drops the old one. No destructive change in the same release.
* Migrations run as a deploy step (`alembic upgrade head`), never at app import. CI runs `alembic upgrade head` on an empty DB and `alembic check` to detect model/migration drift.
* On PostgreSQL: create large indexes `CONCURRENTLY`, set `lock_timeout`, and avoid table rewrites on hot tables.
* Constraints encode invariants (unique, FK, check). The service translates `IntegrityError` into a domain error; it never pre-checks-then-inserts for uniqueness.
* Index every `tenant_id`-leading access path used by the new queries; paginate everything (bounded `limit`, stable `ORDER BY` with a unique tiebreaker; prefer keyset pagination for large tables).

---

## 7. Testing Requirements

Use `pytest`, `httpx.AsyncClient` + `ASGITransport`, and `asgi-lifespan`'s `LifespanManager` (**`ASGITransport` does not run `lifespan` by itself**). Use a real PostgreSQL (testcontainers or a CI service) with a rolled-back transaction per test. Mock only true external boundaries (payment gateway, email), never the repository or service under test. **In `conftest.py`, call `get_settings.cache_clear()` before any test that overrides env vars** so the `@lru_cache` in `open_enterprise_ai.core.config` does not return stale settings.

```python
# tests/conftest.py (essentials)
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"

@pytest.fixture
async def client(settings_override):            # settings_override sets env for the test DB/keys
    from open_enterprise_ai.core.config import get_settings
    get_settings.cache_clear()                    # ensure the test env is read, not a cached one
    from open_enterprise_ai.main import create_app
    app = create_app()
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c
```

```python
# tests/integration/api/test_orders.py -- the mandatory matrix for every endpoint
pytestmark = pytest.mark.anyio

async def test_create_order_happy_path(client, auth_headers_a, order_payload):
    r = await client.post("/api/v1/orders", json=order_payload, headers=auth_headers_a)
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "status", "notes", "items", "created_at"}        # no internal fields leak

async def test_create_order_rejects_unknown_field(client, auth_headers_a, order_payload):
    r = await client.post("/api/v1/orders", json={**order_payload, "tenant_id": "x"}, headers=auth_headers_a)
    assert r.status_code == 422                                                  # extra="forbid"

async def test_create_order_rejects_oversized_input(client, auth_headers_a, order_payload):
    r = await client.post("/api/v1/orders", json={**order_payload, "notes": "x" * 501}, headers=auth_headers_a)
    assert r.status_code == 422

async def test_requires_authentication(client, order_payload):
    assert (await client.post("/api/v1/orders", json=order_payload)).status_code == 401
    bad = {"Authorization": "Bearer not-a-jwt"}
    assert (await client.post("/api/v1/orders", json=order_payload, headers=bad)).status_code == 401

async def test_cross_tenant_read_is_404_and_state_unchanged(client, tenant_a_order, auth_headers_b):
    r = await client.get(f"/api/v1/orders/{tenant_a_order.id}", headers=auth_headers_b)
    assert r.status_code == 404                                                  # same as truly missing

async def test_duplicate_idempotency_key_is_409(client, auth_headers_a, order_payload):
    assert (await client.post("/api/v1/orders", json=order_payload, headers=auth_headers_a)).status_code == 201
    assert (await client.post("/api/v1/orders", json=order_payload, headers=auth_headers_a)).status_code == 409

async def test_errors_never_leak_internals(client, auth_headers_a, monkeypatch):
    # force an unexpected failure and assert a constant, sanitized payload
    ...
    assert r.status_code == 500 and "Traceback" not in r.text and r.json()["title"] == "Internal server error"
```

Also test: insufficient role -> 403, pagination cap (`limit=101` -> 422), expired and wrong-audience tokens -> 401, request body over the limit -> 413, and that a failed external call leaves no half-committed state. Security tests may not be skipped or `xfail`ed. Add a regression test for every Reviewer finding.

---

## 8. Mandatory Pre-Review Self-Check

Run and fix **every** failure; paste real output in the Handoff Note.

```bash
python .agents/skills/fastapi-skill/scripts/audit_fastapi.py <changed_files_or_dirs>   # exit 0 required
ruff check . && ruff format --check .
mypy .                                    # or pyright
bandit -r src/open_enterprise_ai -ll
pip-audit
pytest -v --cov=src/open_enterprise_ai --cov-fail-under=85
```

If you changed `audit_fastapi.py`, also run `pytest .agents/skills/fastapi-skill/scripts/tests`.

### Change Report & Handoff Note (required with every review request)

```markdown
# Change Report & Handoff Note: [Task Name]
Task: [id/link]
Spec version implemented: [id/date]
Files changed: [list]  | Out-of-bounds files touched: none
Reuse Ladder rung used: [1-7 per new component; helpers/libraries reused]
Reused helpers/libraries (ladder rung): [e.g. "stdlib hmac (rung 3)", "existing open_enterprise_ai.core.security.compare_digest (rung 2)"]
New dependencies: [name | exact-PyPI-name verified | license | maintenance | pinned in lockfile | rung justified] or none
Sub-agents / skill used: coder / fastapi-skill
Docs updated: [OpenAPI metadata, .env.example entries, README/ADR/runbook]
Migrations: [revision ids or none; expand/contract notes]
New suppressions (rule, file:line, justification): [list or none]
Deviations from spec and why: [list or none]
Known limitations / follow-up tasks: [list or none]
Commands run and actual results:
  - audit_fastapi.py: [exit code + actual output]
  - ruff / mypy / bandit / pip-audit: [actual output]
  - pytest: [N passed, cov X%, 0 skipped security tests]
Security considerations: [BOLA scoping, authn/authz, new suppressions (rule, file:line, justification), or deviations]
Docs updated: [OpenAPI metadata, .env.example entries, README/ADR/runbook updates]
Migration/rollback notes: [Alembic revision IDs, expand/contract notes, rollback steps]
Unresolved issues: [none | specific items requiring Orchestrator attention]

```

---

## 9. Addressing Reviewer Findings

When the Reviewer returns `REQUEST CHANGES`:

1. Reply per finding ID (`F-1`...): fixed in `<file:line>` + regression test `<test name>`, **or** disputed with concrete evidence for the Orchestrator to adjudicate.
2. Fix root causes of every blocking defect. Do not paper over with `# noqa`, `# type: ignore`, `# nosec` or `# audit: ignore`.
3. Add a regression test that fails before the fix and passes after.
4. After 3 failed fix attempts or 3 rounds on one finding, stop and escalate to the Orchestrator.
