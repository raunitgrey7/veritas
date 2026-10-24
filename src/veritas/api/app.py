"""FastAPI application: guardrail scanning, corpus coverage and the dashboard.

Endpoints:

* ``GET /health`` liveness and version.
* ``GET /metrics`` Prometheus text exposition.
* ``POST /scan`` evaluate a prompt with the input guardrail.
* ``POST /scan/output`` evaluate a model output with the output scanners.
* ``GET /corpus/coverage`` corpus counts for the dashboard.
* ``GET /benchmark/latest`` the most recent benchmark result, if present.
* ``GET /`` the single-page dashboard served from static files.

Every request gets a request id (from the incoming header or generated) that is
echoed back and logged. When ``APP_API_KEY`` is set, the scan endpoints require a
matching ``x-api-key`` header.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from veritas import __version__
from veritas.api.observability import MetricsRegistry, configure_logging
from veritas.api.schemas import (
    CoverageResponse,
    HealthResponse,
    OutputScanRequest,
    ScanRequest,
    ScanResponse,
    SignalOut,
)
from veritas.api.settings import Settings, get_settings
from veritas.corpus import build_attack_corpus, build_benign_corpus, coverage
from veritas.detectors import Guardrail
from veritas.detectors.pipeline import GuardVerdict

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _build_metrics() -> MetricsRegistry:
    registry = MetricsRegistry()
    registry.register("veritas_requests_total", "HTTP requests handled")
    registry.register("veritas_scan_verdicts_total", "Scan verdicts by decision")
    return registry


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory so tests can inject settings and get a fresh state."""
    cfg = settings or get_settings()
    app = FastAPI(title="veritas", version=__version__,
                  description="LLM evaluation, red-teaming and guardrail platform.")
    app.state.settings = cfg
    app.state.logger = configure_logging(cfg.log_level)
    app.state.metrics = _build_metrics()
    app.state.guardrail = Guardrail()
    app.state.coverage = coverage(build_attack_corpus(), build_benign_corpus())
    _register_middleware(app)
    _register_routes(app)
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def _register_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def observe(request: Request, call_next):  # noqa: ANN001, ANN202
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 3)
        response.headers["x-request-id"] = request_id
        app.state.metrics.inc("veritas_requests_total",
                              {"path": request.url.path, "method": request.method,
                               "status": str(response.status_code)})
        app.state.logger.info("request", extra={
            "request_id": request_id, "method": request.method,
            "path": request.url.path, "status": response.status_code,
            "duration_ms": duration_ms})
        return response


def require_api_key(request: Request,
                    x_api_key: Annotated[str | None, Header()] = None) -> None:
    """Dependency that enforces the API key when one is configured."""
    configured = request.app.state.settings.api_key
    if configured and x_api_key != configured:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def _to_response(verdict: GuardVerdict) -> ScanResponse:
    return ScanResponse(
        verdict=verdict.verdict.value, risk=round(verdict.risk, 4),
        categories=verdict.categories, reasons=verdict.reasons,
        signals=[SignalOut(detector=s.detector, category=s.category, score=s.score,
                           explanation=s.explanation, evidence=s.evidence)
                 for s in verdict.signals])


def _register_routes(app: FastAPI) -> None:
    guard_dep = Depends(require_api_key)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", service=app.state.settings.service_name,
                              version=__version__)

    @app.get("/metrics")
    def metrics() -> Response:
        return PlainTextResponse(app.state.metrics.render(), media_type="text/plain")

    @app.post("/scan", response_model=ScanResponse, dependencies=[guard_dep])
    def scan(req: ScanRequest) -> ScanResponse:
        verdict = app.state.guardrail.evaluate_input(req.prompt, canary=req.canary)
        app.state.metrics.inc("veritas_scan_verdicts_total", {"verdict": verdict.verdict.value})
        return _to_response(verdict)

    @app.post("/scan/output", response_model=ScanResponse, dependencies=[guard_dep])
    def scan_output(req: OutputScanRequest) -> ScanResponse:
        verdict = app.state.guardrail.evaluate_output(req.output, canary=req.canary)
        app.state.metrics.inc("veritas_scan_verdicts_total", {"verdict": verdict.verdict.value})
        return _to_response(verdict)

    @app.get("/corpus/coverage", response_model=CoverageResponse)
    def corpus_coverage() -> CoverageResponse:
        return CoverageResponse(**app.state.coverage)

    @app.get("/benchmark/latest")
    def benchmark_latest() -> Response:
        path = Path(app.state.settings.results_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="no benchmark results found")
        return Response(content=path.read_text(encoding="utf-8"), media_type="application/json")

    @app.get("/")
    def index() -> Response:
        page = STATIC_DIR / "index.html"
        if not page.exists():
            return PlainTextResponse("veritas API. dashboard not built.", status_code=200)
        return FileResponse(page)


app = create_app()
