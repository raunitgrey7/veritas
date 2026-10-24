"""FastAPI service and single-page dashboard for veritas.

``app.create_app`` is the application factory; ``app.app`` is the module-level
instance uvicorn serves. The service exposes guardrail scanning, corpus coverage
and the latest benchmark result, plus ``/health`` and ``/metrics``.
"""

from veritas.api.app import app, create_app

__all__ = ["app", "create_app"]
