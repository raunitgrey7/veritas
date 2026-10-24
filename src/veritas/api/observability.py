"""Structured JSON logging, request IDs and a tiny Prometheus registry.

The service has no external observability dependency. Logs are one JSON object
per line so they ingest cleanly into any log pipeline. Metrics are exposed in
Prometheus text format from a hand-rolled registry; a few counters are enough to
show request volume and verdict distribution without pulling in a client library.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections import defaultdict


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "method", "path", "status", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Install the JSON formatter on a dedicated logger and return it."""
    logger = logging.getLogger("veritas.api")
    logger.setLevel(level.upper())
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


class MetricsRegistry:
    """A minimal, thread-safe counter registry rendered as Prometheus text."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._help: dict[str, str] = {}

    def register(self, name: str, help_text: str) -> None:
        """Declare a counter and its help line."""
        self._help[name] = help_text

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        """Increment a counter identified by name and label set."""
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counters[key] += value

    def render(self) -> str:
        """Render all counters in Prometheus text exposition format."""
        lines: list[str] = []
        emitted: set[str] = set()
        with self._lock:
            items = sorted(self._counters.items())
        for (name, labels), value in items:
            if name not in emitted:
                lines.append(f"# HELP {name} {self._help.get(name, name)}")
                lines.append(f"# TYPE {name} counter")
                emitted.add(name)
            label_str = ",".join(f'{k}="{v}"' for k, v in labels)
            suffix = f"{{{label_str}}}" if label_str else ""
            lines.append(f"{name}{suffix} {value}")
        return "\n".join(lines) + "\n"
