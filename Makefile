.PHONY: setup lint test bench gate report corpus serve clean all

# Install the project and all dev dependencies into a local .venv.
setup:
	uv sync --all-extras

# Static analysis: ruff must be clean.
lint:
	uv run ruff check src tests

# Unit, integration, property-based, adversarial and determinism tests.
test:
	uv run pytest -q

# Build the corpus, evaluate, and write benchmarks/results.json and results.md.
bench:
	uv run python -m veritas.benchmark

# Fail if the latest results regress against benchmarks/baseline.json or breach thresholds.
gate:
	uv run python -m veritas.gate

# Render the self-contained HTML report from the latest results.
report:
	uv run python -m veritas.report

# Write the corpus JSONL files under data/ and print coverage.
corpus:
	uv run python -m veritas.cli corpus

# Serve the API and dashboard on http://127.0.0.1:8000 .
serve:
	uv run uvicorn veritas.api.app:app --host 127.0.0.1 --port 8000

# Remove generated artefacts (the corpus and results are regenerated on demand).
clean:
	rm -rf .pytest_cache .ruff_cache .hypothesis benchmarks/report.html
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# Convenience target for local verification.
all: lint test bench gate
