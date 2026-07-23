.PHONY: sync format lock-check lint typecheck schema-check secret-check test security-test check demo clean

EVITRIAGE_COMMAND ?= uv run --offline evitriage

sync:
	uv sync --all-extras

format:
	uv run ruff format .
	uv run ruff check --fix .

lock-check:
	uv lock --check

lint:
	uv run ruff format --check .
	uv run ruff check .

typecheck:
	uv run mypy src tests

schema-check:
	uv run python -m evitriage.schema_generation --check

secret-check:
	uv run python -m evitriage.secret_scan

test:
	uv run pytest

security-test:
	uv run pytest -m security --no-cov

check: lock-check lint typecheck schema-check secret-check test

demo:
	@$(EVITRIAGE_COMMAND) triage \
		--project-config configs/projects/gate-e-demo.yaml \
		--sarif tests/fixtures/sarif/gate-e-three-label.sarif \
		--evidence-supplement tests/fixtures/evidence/gate-e-three-label-supplement.json \
		--llm-profile configs/llm/replay-v0.1.yaml \
		--replay-cache tests/fixtures/replay-bundles/gate-e-three-label-v0.1 \
		--json

clean:
	@echo "Refusing broad cleanup; use managed workspace lifecycle operations."
