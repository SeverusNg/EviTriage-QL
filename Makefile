.PHONY: sync format lock-check lint typecheck schema-check secret-check test security-test check demo release-artifacts release-verify clean

EVITRIAGE_COMMAND ?= uv run --offline evitriage
RELEASE_DIR ?= dist/release/0.2.0
DEMO_ARGUMENTS = triage \
	--project-config configs/projects/gate-e-demo.yaml \
	--sarif tests/fixtures/sarif/gate-e-three-label.sarif \
	--evidence-supplement tests/fixtures/evidence/gate-e-three-label-supplement.json \
	--llm-profile configs/llm/replay-v0.1.yaml \
	--replay-cache tests/fixtures/replay-bundles/gate-e-three-label-v0.1 \
	--json

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
	@$(EVITRIAGE_COMMAND) $(DEMO_ARGUMENTS)

release-artifacts:
	uv build --offline --out-dir $(RELEASE_DIR)
	uv export --quiet --all-extras --locked --no-header --no-emit-project --output-file $(RELEASE_DIR)/requirements-all.lock
	uv run --offline pytest --release-suite=full --release-summary=$(RELEASE_DIR)/pytest-summary.json
	uv run --offline pytest -m security --no-cov --release-suite=security --release-summary=$(RELEASE_DIR)/security-test-summary.json
	@$(EVITRIAGE_COMMAND) $(DEMO_ARGUMENTS) > $(RELEASE_DIR)/example-demo-summary.json
	uv run --offline python -m evitriage.release --output-dir $(RELEASE_DIR) --assemble-example $(RELEASE_DIR)/example-demo-summary.json

release-verify:
	uv run --offline python -m evitriage.release --output-dir $(RELEASE_DIR) --verify

clean:
	@echo "Refusing broad cleanup; use managed workspace lifecycle operations."
