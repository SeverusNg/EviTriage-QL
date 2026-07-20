.PHONY: sync format lock-check lint typecheck schema-check test check clean

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

test:
	uv run pytest

check: lock-check lint typecheck schema-check test

clean:
	@echo "Refusing broad cleanup; use managed workspace lifecycle operations."
