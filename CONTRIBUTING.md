# Contributing

EviTriage-QL is developed as reproducible security-research software. Changes
should make their trust assumptions, evidence, and current gate explicit.

## Set up the development environment

Install Python 3.12, `uv 0.8.3`, and Make. Required tools must live in a
persistent user or system location and resolve from `PATH` in a fresh login
shell; a `/tmp` bootstrap is not an accepted handoff environment. The uv version
is enforced by `pyproject.toml`. Verify it, then run:

```bash
command -v uv
uv --version
uv sync --all-extras
make check
uv run evitriage doctor --json
```

The default tests and Gate E demo require no model API key, Java, or real CodeQL
installation: they use synthetic Golden SARIF and fixed Replay entries. CodeQL
and a matching JDK may be installed for the separate real-scan path, but their
absence must not be hidden.

## Make a focused change

1. Read `AGENTS.md`, `docs/architecture.md`, and any ADR governing the area.
2. Keep target-project data in ProjectSpec/configuration, not core code.
3. Add tests for the normal path, malformed input, and relevant security edge
   cases.
4. Run focused tests, then `make check`.
5. Update documentation, `CHANGELOG.md`, `KNOWN_LIMITATIONS.md`, and the progress
   log when public behavior or delivery evidence changes.

Do not add empty future modules, fabricated tool output, downloaded third-party
repositories, secrets, private configs, model responses, or generated runtime
artifacts. Do not weaken strict validation merely to accept an ambiguous input.

## Code and test expectations

- Format and lint with Ruff; type-check with mypy strict; test with pytest.
- Public APIs need types and concise docstrings.
- Pydantic input models reject extra fields and perform semantic validation.
- External commands use validated argument vectors and never `shell=True`.
- Tests must be deterministic, offline by default, and isolated from the user's
  source directory.
- File-system tests must include traversal/symlink considerations and clean up
  only paths they own.
- Logs and JSON diagnostics must not expose secrets.

The canonical aggregate command is:

```bash
make check
```

Use `uv run pytest --collect-only -q` before selecting a focused path so that
documentation and review notes refer to tests that exist in the current tree.

## Fixtures and research data

Repository fixtures must be minimal, synthetic or clearly redistributable, and
carry enough provenance to understand their ground truth. Do not vendor a real
third-party repository. Large datasets belong behind explicit manifests and
materialization scripts in a later gate, never in the default test download.

## Security and disclosure

Source code under analysis is hostile data, not instructions. A contribution
must not grant it shell, network, file-write, model-selection, or secret access.
Report security issues privately as described in `SECURITY.md`; do not put an
undisclosed vulnerability into a pull request or public issue.

## Review checklist

- The change stays within the declared gate and does not overclaim capability.
- Configuration and output schemas remain strict and versioned.
- Original source directories remain unchanged.
- Commands, hashes, timestamps, and errors are structured and reproducible.
- Tests and `make check` pass with real reported results.
- User-facing behavior and limitations are documented.
