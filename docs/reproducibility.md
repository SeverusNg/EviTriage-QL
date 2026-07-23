# Reproducing the v0.2.0 release

This document covers the `v0.2.0` release path. It retains the bounded Gate G
offline research vertical and adds the fail-closed multi-credential extension
described in the release notes and dated progress log; a successful
reproduction is not an accuracy or production-readiness claim.

## Build and verify the release directory

Use Python 3.12, persistent `uv 0.8.3`, and GNU Make. A first dependency sync
can require network access; the build/demo paths are offline once all locked
packages and the Maven distribution needed by a real scan are cached.

```bash
uv sync --all-extras
make check
make release-artifacts
make release-verify
```

The default directory is `dist/release/0.2.0/` and is ignored by Git. It
contains:

- the `0.2.0` wheel and source distribution;
- `requirements-all.lock`, exported from `uv.lock` with package hashes;
- `evitriage-ql.cdx.json`, a deterministic CycloneDX 1.5 runtime/dev SBOM;
- `case-matrix.json`, the six case/CWE/source/result/decision bindings;
- `example-decisions.jsonl`, `example-report.html`, and the corresponding
  `example-run-manifest.json` from a fresh finalized offline demo;
- `example-demo-summary.json`, `pytest-summary.json`, and
  `security-test-summary.json`, recording the actual demo and test outcomes;
- `release-manifest.json`, freezing the uv lock, public schema set, prompt
  version, file sizes, and file SHA-256 values;
- `SHA256SUMS`, which also covers the release manifest.

`make release-artifacts` runs the full branch-aware pytest suite, the named
security subset, and a fresh six-case demo before assembly. It rejects a failed
test summary, a non-finalized or writable run, a report/case/source mismatch,
or an altered prompt-injection outcome. Rebuilding into a directory containing
an unknown old file fails instead of silently publishing mixed versions. The
verifier rejects symlinks, unsafe names, duplicate records, and any registered
byte/size change.

## Reinstall from the source distribution

Create a new directory outside the checkout and substitute the release archive
path produced above:

```bash
mkdir /tmp/evitriage-clean-room
tar -xzf dist/release/0.2.0/evitriage_ql-0.2.0.tar.gz \
  -C /tmp/evitriage-clean-room
cd /tmp/evitriage-clean-room/evitriage_ql-0.2.0
uv sync --all-extras
make check
make demo
uv run evitriage doctor --json
```

`uv sync --all-extras --offline` is the stronger cached-dependency check. It
must fail honestly when a required wheel is absent; the ordinary first install
may use the package index. `make demo` itself uses Replay only and makes no
model/provider request. A successful summary must be `JUDGED`, contain six
alerts with exactly three TP, two FP, and one NMC, make eighteen Replay calls,
and keep `real_codeql=false`. The six rows cover CWE-22 TP/FP/NMC, CWE-78
TP/FP, and a prompt-injection case whose final label remains TP.

The sdist secret scan does not pretend a `.git` directory exists. It validates
the package identity using `PKG-INFO`, `pyproject.toml`, and `uv.lock`, scans
the releasable tree, excludes only named top-level runtime/build output, and
rejects other symlinks/non-regular files.

## Run the separate real CodeQL smoke

The real-tool path requires the configured Java 17, CodeQL CLI 2.26.1, and the
pinned Maven 3.9.9 distribution in the wrapper cache:

```bash
uv run evitriage doctor --json
uv run evitriage scan \
  --project-config configs/projects/gate-e-demo.yaml \
  --json
```

Accept the smoke only when the summary says `real_codeql=true`, reports
CodeQL `2.26.1`, and reaches `CONTEXT_READY`. The accepted 2026-07-23 run found
four real query results in the self-contained matrix project: two
`java/path-injection` results plus `java/command-line-injection` and
`java/relative-path-command` on the direct command case. This need not equal
the synthetic six-result Golden SARIF, whose purpose is deterministic decision
coverage. Rehash every registered artifact against `run-manifest.json` and
verify final owner-read-only modes. A CodeQL path proves query/pipeline
execution; it is not an EviTriage TP/FP/NMC verdict, an exploit proof, or
evidence about arbitrary repositories.

The exact commands, failures, run IDs, hashes, and exit codes from the current
Gate G attempt are recorded in
[`docs/progress/2026-07-27-v0.1.md`](progress/2026-07-27-v0.1.md).

## Independent replay handoff

Give a reviewer the exact release directory without modifying its contents.
They can first run `make release-verify RELEASE_DIR=/path/to/release`, compare
`SHA256SUMS`, reinstall the sdist into a new directory using the procedure
above, and run `make check`, `make security-test`, and `make demo`. A matching
six-case summary and Replay analysis identity demonstrates byte- and
identity-bound replay. Record the reviewer, host/tool versions, commands, exit
codes, and resulting hashes separately; this checkout does not fabricate a
third-party or second-host result.
