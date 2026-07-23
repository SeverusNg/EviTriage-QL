# EviTriage-QL Deployment and Operations Guide

[English](deployment-guide.md) | [简体中文](deployment-guide.zh-CN.md)

This guide is for operators using the project for the first time. It explains
how to turn an EviTriage-QL checkout into a working local command-line
environment, then incrementally run the offline demo, ingest existing SARIF,
perform a real CodeQL scan, and optionally invoke DeepSeek triage.

The current release is a research CLI, not a web service. It has no listening
port, background daemon, task queue, or multi-user console, and it does not
require an external database server. Each command creates a new auditable run
directory; optional metadata uses local SQLite. Deployment therefore does not
mean starting a permanently online automated vulnerability-remediation service.

## 1. Choose a path first

Start with the first row and add external tools, network access, and data
exposure only when they are needed.

| Path | What it demonstrates | Additional dependencies | Successful terminal state |
| --- | --- | --- | --- |
| `make demo` | Reproducible end-to-end workflow and deterministic reports for six synthetic cases | No Java, CodeQL, API key, or real model | `JUDGED` |
| `ingest-sarif` | Existing SARIF can be preserved, normalized, and bound to source context/evidence | Local source matching the SARIF | `CONTEXT_READY` |
| `triage --sarif` with Replay | Existing SARIF can pass through three agents and the conservative policy | A trusted read-only Replay cache matching exact request hashes | `JUDGED` |
| `scan` | Real CodeQL can build a project, produce SARIF, and extract context | JDK 17, CodeQL 2.26.1, cached Maven 3.9.9 | `CONTEXT_READY` |
| `triage --scan` | A fresh real scan can continue directly to reports | Real-scan environment plus Replay data or authorized DeepSeek | `JUDGED` |
| DeepSeek `triage` | Controlled evidence can be sent to the fixed remote model endpoint for three-stage triage | Network access, explicit upload policies, and a securely handed-off API key | `JUDGED` |

`TP`, `FP`, and `NMC` are secondary-triage labels. Regardless of the label,
`auto_dismiss` is always `false`; the system never closes a CodeQL alert
automatically. Golden SARIF, Replay responses, and evidence supplements are
synthetic fixtures and are not evidence of accuracy on a real project.

## 2. Deployment topology and directories

Treat the checkout, input source, and runtime output as three separate security
domains:

```text
EviTriage-QL checkout
├── src/, configs/, tests/       # program, trusted examples, synthetic fixtures
├── .venv/                       # Python environment managed by uv
├── workspaces/                  # source snapshots, build copies, CodeQL databases
└── artifacts/
    ├── evitriage.db             # optional local SQLite metadata
    └── runs/<run-id>/           # SARIF, evidence, model stages, reports, manifest

/path/to/target-source/          # operator input, treated as read-only
~/.local/share/... or
~/.password-store/...           # optional encrypted credentials outside the repository
```

The default `workspaces/`, `artifacts/`, and secret-related files are ignored
by Git. They can contain private source, SARIF, source excerpts, and model
output, so protect them at least as strongly as the target source. Do not place
them in public artifacts, ordinary CI logs, or source-control commits.

A successful full triage run normally produces:

```text
artifacts/runs/<run-id>/
├── workflow-events.jsonl
├── run-manifest.json
├── input/source.sarif or codeql/results.sarif
├── normalized/alerts.json
├── context/
├── evidence/
├── triage/{analyst,rebuttal,judged}.json
└── reports/{decisions.jsonl,index.html}
```

At finalization, registered artifacts, the event log, and the manifest are
reverified by SHA-256 and made owner-read-only (`0400`). This is expected, not
a permission failure; do not broadly relax permissions merely for convenient
viewing.

## 3. Base environment

### Required components

- A Linux or WSL shell;
- Python 3.12; package metadata permits `>=3.12,<3.14`, while the current
  acceptance baseline uses 3.12;
- persistent `uv 0.8.3` discoverable on `PATH` in a fresh login shell;
- GNU Make or a compatible `make`;
- enough local disk for dependencies, source copies, and run artifacts.

`pyproject.toml` rejects a uv version other than `0.8.3`. Install uv through its
official installation path or a controlled package manager, but verify the
executable that the shell actually resolves. A temporary bootstrap under
`/tmp` is not a completed deployment.

```bash
cd /path/to/EviTriage-QL

python3 --version
command -v uv
uv --version
make --version
```

Expect `uv --version` to print `uv 0.8.3`. The first dependency sync can access
a Python package index. An organization requiring offline installation must
pre-populate the uv cache or provide an internal mirror built from the verified
source distribution and locked dependencies. Once dependencies are available,
the demo and default tests make no model-service request.

```bash
uv sync --all-extras
uv run --offline evitriage version
```

If the deployment needs the Gate A local metadata tables, explicitly initialize
or upgrade the managed SQLite database:

```bash
uv run evitriage db migrate --json
```

The default file is `artifacts/evitriage.db` with mode `0600`. Offline demo,
SARIF, and run-manifest artifacts remain in their run directories. This
migration does not turn the project into a database service and needs no
separate database process.

Run commands from the repository root. If invocation from another directory is
unavoidable, set `EVITRIAGE_PROJECT_ROOT` to the current EviTriage-QL root. Do
not allow an untrusted target project to control that variable.

## 4. First start: run completely offline

Run environment diagnostics, the complete quality gate, and the demo:

```bash
uv run evitriage doctor --json
make check
make security-test
make demo
```

- `doctor` reports the real state of Python, uv, SQLite, managed directories,
  Java, `javac`, and CodeQL. Missing Java/CodeQL is acceptable for the offline
  demo, but not for a real scan.
- `make check` covers lock validation, formatting, lint, mypy, schemas, secret
  scanning, pytest, and the branch-coverage gate.
- `make security-test` selects prompt-injection, malicious-URI,
  path/symlink, HTML-escaping, shell-metacharacter, and secret-redaction
  regressions.
- `make demo` uses fixed Replay data, does not load an API key, and makes no
  model network request.

A successful `make demo` emits a JSON `TriageRunSummary` with these main
properties:

- `state` is `JUDGED`;
- `real_codeql` is `false`;
- six alerts produce three `TP`, two `FP`, and one `NMC`;
- eighteen Replay calls are made;
- `artifact_run_root` identifies the audit directory for the run.

Open `artifact_run_root/reports/index.html` for the self-contained escaped
report. `reports/decisions.jsonl` is intended for machine processing. Its
labels are reproducibility evidence for fixed synthetic cases, not a
model-quality benchmark.

## 5. Connect existing SARIF

This is the least expensive and lowest-risk way to connect your own project.
It does not execute the target build and does not require CodeQL or a model,
but the operator must provide the **source revision that produced the SARIF**.

### 5.1 Create a project configuration

Copy the closest ProjectSpec example, such as
`configs/projects/example-local.yaml`. Name a private file
`configs/projects/private-<name>.yaml`; that pattern is already ignored by Git.
Review at least:

| Configuration | Purpose |
| --- | --- |
| `project.id` | Stable, non-secret project identity |
| `source.path` | Local source directory corresponding to the SARIF |
| `source.snapshot_mode` | Currently must be `copy` |
| `build.command` | Maven Wrapper argument vector used by a real scan |
| `codeql.cli_version` | Current real-scan gate pins `2.26.1` |
| `analysis.target_cwes` | CWEs in scope for this run |
| `security.source_upload_policy` | Keep `offline_only` for offline paths |
| `storage.workspace_root` / `artifact_root` | Distinct, non-overlapping managed write roots |

ProjectSpec uses a strict schema. Unknown fields, path or symlink escape, shell
commands, unpinned query packs, and unsafe build settings are rejected.

### 5.2 Validate and ingest

For source inside the checkout:

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --json

uv run evitriage ingest-sarif \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --json
```

For source outside the checkout, a trusted operator must explicitly repeat the
allowed root on both commands:

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json

uv run evitriage ingest-sarif \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

Success reaches `CONTEXT_READY`. The system preserves the raw SARIF bytes,
records the exact `(SARIF SHA-256, run index, result index)`, and generates
normalized alerts, source slices, an evidence registry, an evidence graph, and
an escaped source map.

If a SARIF-declared file hash conflicts with current source, the system rejects
it. A missing file is recorded explicitly as unknown/partial context rather
than claiming verified coordinates. `CONTEXT_READY` is not a `TP`/`FP`/`NMC`
verdict.

## 6. Offline Replay triage

Continue from existing SARIF with:

```bash
uv run evitriage triage \
  --project-config configs/projects/private-example.yaml \
  --sarif /path/to/result.sarif \
  --llm-profile configs/llm/replay-v0.1.yaml \
  --replay-cache /trusted/read-only/replay-cache \
  --json
```

The Replay cache must be trusted, read-only, free from symlink escape, and
already contain a strict structured response matching every canonical model
request SHA-256. The repository includes only the fixed six-case demo cache;
it has **no** general Replay-cache producer for arbitrary projects. A missing
entry produces an auditable `MODEL_FAILED` state and never silently switches
to a network model.

`--evidence-supplement` can add reviewed evidence, but the supplement must be
strictly bound to the project, source snapshot, raw SARIF, and exact result
occurrence. It can add assertions only and cannot set the final label. Never
reuse the demo supplement for another project.

## 7. Deploy the real CodeQL scan environment

EviTriage-QL does not install the JDK, CodeQL, or Maven. Checked-in
configurations currently require:

- matching `java` and `javac` from the same JDK 17;
- CodeQL CLI `2.26.1` on `PATH`;
- a validated Maven Wrapper in the target source;
- Maven `3.9.9`, as declared by the wrapper, already populated in cache by a
  controlled step because the actual build command includes `--offline`;
- exact `scope/name@x.y.z` pins for optional query/model packs.

Verify external tools first:

```bash
codeql version --format=terse
java -version
javac -version
uv run evitriage doctor --json
```

Then validate the configuration and scan:

```bash
uv run evitriage project validate \
  --config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json

uv run evitriage scan \
  --project-config configs/projects/private-example.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

A successful `scan` must report `real_codeql=true`, CodeQL `2.26.1`, and
`CONTEXT_READY`. A missing tool, version mismatch, build failure, timeout, or
unsafe output creates a structured failure; Golden SARIF is never substituted
as a fabricated success.

A real scan executes the target Maven build as the current host user. Managed
copies and argument validation are not a complete operating-system sandbox.
For any project that is not fully trusted, add an external dedicated
least-privilege account or isolated VM/container with network, CPU, memory,
process, and filesystem limits. Do not expose cloud credentials, an SSH agent,
developer tokens, or unrelated project secrets to the scan account. The
repository does not currently ship a container template that should be treated
as a production sandbox.

## 8. Go directly from a real scan to triage

`triage` requires exactly one of `--sarif` and `--scan`. With a prepared Replay
cache:

```bash
uv run evitriage triage \
  --project-config configs/projects/private-example.yaml \
  --scan \
  --llm-profile configs/llm/replay-v0.1.yaml \
  --replay-cache /trusted/read-only/replay-cache \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

This allocates a fresh run and continues from CodeQL through the JSONL/HTML
reports. A finalized old `scan` run cannot currently be resumed in place as a
triage run, and there is no `report --run-id` command. Retaining an old run is
for audit and does not change its state.

## 9. Optional remote DeepSeek triage

Enable this path only when the organization permits controlled source excerpts
and evidence to be sent to DeepSeek. The model endpoint is fixed to
`api.deepseek.com:443/chat/completions` and cannot be changed by a project
configuration. Both the trusted ProjectSpec and LLM Profile must declare
`remote_llm_allowed`, as shown by:

- `configs/projects/example-local-deepseek-v4.yaml`
- `configs/llm/deepseek-v4-pro.yaml`

**Never** place an API key in chat, command arguments, YAML, `.env`, shell
scripts, logs, Git, or run artifacts. Revoke a key exposed in chat before
enrolling a replacement through one of the following paths.

### One-process environment: WSL/Linux

```bash
(
  trap 'unset DEEPSEEK_API_KEY' EXIT
  read -rsp 'DeepSeek API Key: ' DEEPSEEK_API_KEY
  printf '\n'
  export DEEPSEEK_API_KEY

  uv run evitriage triage \
    --project-config configs/projects/private-deepseek.yaml \
    --sarif /path/to/result.sarif \
    --llm-profile configs/llm/deepseek-v4-pro.yaml \
    --credential-provider environment \
    --allowed-source-root /canonical/path/to/target-source \
    --json
)
```

### pass/GPG: persistent WSL or native Linux storage

Initialize the standard pass store outside EviTriage-QL with a
**passphrase-protected** GPG private key:

```bash
pass init <your-gpg-key-id>
uv run evitriage credentials set-deepseek --provider pass
uv run evitriage credentials status --json
```

Then pass `--credential-provider pass` to `triage`. The fixed entry is
`evitriage/deepseek-api-key`. A gpg-agent can cache the unlocked capability;
configure a short TTL appropriate to the host and lock or terminate the agent
at the end of the session.

### systemd-creds/TPM2: native Linux with TPM2

After confirming access to `/dev/tpmrm0` and a supported
`/usr/bin/systemd-creds`, enroll through the hidden double prompt:

```bash
uv run evitriage credentials set-deepseek --provider systemd-creds
uv run evitriage credentials status --json
```

Then pass `--credential-provider systemd-creds` to `triage`. WSL usually does
not support this path; use pass/GPG or the one-process environment instead.
Credential protection protects the API key only. Authorized evidence and
source excerpts are still sent to the provider and can incur cost. See
[LLM invocation, credential boundaries, and the full flow](llm-invocation-and-credential-flow.md)
for the complete boundary.

## 10. Routine operations, CI, and audit

### Before every run

```bash
uv run evitriage doctor --json
uv run evitriage project validate \
  --config /path/to/project.yaml \
  --allowed-source-root /canonical/path/to/target-source \
  --json
```

Confirm that the source revision matches the SARIF, disk capacity is
sufficient, `workspaces/` and `artifacts/` do not overlap the source, and
remote upload is actually authorized for this run.

### After every run

- Record the command, exit code, `run_id`, `state`, `artifact_run_root`, and
  `real_codeql`.
- Preserve the complete run directory, not only the HTML file.
- Audit registered artifacts against the sizes and SHA-256 values in
  `run-manifest.json`.
- Protect HTML, JSONL, and source excerpts at the same classification as the
  original source.
- On failure, inspect `metadata/error.json` and registered bounded
  stdout/stderr. Do not overwrite the failure history with a manual success.

For `--json`, successful summaries go to standard output, structured errors go
to standard error, and failures use a non-zero exit code. CI should decide from
the exit code, not by searching human-readable logs. Give every CI job distinct
managed roots and publish the complete audit run directory as a
restricted-access artifact. Inject a remote model key only as a short-lived CI
secret for that process; never write it into a workspace or cache.

The project currently allocates new runs and does not support an
operator-selected run ID, recovery from a failed stage, or workflow
continuation. `make clean` refuses broad cleanup. Define retention using exact
run directories, data classification, and audit requirements; do not perform
an unreviewed recursive deletion against the repository root, `workspaces/`, or
`artifacts/`.

To rebuild and verify the release closure:

```bash
make release-artifacts
make release-verify
```

The default output is `dist/release/0.2.0/`. See the
[reproducibility guide](reproducibility.md) for a clean source-distribution
reinstall and independent verification. A successful release build is not a
production-readiness or model-accuracy claim.

## 11. Troubleshooting

| Symptom | Check first |
| --- | --- |
| uv version rejected | Confirm `command -v uv` and `uv --version` resolve to `0.8.3` |
| Repository root not found | Run inside the checkout/extracted tree or set a trusted `EVITRIAGE_PROJECT_ROOT` |
| `doctor` reports missing CodeQL/Java | Continue for the offline demo; install the exact versions before real scanning |
| ProjectSpec path rejected | Use a canonical allowed root; avoid `..`, symlinks, and source/output overlap |
| SARIF hash or coordinate failure | Confirm the exact source revision and strict SARIF 2.1.0 input |
| Maven Wrapper fails offline | Confirm Maven 3.9.9 was populated in the wrapper cache in a controlled step |
| Replay `MODEL_FAILED` | Confirm each request-hash response exists, is read-only, and satisfies the exact role schema |
| DeepSeek configuration failure | Check both `remote_llm_allowed` declarations, model ID, credential status, and provider selection |
| Final files are not writable | `0400` is expected after finalization; create a new run instead of altering a completed one |

Use `uv run evitriage -v ...` for redacted debug-level structured logs. Do not
bypass a problem by weakening schemas, disabling path checks, or replacing a
failure with fixture output.

## 12. Deployment acceptance checklist

Minimum offline acceptance:

```bash
uv sync --all-extras
make check
make security-test
make demo
uv run evitriage doctor --json
uv run evitriage project validate \
  --config configs/projects/example-local.yaml \
  --json
uv run evitriage ingest-sarif \
  --project-config configs/projects/example-local.yaml \
  --sarif tests/fixtures/sarif/single-path.sarif \
  --json
```

If the deployment claims real-scan support, separately record
`codeql version --format=terse`, `java -version`, `javac -version`, and the real
`scan` command, exit code, run ID, `real_codeql=true`, and terminal state. If it
claims a remote-model path, separately record upload authorization, non-secret
credential status, provider, model ID, cost/rate-limit boundaries, and one
explicitly authorized live smoke. Automated tests must never load operator
credentials or invoke the real model.

Finally, EviTriage-QL v0.2.0 is bounded, auditable research infrastructure, not
a production-ready vulnerability classifier. Real builds require external
operating-system isolation, model output requires human review, and no
component automatically dismisses upstream alerts.
