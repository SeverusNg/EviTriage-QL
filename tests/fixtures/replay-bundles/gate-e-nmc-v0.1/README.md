# Gate E NMC offline Replay bundle

This bundle was authored specifically for the deterministic EviTriage-QL
offline demonstration and is distributed under this repository's Apache-2.0
license. The three JSON response files are synthetic Analyst, Rebuttal, and
Judge fixtures addressed by the canonical request SHA-256 generated from the
checked-in `single-path.sarif`, source snapshot, resulting evidence, prompts,
response schemas, and `replay-v0.1` profile. The manifest separately binds the
raw `example-local` ProjectSpec used by the demo.

The responses were not produced by a real model and are not evidence of model
quality, vulnerability accuracy, or the security of arbitrary source code. The
expected NMC decision deliberately preserves uncertainty and never dismisses
the upstream alert. `bundle-manifest.json` records input/profile identities and
the exact response-file hashes; tests validate it against `bundle.schema.json`
and replay the complete workflow.

Changing a prompt, response schema, trusted profile, SARIF input, or selected
source/evidence changes the canonical request hash and causes an explicit
Replay miss instead of silently accepting a stale response.
