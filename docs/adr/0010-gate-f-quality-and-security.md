# ADR 0010: Make Gate F security properties directly selectable and testable

- Status: Accepted
- Date: 2026-07-23
- Gate: F (P0 quality and security)

## Context

Gate E already exceeded the P0 branch-aware coverage threshold and had tests
for the individual path, SARIF, prompt, report, and secret boundaries. Those
tests were distributed across unit and integration modules, however, so there
was no single command proving the Gate F attack-class matrix. The model
workflow also marked repository and SARIF content as inert data but did not
apply the existing secret redactor to every outbound task payload.

Gate F requires explicit evidence for prompt injection, malicious URIs,
path/symlink escape, HTML escaping, shell metacharacters, and secret redaction.
It must preserve exact local evidence for audit and must not weaken Replay
identity, evidence closure, or the deterministic TP/FP/NMC policy.

## Decision

1. The triage workflow redacts credential-shaped keys and text before computing
   the canonical model request hash and before calling any StructuredLLM. The
   DeepSeek adapter independently applies the same transformation as a
   defense-in-depth provider boundary. Original source, SARIF, SliceArtifact,
   and Evidence Registry artifacts remain byte- or content-exact locally.
2. Pytest registers `security`, `golden`, and `e2e` markers. Representative
   Gate F boundary tests carry the `security` marker, and `make security-test`
   runs that subset without coverage accounting. The full `make check` remains
   the only coverage acceptance command and continues to require at least 80%
   branch-aware project coverage.
3. The security selection includes this acceptance matrix:

   | Attack class | Executable evidence |
   | --- | --- |
   | Prompt injection | A source-comment injection is absent from outbound E2E model payloads; a direct evidence injection remains inert data and cannot request tools |
   | Malicious URI | Remote, encoded traversal, UNC, malformed, and symlink-crossing SARIF locations fail closed, including the checked-in hostile Golden fixture |
   | Path/symlink escape | Workspace preparation and SARIF resolution reject escaping symlinks without modifying the outside target |
   | HTML injection | Script-shaped SARIF and prompt-injection text is emitted only as escaped report text |
   | Shell metacharacters | CodeQL's required command string contains one POSIX-quoted Maven argument; execution remains an argv call with `shell=False` |
   | Secret redaction | Logs, workflow payloads, and the direct DeepSeek provider body replace credential-shaped values before their trust boundaries |

4. The integrated security case still runs the ordinary existing-SARIF
   `triage → JUDGED → JSONL/HTML → immutable finalization` path with dynamic
   local Replay entries. It performs no network request and consumes no
   operator credential.

## Consequences

- `make security-test` gives reviewers a fast, named Gate F regression suite;
  `make check` remains authoritative for formatting, lint, strict typing,
  schema consistency, repository secret scanning, the complete test suite, and
  the coverage floor.
- Redaction is deterministic and therefore part of canonical request identity.
  A Replay entry produced from an unsafe unredacted request cannot silently
  match the hardened request.
- Exact local audit artifacts may still contain source-controlled credentials
  or other sensitive source text. They require the same access controls as the
  analyzed repository; outbound redaction and HTML escaping are not a data-loss
  prevention system or authorization to publish reports.
- Pattern redaction cannot identify every unlabeled or novel secret format.
  Remote model use still requires the explicit ProjectSpec/profile upload
  policy and operator review.
