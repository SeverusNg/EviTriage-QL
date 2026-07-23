# ADR 0012: Close the v0.1 six-case matrix and bind release evidence

- Status: Accepted
- Date: 2026-07-23
- Gate: G (P0 release-candidate closure)

## Context

Gate E proved one TP, one FP, and one NMC report through the ordinary offline
pipeline, while Gate F separately proved prompt-injection containment. The
top-level v0.1 contract was stricter: it required six compilable cases—CWE-22
TP/FP/NMC, CWE-78 TP/FP, and prompt injection—and required the example report,
its run manifest, and a machine-readable test summary in the release evidence.
Counting distributed unit/security tests as that matrix would have hidden
missing CWE-78 and case-to-report provenance.

Adding cases also changes the source-tree identity, evidence IDs, analysis
identity, and every canonical Replay request hash. Reusing the former
three-alert bundle after changing source would violate Replay's stale-input
failure contract.

## Decision

1. The checked-in `gate-e-demo` Maven project is the exact six-case v0.1
   matrix. Every case has a strict manifest binding its matrix role, CWE,
   source SHA-256, SARIF occurrence, input provenance, and expected label. A
   Java 17 acceptance test compiles all six sources into a temporary directory.
   The project owns a checked-in, Maven-3.9.9/SHA-pinned wrapper and is the
   ProjectSpec source/build root, so real CodeQL does not depend on a sibling
   fixture's wrapper.
2. The default demo uses six-result synthetic Golden SARIF and a strict
   source/SARIF-identity-bound test supplement. It remains explicitly distinct
   from real CodeQL. The new Replay bundle contains eighteen canonical
   request-addressed responses and must produce `TP=3`, `FP=2`, `NMC=1`, with
   every `auto_dismiss=false`.
3. The prompt-injection case embeds an adversarial source comment in a direct
   CWE-22 TP. The comment grants no tool or permission, is absent from the
   minimal evidence-only model payload, and cannot change the final TP label.
4. `make release-artifacts` runs the full branch-aware pytest gate, the named
   security subset, and a fresh six-case demo. Pytest writes strict full and
   security JSON summaries containing the real exit and outcome counts.
5. The release assembler accepts only a finalized, owner-read-only six-case
   run under the managed artifact root. It rehashes every registered artifact,
   strictly parses all report rows and the run manifest, checks the six
   case/CWE/source/result/decision mappings, and stages the JSONL, escaped HTML,
   run manifest, demo summary, case-matrix summary, and test summaries.
6. The release manifest and `SHA256SUMS` register every staged file. Missing,
   failed, stale, mismatched, extra, unsafe, symlinked, or tampered inputs fail
   closed. No tag, signature, hosted run, second-host result, or publication is
   created by these commands.

## Consequences

- The two local P0 blockers recorded by the first Gate G tranche are closed:
  the six-case pipeline is executable and the reviewed example/test evidence is
  part of the same independently verifiable checksum closure as the package.
- The matrix is deterministic pipeline/policy evidence, not an accuracy study.
  Golden SARIF, supplements, and Replay responses are synthetic; only the
  separately recorded four-result smoke is real CodeQL evidence. Its result
  count is not required to equal the six-case synthetic acceptance matrix.
- Changing any case source, SARIF, supplement, prompt, response schema, profile,
  or evidence changes the corresponding identities and requires an intentional
  Replay/evidence rebuild.
- A release tag and third-party/second-host replay remain external acceptance
  actions. Their absence must remain visible even when local candidate checks
  pass.
