# ADR 0004: Gate C-Extra query-positive benchmark readiness

- **Status:** Accepted
- **Date:** 2026-07-22
- **Applies to:** Gate C-Extra between context/evidence and bounded agents

## Context

Gate C can turn a normalized alert into bounded source context and a closed
Evidence Registry, but its positive Golden alert is original synthetic SARIF.
The only recorded real CodeQL scan analyzed `example-local` before Gate C and
produced zero results. That run proves the external-tool path, not that a real
CodeQL path alert can traverse normalization, context extraction, and evidence
registration.

Building Gate D only on synthetic alert input would leave the highest-risk
integration assumption untested. A query-positive microbenchmark is therefore
required before agent output can be treated as evidence about the intended
v0.1 workflow.

## Decision

1. Name the bounded follow-up **Gate C-Extra: Query-Positive Benchmark
   Readiness**. It does not add classification or otherwise enter Gate D.
2. Add one original Apache-2.0 Java case to the existing `path-app` Maven
   fixture. A JDK `Socket` input stream supplies a remote filename that reaches
   `Path.resolve` and a file-read sink without a containment guard.
3. Preserve `PathReader` as the original command-line runner smoke. The new
   case has separate machine-readable ground truth and source identity so the
   two purposes are not conflated.
4. A successful Golden ingest is insufficient for this gate. Acceptance
   requires a real CodeQL `2.26.1` scan using the pinned Java
   `security-extended` suite and the normal `scan` command.
5. The real result must contain `java/path-injection`, a non-empty ordered
   `codeFlows` path referencing the new source file, and then reach
   `CONTEXT_READY` through the shared normalizer and Gate C implementation.
6. At least one matching context slice must be complete, enclose the target
   callable, retain source/sink references, and be reachable from the Evidence
   Registry/source map. All registered artifacts must pass final hash, size,
   and owner-read-only checks.
7. The fixture label is case ground truth for later replay tests. Gate C-Extra
   emits no Claim and no EviTriage TP/FP/NMC decision.

## Non-goals

- completing the remaining CWE-22/CWE-78 TP/FP/NMC fixture matrix;
- adding OWASP Benchmark, Vul4J, CWE-Bench-Java, Git acquisition, or Gradle;
- executing the socket listener, exploitation, or a proof of vulnerability;
- changing CodeQL queries or adding a model pack merely to force an alert;
- adding Fake/Replay LLMs, Analyst/Rebuttal/Judge, or deterministic policy.

## Acceptance evidence

The dated progress log must record exact commands, exits, run ID, tool
versions, SARIF/result/path counts, matching rule and source locations, context
completeness, evidence/claim counts, artifact hashes, and permission audit.
Failure to produce the expected real alert remains an explicit incomplete gate;
synthetic SARIF must not replace it.

## Outcome

Accepted by real run `20260721T201029897333Z-849cee21ce99` on 2026-07-22 with
CodeQL 2.26.1, Java/`javac` 17.0.19, and the pinned Java `security-extended`
suite. The scan produced one `java/path-injection` alert and one complete
eight-step path in the SHA-bound `SocketPathReader.java`. The shared pipeline
reached `CONTEXT_READY` with one complete `readRequestedFile` slice spanning
lines 15–28, four evidence items, and zero claims.

The run registered 25 artifacts; an independent audit matched every recorded
size and SHA-256, and all 27 run files were mode `0400`. The raw SARIF SHA-256
is `9db1cde2c5c1f57c193f3299ce68698bbaeef4437325d8eb40da12a4a38b962e`;
the normalized bundle SHA-256 is
`29e292367affbb0e7608add00fd5e80e18bcf414bd7d8c6aa30a5b88a02f4b16`.

The real output also exposed three boundary defects before acceptance: CodeQL's
undeclared `%SRCROOT%` convention, SARIF's omitted same-line `endLine` default,
and a lexical extractor mistaking a `try` header containing a nested call for a
method. Each now has a narrow implementation fix and regression coverage. No
Golden data was substituted for these failed or rejected attempts.

## Consequences

Gate D begins with at least one real query-positive path flowing through the
same contracts used by offline replay. This still does not establish benchmark
representativeness: the remaining minimum six-case matrix and public datasets
stay explicitly pending.
