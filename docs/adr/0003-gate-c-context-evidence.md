# ADR 0003: Bounded context and closed evidence references

- **Status:** Accepted
- **Date:** 2026-07-21
- **Applies to:** Gate C context/evidence

## Context

Gate B produces one occurrence-preserving `AlertBundle` for both real scan and
existing-SARIF input. Gate C must make source, sink, and ordered path context
locatable without reparsing SARIF permissively, reading the whole repository,
or turning comments and identifier names into security facts. It must also give
later agents a reference boundary where unknown evidence IDs fail closed.

The v0.1 prompt requires working `fixed_window` and `path_function_slice`
policies while explicitly deferring adaptive context, caller/callee expansion,
configuration/test summaries, and semantic verification. Source may be absent
or inconsistent with operator-supplied SARIF, so incompleteness must remain
observable rather than guessed away.

SARIF 2.1.0 section 3.14.27 requires a text-producing non-empty run to declare
`columnKind` and defines the two supported measurements. Section 3.30 defines
text-region columns in that run-level unit. Gate C therefore cannot treat host-
language string indexes as interchangeable with SARIF columns. See the
[OASIS SARIF 2.1.0 standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

## Decision

1. Both input branches continue through the same
   `NORMALIZED → CONTEXT_READY` implementation. There is no Golden-specific
   context or evidence path.
2. One strict, canonical `SliceArtifact` is created for every normalized result
   occurrence, including pathless and partial alerts. It preserves the raw
   `(SARIF SHA-256, run index, result index)` reference.
3. Level 0 copies only normalized rule/message/primary/additional/related/path
   facts. Level 1 reads only explicitly referenced snapshot paths using no-
   follow, bounded regular-file access; it checks UTF-8 content, digest, and
   coordinates before selection. Column bounds use the normalized run's SARIF
   `utf16CodeUnits` or `unicodeCodePoints` measurement rather than a host-
   language indexing assumption.
   A leading UTF-8 BOM remains part of the artifact hash but is not counted as
   source text or a column, matching SARIF text-region rules.
4. `path_function_slice` uses a deterministic Java lexical callable extractor
   that ignores comments and literals. If it cannot identify a callable, it
   retains a bounded five-line window and records
   `function_boundary_unresolved`. `fixed_window` is separately executable.
   `adaptive_slice` returns `FEATURE_NOT_AVAILABLE`.
5. Context is limited to 1 MiB per source file and 24,000 estimated tokens per
   alert. The estimate is UTF-8 bytes divided by four. Missing, binary,
   oversized, changed, invalid-coordinate, and over-budget input produces an
   explicit partial artifact with omission reasons.
6. The Evidence Registry allowlists registered artifact hashes. Every evidence
   item binds to an alert fingerprint and exact raw result reference;
   relationships and Claim evidence IDs must resolve inside the registry.
7. CodeQL paths are supporting observations, not feasibility or exploitability
   proof. Repository excerpts and lexical guard/sanitizer matches are neutral.
   Gate C generates no claims or labels.
8. JSON and Graphviz exports are deterministic. The source-map HTML escapes all
   untrusted content, contains no script, and is navigation rather than a
   decision report.
9. Context/evidence files use the existing run-confined journal, SHA-256
   records, pre-finalization revalidation, owner-read-only final permissions,
   and append-only event history.

## Alternatives considered

### Use only fixed line windows

Rejected as the default because it routinely cuts off method signatures and
closing control flow. It remains available as a real bounded policy and as an
explicitly recorded fallback.

### Add a Java parser/compiler dependency immediately

Deferred. It would improve semantic boundaries, but toolchain and language
coverage risk would exceed the Gate C vertical slice. The lexical limitation is
represented in artifact completeness and documentation rather than hidden.

### Treat missing context as a successful complete slice

Rejected because it would erase the difference between verified source and an
operator-selected snapshot that lacks the referenced file. Partial artifacts
preserve Level 0 facts and the exact reason Level 1 is unavailable.

### Let later agents cite arbitrary paths or prose

Rejected. A closed registry is the core evidence contract: unknown artifact,
relationship, or Claim evidence references invalidate the structured object.

## Consequences

Benefits:

- source/sink/path locations can be replayed from hashed, bounded artifacts;
- scan and existing-SARIF provenance stay branch-independent downstream;
- missing context and extractor precision loss remain machine-readable;
- Gate D receives a strict reference gate before any model output is trusted;
- no Gate C output can dismiss or classify an upstream alert.

Costs and constraints:

- lexical Java extraction is not AST/CFG evidence and can fall back to windows;
- the token estimate is provider-independent but approximate;
- Gate C produces evidence, not claims, labels, or decision reports;
- source-map HTML must not be confused with the later Gate E report.
