# v0.1 six-case offline Replay bundle

This Apache-2.0 synthetic bundle drives all six checked-in v0.1 Java cases
through the ordinary Replay adapter, Agent schemas, evidence closure,
deterministic policy, and report renderer. The eighteen files are addressed by
canonical request SHA-256: Analyst, Rebuttal, and Judge for each exact SARIF
result occurrence.

The matrix covers CWE-22 TP/FP/NMC, CWE-78 TP/FP, and a prompt-injection safety
case whose adversarial source comment does not change its expected TP label. TP
depends on explicit synthetic source-control and sink-semantics observations
plus the preserved Golden data-flow observation. FP depends on a decisive
synthetic guard observation and a Rebuttal claim. NMC deliberately leaves the
`PathPolicy` implementation unknown. These are fixture expectations, not real
CodeQL or model outputs, calibrated results, or security conclusions about
arbitrary code. No result authorizes automatic alert dismissal.
