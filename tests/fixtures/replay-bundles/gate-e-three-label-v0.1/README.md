# Gate E TP/FP/NMC offline Replay bundle

This Apache-2.0 synthetic bundle drives the three checked-in Gate E Java cases
through the ordinary Replay adapter, Agent schemas, evidence closure,
deterministic policy, and report renderer. The nine files are addressed by
canonical request SHA-256: Analyst, Rebuttal, and Judge for each exact SARIF
result occurrence.

TP depends on explicit synthetic source-control and sink-semantics observations
plus the preserved CodeQL data-flow observation. FP depends on a decisive
synthetic containment-guard observation and a Rebuttal claim. NMC deliberately
leaves the `PathPolicy` implementation unknown. These are fixture expectations,
not real-model outputs, calibrated results, or security conclusions about
arbitrary code. No result authorizes automatic alert dismissal.
