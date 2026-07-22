# Gate E three-label Java fixture

These original Apache-2.0 micro-cases exist only to exercise the auditable
offline report path. `DirectPathCase` is paired with explicit synthetic
source/sink evidence, `CanonicalPathCase` is paired with a decisive synthetic
containment-check observation, and `UnknownWrapperCase` deliberately leaves an
unresolved policy wrapper. The labels are fixture expectations, not claims
about arbitrary code or model quality.

The Gate E demo consumes checked-in Golden SARIF. It does not present that
SARIF as output from a real CodeQL execution.
