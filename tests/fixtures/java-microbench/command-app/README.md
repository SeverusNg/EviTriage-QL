# command-app

- Provenance: original synthetic EviTriage-QL fixture, Apache-2.0.
- Build: `mvn -q -DskipTests package` with JDK 17.
- Intended later case: CWE-78 direct TP.
- Source fact: the first command-line argument reaches a `ProcessBuilder`
  invocation through `sh -c`.
- Guard/sanitizer fact: there is no command allowlist.
- Expected later workflow output: `TP`, once Gate B-D provide real normalized
  path evidence and deterministic decision policy.

Gate A only validates and snapshots this project. It does not claim that a
CodeQL query has run or that the expected label has been produced.
