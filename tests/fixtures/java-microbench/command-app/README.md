# command-app

- Provenance: original synthetic EviTriage-QL fixture, Apache-2.0.
- Build: `./mvnw --offline -q -DskipTests package` with JDK 17 and the pinned
  Maven 3.9.9 distribution already present in the wrapper cache.
- Intended later case: CWE-78 direct TP.
- Source fact: the first command-line argument reaches a `ProcessBuilder`
  invocation through `sh -c`.
- Guard/sanitizer fact: there is no command allowlist.
- Expected later workflow output: `TP`, once Gate B-D provide real normalized
  path evidence and deterministic decision policy.

Gate B can scan this fixture only when the pinned JDK and CodeQL tools are
present. Golden SARIF tests do not claim that a real CodeQL query has run or
that the expected later triage label has been produced.
