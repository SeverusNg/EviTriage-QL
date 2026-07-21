# path-app

- Provenance: original synthetic EviTriage-QL fixture, Apache-2.0.
- Build: `./mvnw --offline -q -DskipTests package` with JDK 17 and the pinned
  Maven 3.9.9 distribution already present in the wrapper cache.
- Intended later case: CWE-22 direct TP.
- Source fact: `args[1]` reaches `Path.resolve` and then `Files.readString`.
- Guard/sanitizer fact: there is no canonical-path containment check.
- Expected later workflow output: `TP`, once Gate B-D provide real normalized
  path evidence and deterministic decision policy.

Gate B can scan this fixture only when the pinned JDK and CodeQL tools are
present. Golden SARIF tests do not claim that a real CodeQL query has run or
that the expected later triage label has been produced.
