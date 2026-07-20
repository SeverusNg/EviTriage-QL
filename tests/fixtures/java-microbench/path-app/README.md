# path-app

- Provenance: original synthetic EviTriage-QL fixture, Apache-2.0.
- Build: `mvn -q -DskipTests package` with JDK 17.
- Intended later case: CWE-22 direct TP.
- Source fact: `args[1]` reaches `Path.resolve` and then `Files.readString`.
- Guard/sanitizer fact: there is no canonical-path containment check.
- Expected later workflow output: `TP`, once Gate B-D provide real normalized
  path evidence and deterministic decision policy.

Gate A only validates and snapshots this project. It does not claim that a
CodeQL query has run or that the expected label has been produced.
