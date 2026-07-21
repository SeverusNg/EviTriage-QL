# path-app

- Provenance: original synthetic EviTriage-QL fixture, Apache-2.0.
- Build: `./mvnw --offline -q -DskipTests package` with JDK 17 and the pinned
  Maven 3.9.9 distribution already present in the wrapper cache.
- Intended later case: CWE-22 direct TP.
- Source fact: `args[1]` reaches `Path.resolve` and then `Files.readString`.
- Guard/sanitizer fact: there is no canonical-path containment check.
- Expected later workflow output: `TP`, once Gate B-D provide real normalized
  path evidence and deterministic decision policy.

Gate C-Extra adds `SocketPathReader.readRequestedFile`: a Socket-backed
`BufferedReader.readLine` reaches `Path.resolve` and `Files.readString` without
a containment check. Its strict ground-truth manifest is
`cases/cwe22-socket-direct-tp.json`. The case is compiled and statically
analyzed only; tests do not open a listener, read arbitrary files, or execute a
proof of vulnerability. The manifest's `TP` is curated case metadata for later
replay, not a Gate C classification output.

Gate B can scan this fixture only when the pinned JDK and CodeQL tools are
present. Golden SARIF tests do not claim that a real CodeQL query has run or
that the expected later triage label has been produced. Gate C-Extra real run
`20260721T201029897333Z-849cee21ce99` used CodeQL 2.26.1 and recorded one
`java/path-injection` result with a complete eight-step path through this exact
SHA-bound source; it still emitted no EviTriage claim or decision.
