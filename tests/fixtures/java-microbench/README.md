# Java microbench fixtures

These projects are original, synthetic EviTriage-QL fixtures distributed under
the repository's Apache-2.0 license. They are deliberately tiny and use only
the Java standard library. Gate A uses them to prove that two target
configurations follow the same validation and workspace paths. Gate B adds a
real CodeQL runner but does not report a smoke success unless the external
tools actually execute.

- `path-app`: direct user-controlled path resolution and file read. Gate
  C-Extra adds a separately identified CWE-22 Socket remote-input case with
  machine-readable ground truth.
- `command-app`: direct user-controlled command execution (planned CWE-78
  direct-TP case).

Each project is a Maven Java 17 project. Its checked-in `mvnw` is the Apache
Maven Wrapper 3.3.4 `only-script` launcher from upstream tag
`maven-wrapper-3.3.4` (commit `524486aff97d0748926a977665d5befb3251ff17`),
licensed under Apache-2.0. The wrapper pins Maven 3.9.9 and verifies the
distribution SHA-256. A controlled bootstrap may populate the wrapper cache;
the configured scan build itself uses Maven `--offline`. Java, Maven cache,
and CodeQL availability are not assumed by offline CI.

`case.schema.json` is the strict shared contract for microbenchmark ground
truth. Case manifests bind labels and expected upstream CodeQL behavior to an
exact source SHA-256; a label in this metadata is not an EviTriage decision.
