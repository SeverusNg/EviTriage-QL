# Java microbench fixtures

These projects are original, synthetic EviTriage-QL fixtures distributed under
the repository's Apache-2.0 license. They are deliberately tiny and use only
the Java standard library. Gate A uses them to prove that two target
configurations follow the same validation and workspace paths; it does not run
CodeQL or emit vulnerability labels.

- `path-app`: direct user-controlled path resolution and file read (planned
  CWE-22 direct-TP case).
- `command-app`: direct user-controlled command execution (planned CWE-78
  direct-TP case).

Each project is a Maven Java 17 project and can be compiled in an environment
with Maven/JDK 17 using `mvn -q -DskipTests package`. Maven/JDK availability is
not assumed by Gate A CI.
