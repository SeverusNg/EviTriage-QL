# Synthetic SARIF fixtures

These SARIF 2.1.0 documents were authored specifically for EviTriage-QL's
offline tests. They are not copied from a third-party repository and must not
be represented as output from a real CodeQL invocation. They are distributed
under this repository's Apache-2.0 license.

`single-path.sarif` is the primary Golden input. Its path, coordinates,
snippet, and declared SHA-256 correspond to the checked-in
`java-microbench/path-app` `PathReader.java` source file. The remaining files
are deliberately synthetic structural or adversarial variants used to test:

- multiple, duplicate, and absent code-flow paths;
- multiple SARIF runs and duplicate results;
- both allowed `columnKind` values, missing snippets, and Windows URI bases;
- invalid regions, traversal/remote URIs, and other unsafe input.

Tests preserve each input's exact bytes and identify normalized results with
the raw SARIF SHA-256 plus `(run_index, result_index)`. A real CodeQL smoke run
remains a separate environment-dependent acceptance check.
