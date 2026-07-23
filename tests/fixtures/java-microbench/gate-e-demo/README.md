# v0.1 six-case Java matrix

This original Apache-2.0 Maven project contains the six frozen v0.1 release
cases: CWE-22 direct TP, canonical-path-check FP, unknown-wrapper NMC; CWE-78
direct TP and allowlist FP; and a prompt-injection comment embedded in a
CWE-22 direct-TP case. The injection remains inert source data, cannot grant
tools or permissions, and does not change the expected TP decision.

The project is self-contained: its checked-in Maven Wrapper pins Maven 3.9.9
and its exact Apache distribution SHA-256. `configs/projects/gate-e-demo.yaml`
uses this directory as both the source and build root, so a real CodeQL scan
does not depend on a wrapper or build file in a sibling fixture.

The offline demo consumes checked-in synthetic Golden SARIF and test
supplements. It does not present those artifacts as real CodeQL or model
output, independently verified ground truth, or an accuracy benchmark. The
separate real-CodeQL smoke remains query/pipeline evidence.
