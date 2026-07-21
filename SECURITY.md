# Security policy

## Supported versions

EviTriage-QL is pre-release research software. Until a tagged release exists,
only the latest revision on the primary development branch receives security
fixes. The Gate B input pipeline is a research foundation and must not be treated as a
production vulnerability-classification service.

## Reporting a vulnerability

Do not include exploit details, secrets, private source code, or information
about an undisclosed third-party vulnerability in a public issue. Use the
repository host's private security-advisory channel, or another private channel
explicitly published by the maintainers. If no private channel is available,
ask the maintainers publicly for a private contact without disclosing technical
details.

Include, when safe:

- the affected commit or release and operating system;
- a minimal reproduction using synthetic data;
- the expected and observed security boundary;
- impact and any known preconditions;
- suggested mitigation, if available.

Maintainers will acknowledge and coordinate based on availability; this
research project does not promise a fixed response SLA. Please allow a fix and
coordinated disclosure before publishing details.

## Relevant trust boundaries

The operator chooses a ProjectSpec, but its contents, target source trees,
comments, build files, SARIF documents, and future model output cross untrusted
boundaries. Security-relevant reports include, but are not limited to:

- path traversal or symlink escape from managed roots;
- modification of an original target source tree;
- shell execution or command injection through configuration/repository text;
- secret exposure in logs, diagnostics, manifests, databases, or reports;
- accepting unknown or privilege-changing ProjectSpec fields;
- unsafe SQLite/database URL handling;
- falsely reporting a CodeQL scan or evidence-backed decision;
- a future model or repository changing tool permissions or workflow goals.

`ingest-sarif` never executes the target. `scan` can execute only the explicitly
configured, checked-in Maven Wrapper through the constrained CodeQL runner, but
Gate B does not yet provide a complete OS filesystem/network/resource sandbox.
Run real scans only for trusted fixtures or inside a disposable external
sandbox without valuable credentials.

## Responsible use

Use this software only on systems and code for which you have authorization.
The project does not automatically dismiss alerts, generate exploits, or
authorize offensive testing. Follow applicable law, target-project disclosure
policies, dataset licenses, and CodeQL's own license terms.
