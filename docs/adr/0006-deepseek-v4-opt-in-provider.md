# ADR 0006: Make DeepSeek V4 an explicit remote-data opt-in

- **Status:** Accepted
- **Date:** 2026-07-22
- **Decision owners:** EviTriage-QL contributors
- **Applies to:** Optional post-Gate-D real-provider execution

## Context

Gate D deliberately established Fake/Replay before a network provider. A user
has now explicitly requested DeepSeek V4 integration and strong protection
against Git credential leakage. A remote model necessarily receives selected
evidence and source excerpts, so provider configuration cannot silently reuse
an `offline_only` project or accept an arbitrary endpoint from target-controlled
configuration.

DeepSeek's official API documentation currently identifies
`deepseek-v4-pro` and `deepseek-v4-flash`, with an OpenAI-compatible Chat
Completions endpoint at `https://api.deepseek.com/chat/completions` and Bearer
authentication.

## Decision

1. `DeepSeekLLM` supports exactly `deepseek-v4-pro` and
   `deepseek-v4-flash`. Host, port, path, timeout, JSON mode, and disabled
   thinking are adapter constants, not ProjectSpec fields or environment
   overrides. Redirects and tool calls are not followed or enabled.
2. The API key comes from either one-process `DEEPSEEK_API_KEY` input or a fixed
   repository-external TPM2/systemd encrypted credential. Enrollment reads a
   hidden prompt and pipes plaintext directly to `systemd-creds`; only the
   owner-private ciphertext reaches disk. Each run decrypts through an
   in-memory pipe. The key is used only to construct the HTTPS Authorization
   header and never enters the canonical user payload, prompt, manifest,
   artifact, or error details. Non-success provider bodies are discarded
   without logging.
3. Network execution requires two independent matching declarations:
   `LLMProfile.data_policy=remote_llm_allowed` and
   `ProjectSpec.security.source_upload_policy=remote_llm_allowed`. Any mismatch
   finalizes the run as `POLICY_REJECTED` before SARIF evidence is sent.
4. The fixed Analyst/Rebuttal/Judge prompts send one JSON user message containing
   the strict response schema and bounded evidence payload. The adapter requests
   JSON Output; returned content still passes the same duplicate-key,
   non-finite-number, Pydantic, evidence-reference, repair, and deterministic
   policy gates as Replay.
5. The recommended persistent handoff is `evitriage credentials set-deepseek`
   on a Linux host whose operator can access TPM2. The encrypted blob has a
   fixed name/path, strict owner/mode/link checks, and an embedded purpose name.
   A hidden `read -s` inside a one-command subshell remains the ephemeral
   fallback. Chat, command arguments, YAML, `.env`, scripts, fixtures, and Git
   are prohibited key transports; a chat-exposed key must be revoked first.
6. `make check` scans tracked and non-ignored untracked files for selected
   credential patterns without printing matched values. `.env`, private key,
   model-response, workspace, and artifact paths remain ignored.

## Consequences

One DeepSeek credential can serve all three roles; normal execution makes three
requests per alert and bounded schema repair can raise that to six. This can
incur external cost and transfers the evidence payload to DeepSeek. The
dedicated example ProjectSpec makes that transfer visible and leaves existing
offline ProjectSpecs unchanged.

The endpoint restriction prevents a project or environment variable from
redirecting credentials to another host. TLS protects transport to the
authenticated host, but it does not hide source from the provider or eliminate
provider retention, account, billing, jurisdiction, DNS/runtime-compromise, or
same-user process-inspection risks.

No system can offer absolute API-key safety while using the key. TPM2 prevents
the encrypted at-rest blob from being decrypted away from the enrolled machine,
but the authorized runtime still receives plaintext in memory. The current
controls minimize persistence and accidental Git disclosure; higher-assurance
deployments should use a dedicated execution account and OS/cloud secret
manager, then rotate or revoke the provider key after suspected exposure.

## Validation

Tests must use a simulated HTTPS connection and no real credential. Acceptance
requires exact host/path/body assertions, JSON schema delivery, successful
three-role CLI integration, missing-key failure, discarded error-body checks,
offline-project rejection, strict profile validation, repository secret-scan
success, generated schema checks, and the full repository test suite. A live
provider success may be reported only after the operator supplies a key through
the documented environment path and the actual command/exit code is recorded.

On 2026-07-23, the operator-authorized TPM2 path satisfied that additional
live-smoke condition. The bounded triage command exited 0 after three accepted
role calls and ignored run `20260722T174132749958Z-8fce5d0ab3f9` reached
`JUDGED` with `NMC` and `auto_dismiss=false`. This does not change the rule that
automated tests use simulations, nor does it establish model quality, billing,
rate-limit behavior, or general provider availability.
