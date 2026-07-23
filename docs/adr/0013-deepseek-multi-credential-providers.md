# ADR 0013: Separate DeepSeek credential providers from the LLM adapter

- **Status:** Accepted
- **Date:** 2026-07-23
- **Decision owners:** EviTriage-QL contributors
- **Applies to:** DeepSeek credential discovery, loading, enrollment, and CLI selection

## Context

ADR 0006 introduced a fixed DeepSeek HTTPS adapter with one-process environment
input and a TPM2/systemd encrypted store. That protected the initial Linux path,
but credential discovery remained inside `DeepSeekLLM`, and TPM2/systemd is not
a dependable WSL option. Adding ad-hoc conditionals to the model adapter,
workflow, or pipeline would couple secret storage to model transport and make
fallback behavior difficult to audit.

Secret Service/Python keyring is not a reliable default for WSL, SSH, CI, and
other headless sessions because a desktop D-Bus session and unlocked keyring
may not exist. Standard pass/GPG works on WSL and native Linux without adding
an arbitrary credential-command feature, provided the operator protects the
GPG private key with a passphrase and understands gpg-agent caching.

## Decision

1. `CredentialProvider` exposes only `provider_id`, `availability()`, and
   `load_secret()`. `EnvironmentCredentialProvider`,
   `SystemdCredentialProvider`, and `PassCredentialProvider` implement it;
   `CredentialResolver` owns all selection and fallback.
2. `triage --credential-provider` accepts `environment`, `systemd-creds`,
   `pass`, or `auto`. Auto order is fixed as environment, systemd-creds, then
   pass. Explicit selection never falls back. Auto skips only an unavailable
   provider; a malformed, unsafe, or selected-but-unloadable provider fails
   closed.
3. Environment input reads only the current process's `DEEPSEEK_API_KEY` and
   has no persistence command. The existing fixed systemd executable,
   repository-external ciphertext path, root ownership, owner-only mode,
   no-follow read, TPM2 name, and in-memory pipe behavior remain unchanged.
4. Pass uses only the validated fixed entry `evitriage/deepseek-api-key`.
   Entries reject absolute paths, empty/`.`/`..` segments, option-leading
   segments, non-ASCII characters, shell metacharacters, and excessive length.
   The discovered absolute `pass` executable must be a non-symlink regular
   executable owned by root or the current user and not group/world writable.
5. Pass commands are fixed argument vectors: `pass show <entry>` for loading
   and `pass insert [--force] --echo <entry>` for enrollment. They use
   `subprocess.run` through an injectable runner, never a shell. Enrollment
   sends the confirmed key only over standard input; loading removes at most
   one expected final newline before applying the shared API-key validation.
6. The pass child environment obtains HOME from the pwd database, fixes
   `PASSWORD_STORE_DIR` to `~/.password-store`, supplies a fixed system PATH
   and locale, and allowlists only bounded GPG/pinentry session variables.
   Pass extensions, proxies, tokens, API keys, and unrelated parent variables
   are absent. Timeout, stdout/stderr acceptance limits, safe exit-code
   reporting, and output-free errors apply to every pass operation.
7. `credentials status --json` checks non-secret availability without
   decrypting or invoking pass/GPG. It reports each provider and auto's final
   selection, but no key, ciphertext, path, GPG identity, command output, or
   recovery material. `credentials set-deepseek --provider pass` retains the
   hidden double prompt and creates no plaintext temporary file.
8. `DeepSeekLLM` receives one already validated in-memory key. It retains only
   fixed official HTTPS request construction and response validation; no
   credential source or fallback logic exists in the adapter, workflow, or
   pipeline. Replay and Fake execution never instantiate the resolver.

## Consequences

WSL users can use pass/GPG for persistence or an environment key for one
process. Native Linux users can continue using TPM2/systemd or select pass.
Passphrase-protected GPG encrypts the password-store entry at rest, but an
unlocked gpg-agent can authorize same-user use until its cache expires. TPM2
and pass protect only API-key storage/handoff; they do not prevent evidence and
source excerpts from being sent after both trusted policies declare
`remote_llm_allowed`.

No backend offers “absolute security.” The key exists briefly in process
memory and in the provider Authorization header. Root, a compromised same-user
runtime, a malicious unlocked-agent client, or provider compromise remain
outside this boundary. Higher-assurance deployments still need a dedicated
account and an OS/cloud secret manager.

## Validation

All command tests use injected fake runners; all DeepSeek tests use simulated
HTTPS. Acceptance covers provider success and absence, environment format
errors, systemd command/ciphertext/permission failures, pass missing
command/entry, GPG failure, timeout, excessive/empty/multiline output, entry
traversal and metacharacters, executable symlink/mode/owner failures, fixed auto
priority, explicit and selected-provider no-fallback behavior, non-disclosure
in status/errors/logs/files, and standard-input-only pass enrollment. No test
may call a real credential tool, read an operator key, or contact DeepSeek.
