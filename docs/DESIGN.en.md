# Design Notes (English summary)

The full design history (in Chinese, including decision rationale and pitfalls) lives in [DESIGN.md](DESIGN.md). This page condenses the decisions that matter to contributors.

## Core invariant

Secret values never enter the model context. The hook is a **dumb text scanner + value pipe**: it reads only the command text, resolves values into a 0600 temp env file, and prepends a `. <envfile>` source prefix. It never rewrites the command body, never logs values, and there is no post-hoc output scrubbing (the host's PostToolUse cannot rewrite `tool_result` — tried, impossible; do not retry).

## Decisions worth knowing

- **Explicit references only.** The hook triggers on `{{secret:NAME}}` placeholders and configured `$VAR` names appearing verbatim in the command text. Implicit env consumers are the model's job (per the skill: write `GH_TOKEN=$GH_TOKEN gh pr list`). No heuristics about tool semantics.
- **Fail loudly, no magic.** Single-quoted references (which would not expand) reject the whole command rather than silently passing. Unknown placeholder names reject rather than skip. Unresolvable values reject with the provider's real error.
- **Dump blacklist is conjunction-based.** A command is rejected only when it contains both a secret reference **and** dump intent (`env` / `printenv` / bare `set` / bare `export`) at command position. Bare `env` in a separate call is safe by construction: each Bash call is a fresh shell, injected variables do not survive across calls.
- **Config lives outside the plugin cache**, at `~/.config/secret-env/secrets.json` (primary) — the install cache is a snapshot that marketplace refresh overwrites; credential mappings stored there vanished once in practice (first live 401's root cause). The in-plugin file is legacy compatibility only.
- **Well-known names as primary keys** (`GH_TOKEN`, `DATABASE_URL`…): the model writes zero-translation commands, and multiple tools share one credential via aliases. Switching backends means editing `uri` only — names and commands untouched.

## Runtime neutrality

`core.mjs` must run on Node as well as Bun: the ZCode hook runs under Bun, but opencode adapters may run on Node and the DSH host is Electron's Node. Core uses only `node:child_process` — no `Bun.*` globals (this broke all three providers on DSH once; regression rule: test both runtimes after any core change).

## Bitwarden two-level resolution (0.1.1)

`bw get password` requires an unlocked vault (`BW_SESSION`), which the hook process does not have. The session key is itself registered as a secret-env entry (`BW_SESSION → keychain://bw-session`); when resolving any `bitwarden://` item, core looks up that entry by name, resolves it via its own provider, and injects it into the `bw` subprocess env. Guards and lifecycle:

- The trigger is the presence of an entry literally named `BW_SESSION` (hard-coded convention).
- Its `uri` must not itself be `bitwarden://` (unlock-requires-unlock deadlock) — explicitly rejected.
- Every `bw unlock` rotates the key; re-run `security add-generic-password -U -s bw-session -a "$USER" -w` to refresh.
- Items are fetched by name (argv-passed, spaces/CJK safe) and only the login item's password field is read; use item ids to disambiguate duplicates.

## Threat model boundary & keepassxc:// provider (planned, 2026-11-05)

**Threat model: keep tokens out of the agent context — not on-disk absolute security.** secrets.json already holds plaintext tokens by design; evaluate any security decision against "context-leak prevention", not disk-attack hardening. Consequences:

- A KeePassXC master password stored directly in secrets.json is an **accepted design**. The kdbx file itself is AES-encrypted and the password does not travel with it on sync/backup — strictly better than the plaintext-token baseline. No keychain master-key chain, no second-level resolution: the configured value is final, and the read path is simpler than bitwarden's (no session state).
- **`keychain://` keeps its name — its backend becomes the kdbx library.** No `keepassxc://` scheme (final call, 2026-11-05, after two prior revisions): the `keychain://` URI stays as the project's sole secret-store interface, but its resolver switches from the macOS `security` command to kdbxweb reading a `.kdbx` file. Zero config migration — every existing `keychain://svc[/acct]` URI keeps working once its value has been moved into the library. Gains: no external CLI, cross-platform uniformity (Linux/Windows without a system keyring), no macOS command coupling. The `security` path demotes to a transitional fallback (used only when no library is configured). Addressing: `keychain://<svc>` → entry title `<svc>` password field; `keychain://<svc>/<acct>` → secondary field. Library path + master password live in the secrets.json keychain-backend block (plaintext, per the threat-model point above).
- Implementation (planned): kdbxweb (pure JS + WebCrypto, runtime-neutral) with hash-wasm injected as the Argon2 implementation; addressing `keepassxc://<db-path>/<entry>[/<field>]` aligned with the general URI scheme; first version read-only. kdbxweb has not published an npm release since 2021 (repo activity in 2024), but the KDBX format is stable and KeeWeb-backed — maturity over novelty; kdbx-wasm (v0.3, zero dependents) rejected as too immature to bet on.
