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
