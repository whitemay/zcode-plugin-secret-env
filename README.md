# zcode-plugin-secret-env

**A local credential manager for AI coding agents**: secrets travel straight from your private vault into the Bash subprocess environment — the model context only ever sees placeholder / variable names, never values.

> **For npm reviewers / security scanners**: this is an *open-source developer tool in the same category as doppler / bitwarden-cli / 1password-cli*. It manages the user's own credentials on their own machine: it calls local vault CLIs (`security` for macOS Keychain, `bw`, `op`, `ov`) and injects resolved values into a subprocess environment via a temp 0600 file. It sends nothing anywhere, has no network listeners, and every external call is to the user's own configured vault backend. Source of truth: `core.mjs` (~400 lines), fully readable.

[简体中文](./README.zh-CN.md) | English

## ⚠️ Version security notice

**All released versions up to and including the current 0.1.x are NOT recommended if your threat model includes on-disk exposure** (shared machines, synced/backed-up config directories, other local software reading your files). Their design stores resolved credential mappings in a **plaintext JSON file** (`~/.config/secret-env/secrets.json`, 0600) and relies on optional system keyring CLIs — protection covers the *agent context* only (values never enter the model, the command text, or the audit log), **not** the disk.

- What 0.1.x does protect: token values never appear in model context, command text, session records, or the hook audit trail.
- What 0.1.x does **not** protect: the mapping file itself is plaintext; anyone who can read it gets every configured token. Values resolvable via `keychain://` are stored in the OS keyring and are safer, but `bitwarden://`/`viking://`/`onepassword://` mappings still disclose their *target URIs* (not values) in the same file.
- The fix is planned (not yet released): the `keychain://` backend switches to an encrypted `.kdbx` vault (KeePassXC-compatible), so mappings and high-value values live in an AES-encrypted vault while URIs stay unchanged. Versions after that release will be suitable for the stronger threat model.

If plaintext-on-disk is acceptable in your environment, current versions are fine for their stated purpose.

## Origin

OpenViking's privacy area is the ideal home for secrets — but when consuming them via the `{{ov_privacy:...}}` placeholder, the MCP side (`privacy_resolve`) resolves the plaintext and it **inevitably flows back into the model context and session records**. However strict the storage side is, that consumption step hands the value to the model. This plugin exists to close that gap: secrets travel from the privacy area straight into the Bash subprocess environment, with the resolution chain completely bypassing the model context.

## How it works

A PreToolUse(Bash) hook scans the command text for **explicit references** (a `{{secret:NAME}}` placeholder or a configured well-known `$VAR`), resolves the true value via a provider into a 0600 temp env file (exported under the name actually referenced in the command, i.e. the well-known original name), and lets the command through with only a source prefix: `. <envfile>; <original command>`. The command text is never rewritten; for implicit env consumers the skill guides the agent to make the reference explicit. Text and value are separated — the audit log only ever sees the env file path.

- **Providers**: `keychain://` (macOS Keychain) / `viking://` (OpenViking privacy layer via `ov privacy resolve`) / `bitwarden://` (Bitwarden CLI) / `onepassword://` (1Password CLI)
- **Dump blacklist**: a command is rejected only when it contains both a secret reference and a dump intent (`env` / `printenv` / bare `set` / bare `export`) at command position
- **Single-quote taboo**: a reference inside single quotes would never expand → the whole command is rejected (fail loudly, no magic)
- **Explicit-reference convention**: the hook is a dumb text scanner; tools that consume env vars implicitly (e.g. bare `gh pr list` reading `' + 'GH_TOKEN' + '`) are handled by the model per the skill, written explicitly as `' + 'GH_TOKEN' + '=$' + 'GH_TOKEN' + ' gh pr list`

## Working with other agent harnesses

Any tool that reads credentials from environment variables is supported with **zero integration code** — write the well-known variable explicitly and the hook injects it:

```bash
DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY pi        # pi coding agent (reads the DeepSeek key)
OPENAI_API_KEY=$OPENAI_API_KEY my-cli        # same pattern for any env-var-driven tool
```

This forms a two-tier integration spectrum:

| Tier | Mechanism | Cost | Covers |
|---|---|---|---|
| Env-var injection | explicit `$`VAR` reference in the command → hook injects into the subprocess env | zero code | every harness whose credentials come from env vars (the common convention) |
| Interception adapters | per-host rewrite of tool calls (ZCode PreToolUse hook / opencode plugin / DSH cordis wrapper) | one adapter per host | hosts where the *agent's own Bash commands* need injection |

The two compose: an agent running inside ZCode can invoke another harness as a subprocess, and credentials flow harness-to-harness without ever entering the model context.

## Install

This project is an npm package plus thin per-host shells. Global command (the real body):

```bash
bun link   # run inside the repo; registers both the secret-env and senv commands (same CLI, short alias) (or npm i -g .)
npm i -g @foperate/secret-env   # or install the published package
```

ZCode shell: Plugin Marketplace → Add Marketplace, paste this repo root → Install **secret-env** (hooks.json points at the global command).

opencode shell: copy the adapter into the plugins directory (V2 API, `tool.execute.before` rewrites `output.args.command` with the same source prefix):

```bash
cp adapters/opencode.ts ~/.config/opencode/plugins/secret-env.ts   # or project .opencode/plugins/
```

DSH (DeepSeek Harness) shell: link the cordis plugin package and insert a row in the profile's user patch layer (a verified `tools/execute` waterfall rewrite of `exec.arguments.command` — see probe record in docs):

```bash
mkdir -p ~/.dsh/profiles/node_modules/@local
ln -sfn "$PWD/adapters/dsh/secret-env" ~/.dsh/profiles/node_modules/@local/secret-env
# then add to ~/.dsh/profiles/<profile>/cordis.patch.yml:
# - insert:
#     - id: secret-env
#       name: '@local/secret-env'
#       config: {}
# restart DSH to load the new module
```

Vault a credential (run in your own terminal, hidden input, the value never touches the conversation):

```bash
secret-env add GH_TOKEN --provider keychain --desc 'GitHub token' --alias GITHUB_TOKEN
secret-env list
```

## Configuration

`~/.config/secret-env/secrets.json` (700 dir / 600 file; maintained by `secret-env add`, or hand-written):

```json
{
  "GH_TOKEN": { "uri": "viking://credential/github-token/token" },
  "OPENAI_API_KEY": { "uri": "keychain://zcode-openai", "aliases": ["OPENAI_KEY"] }
}
```

See [secret-env/secrets.example.json](./secret-env/secrets.example.json) for the template. With an empty config the hook is a pure bypass.

## Known limitations (honest disclosure)

- **No egress sanitization**: ZCode PostToolUse output has no tool_result rewrite capability (verified against harness source), so `echo $GH_TOKEN` reflow has no automatic defense — forbidden by the skill only
- **Depends on skill guidance quality**: without an explicit reference in the command, injection does not happen — by design, fail loudly
- The `viking://` provider requires the `ov` CLI (≥0.5.1) and a local OpenViking service

Design history and mechanism verification records: [docs/DESIGN.md](./docs/DESIGN.md) (Chinese).
