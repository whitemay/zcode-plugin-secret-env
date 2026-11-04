# zcode-plugin-secret-env

ZCode plugin: **secrets travel straight from your private vault into the Bash subprocess environment — the model context only ever sees placeholder / variable names, never values.**

[简体中文](./README.zh-CN.md) | English

## Origin

OpenViking's privacy area is the ideal home for secrets — but when consuming them via the `{{ov_privacy:...}}` placeholder, the MCP side (`privacy_resolve`) resolves the plaintext and it **inevitably flows back into the model context and session records**. However strict the storage side is, that consumption step hands the value to the model. This plugin exists to close that gap: secrets travel from the privacy area straight into the Bash subprocess environment, with the resolution chain completely bypassing the model context.

## How it works

A PreToolUse(Bash) hook scans the command text for **explicit references** (a `{{secret:NAME}}` placeholder or a configured well-known `$VAR`), resolves the true value via a provider into a 0600 temp env file (exported under the name actually referenced in the command, i.e. the well-known original name), and lets the command through with only a source prefix: `. <envfile>; <original command>`. The command text is never rewritten; for implicit env consumers the skill guides the agent to make the reference explicit. Text and value are separated — the audit log only ever sees the env file path.

- **Providers**: `keychain://` (macOS Keychain) / `viking://` (OpenViking privacy layer via `ov privacy resolve`) / `bitwarden://` (Bitwarden CLI)
- **Dump blacklist**: a command is rejected only when it contains both a secret reference and a dump intent (`env` / `printenv` / bare `set` / bare `export`) at command position
- **Single-quote taboo**: a reference inside single quotes would never expand → the whole command is rejected (fail loudly, no magic)
- **Explicit-reference convention**: the hook is a dumb text scanner; tools that consume env vars implicitly (e.g. bare `gh pr list` reading `GH_TOKEN`) are handled by the model per the skill, written explicitly as `GH_TOKEN=$GH_TOKEN gh pr list`

## Install

This project is an npm package plus thin per-host shells. Global command (the real body):

```bash
bun link   # run inside the repo; registers the secret-env command (or npm i -g .)
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
