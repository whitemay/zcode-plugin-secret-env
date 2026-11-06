# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/); versions are pre-1.0, so minor bumps carry new features.

## [Unreleased]

## [0.3.2] - 2026-11-06

Release scope: **plugin distribution only**. No user-facing behavior change — the DSH and opencode adapters are repackaged as thin clients that talk to the globally installed CLI over the host protocol, and the skills are distributed by the host packages instead of the main package. The main package and every plugin package share this version number.

### Added

- **Host protocol v1** — `secret-env info | inject | store`: one line of JSON on stdin, one line on stdout; exit code 0 = ok, 2 = refusal (`error`/`code` in JSON), 3 = protocol mismatch. Values only ever travel over stdin and are never echoed.
- **`@foperate/secret-env-dsh`** — the DSH bundle is now its own zero-dependency npm package (`adapters/dsh`, shipped with `dsh.bundle.patch`, locale, icon and its own skill copy). Installing DSH takes two packages: the global CLI plus this bundle.
- New regression suites: `tests/cli-protocol.mjs`, `tests/dsh-protocol.mjs`, `tests/rules-sync.mjs`, `tests/dsh-package.mjs`.

### Changed

- **DSH adapter is a protocol client**: it no longer imports `core.mjs`/`cli.mjs`/`entry.mjs`. `tools/execute` hands bash to `secret-env inject` (which now also owns the command-text guard), `add_secret` uses `store` (validate → collect value → store), and the synchronous guards keep only what cannot wait for a subprocess: file tools and the non-injecting `pwsh`/`terminal_send` channels. Snapshots come from `info`; protocol mismatch or a missing CLI fails plugin startup (fail closed).
- **opencode adapter** no longer registers `senv-mcp` (in-session registration on opencode falls back to the `senv add` terminal path) and shells out to `secret-env inject` for interception instead of importing the main package. Note: opencode still has no file read/write guard.
- **Skills are shipped by the host packages**: `skills/secret-env/` remains in the repo only as the byte-for-byte sync source and is no longer part of the main package's `files`; ZCode, opencode and DSH each ship their own copy (four copies total, enforced by `tests/skill-sync.mjs`).
- Main package: no `dsh.bundle` declaration, no `./dsh` export, `files` no longer carries `adapters/dsh/` or `skills/`.
- DSH system prompt / guard rule data come from the CLI snapshot, so `bun link` in this repo updates CLI behavior immediately; a bundle upgrade still needs a DSH restart.

## [0.3.1] - 2026-11-06

### Added

- **opencode plugin split into its own package** `@foperate/secret-env-opencode` (workspace member at `adapters/opencode`, npm workspace `workspace:*` dependency on the main package). The host config `plugin` array references the package name `"@foperate/secret-env-opencode"`. opencode rejects `@scope/pkg/subpath` specs: `npa` parses the subpath, the spec stops classifying as a registry version/range/tag, and opencode tries an npm install of a bogus path and fails with `NpmInstallFailedError` — so the previous `"@foperate/secret-env/opencode"` form could never load. Users install both packages globally (`bun install -g @foperate/secret-env @foperate/secret-env-opencode`): a transitively installed dependency's `bin` entries are not linked into `~/.bun/bin` / `~/.npm/bin`.
- The adapter now registers the MCP server and the skill: `senv-mcp` via `ctx.mcp.transform`, the skill via `ctx.skill.transform` reading `adapters/zcode/skills/secret-env/SKILL.md` from the main package (the host does not auto-discover a plugin package's own `skills/` directory). Skill gains `references/opencode.md`.

### Changed

- **Adapters unified under `adapters/<host>/`**: the ZCode install unit moved from `secret-env/` to `adapters/zcode/`, sitting alongside `adapters/opencode/` and `adapters/dsh/`. The ZCode entry in `marketplace.json` switches from a relative path (`"./secret-env"`) to a `git-subdir` source pinned to a release tag, so the marketplace pulls only that subdirectory from GitHub. Repo-internal paths (tests, skill symlink instructions, `files`) follow the move; the runtime config path `~/.config/secret-env/` is unchanged.
- Adapter cross-package references resolve through `createRequire` absolute paths instead of relative paths and `PATH`: core and `senv-mcp` (`require.resolve`) and the skill asset (anchored at the main package root). The MCP command is a single absolute path to the resolved `mcp.mjs` rather than a bare `senv-mcp` — and not `[process.execPath, <mcp.mjs>]`, because opencode treats the first argument of a multi-element command as a `cwd` and fails with `ENOTDIR`. It works when the main package's `bin` is not on `PATH`. The `$HOME/github/...` fallback import is gone — a resolution failure now surfaces as the real error.
- The main package no longer exports `"./opencode"`; `files` narrows `adapters/` to `adapters/dsh/` so the workspace member is not double-shipped.
- Adapter regression tests moved from `adapters/tests/` to top-level `tests/` (`npm files` array negation never worked — tests were silently shipped in the package).

## [0.3.0] - 2026-11-06

### Added

- **In-session credential registration** (two-problem design): metadata (name/aliases/description/provider) is finalized by the agent via the host's native Q&A; the secret value is collected per host through an isolated channel — ZCode via MCP elicitation (`senv-mcp`), DSH via the adapter's `add_secret` tool (host question card), every other host via a complete `senv add` terminal command. The value never enters the model context on any channel.
- **DSH adapter**: synchronous guards over six tool channels (read/read_image/write/edit/apply_patch/bash/terminal_send) protecting config and vault files, an `add_secret` tool, and a configured-entries section injected into the system prompt.
- **`senv-mcp` / `add_secret` (ZCode)**: one-screen value card — the host's forced free-input line takes the secret, an explicit "enter manually via command line" option switches to the terminal channel; non-accept results always carry a ready-made `senv add` command (declined = user chose the terminal path, not a failure).
- **`entry.mjs`**: host-agnostic shared module for entry options and command construction (CLI / MCP / DSH).
- Skill restructured into a host-branching layout: `SKILL.md` (universal conventions + registration flow + routing) with `references/` (zcode.md / dsh.md / providers.md).

### Changed

- `cli.mjs` entry detection compares realpaths, fixing silent exits when invoked through shim symlinks (bun link / global installs).
- README rewritten around capabilities: the MCP section is now "in-session registration" — MCP is documented as the ZCode channel, not a project-level concept.

## [0.2.0] - 2026-11-06

### Added

- KeePassXC-compatible encrypted `.kdbx` vault as the secret store (AES-256, kdbxweb + hash-wasm); `keychain://` URIs keep their name with the engine swapped — zero config migration. Versions ≤ 0.1.x (plaintext JSON storage) are deprecated.
- File guards: the hook rejects agent access to the config file and vault (Bash/Write/Edit/Read).
- **`srun`** — injection outside agent hosts: bare terminals, scripts, cron, systemd units (`srun NAME -- cmd`, `--all` for the full set); named entries resolved through the same providers, values appear nowhere.
- Provider write-side autonomy: `secret-env add` writes through every provider itself (Bitwarden encodedJson via stdin, OpenViking via 0600 values-file, keychain dump-count disambiguation); cross-provider chains (BW_SESSION stored in another provider) resolve transparently.
- Real-verified providers: KeePassXC vault (primary), OpenViking, Bitwarden CLI; 1Password implemented (pending on-device verification).

### Changed

- `keychain` configuration simplified: only the vault master password is configured; backend and vault path follow conventions and are no longer configurable.
- Published as the npm package `@foperate/secret-env` — the global CLI is the real body, per-host shells (ZCode plugin / opencode plugin / DSH cordis plugin) just point at it; editing the source takes effect immediately.

## [0.1.x] - 2026-10 ~ 2026-11

Initial prototype line: plaintext mapping file, ZCode PreToolUse hook, provider abstraction (keychain / viking / bitwarden). **All 0.1.x versions are deprecated — do not use** (see the version security notice in the README).
