# DSH 适配器协议化改造方案

> 目标：`adapters/dsh/` 不再 import 主包代码（`core.mjs` / `cli.mjs` / `entry.mjs`），只通过 CLI 协议交互。
> 动机：解耦后 bundle 可拆为独立薄包，主包只在全局装一份（见对话记录 2026-11-06）。
> 边界：不动 ZCode / opencode 适配器；不改既有行为口径（§4）；**不做**长驻 helper、**不走** MCP。

## 进度

- **阶段 1 已完成（2026-11-06）**：`core.mjs` 加 `PROTOCOL_VERSION` / `configPaths()`；`cli.mjs` 抽 `buildInjection()`（hook zcode 与 inject 共用）并新增 `info` / `inject` / `store` 三命令；`tests/cli-protocol.mjs` 41 项通过；`test:all` 已纳入（`bun run test:protocol` 可单独跑）。
- 阶段 2（适配器改协议客户端）未开工。

## 0. 为什么 guard 不能外置

`ctx.tools.guard` 是同步回调（返回 reason，不 await），且每次工具调用都跑（含 read/write/glob）。
外置成子进程 = 每次工具调用 spawnSync 一次 node（40–60ms），不可接受。因此：

| 路径 | 频次 | 归属 |
|---|---|---|
| guard 判定（受保护路径 + 引用扫描） | 每次工具调用（同步） | 插件内（规则数据 + scanRefs 副本） |
| bash 注入（解析、写 env 文件） | 仅命令含引用时（异步） | CLI 子进程 |
| add_secret 入库 | 极低频（异步） | CLI 子进程 |
| 名单/规则快照 | 启动 + 配置变更（异步） | CLI 子进程 |

## 1. 协议定义（protocol 1）

一行 JSON 进（stdin）、一行 JSON 出（stdout）；日志只走 stderr 与插件日志。**任何响应都不含凭据值。**

```
secret-env info --json
  → {
      protocol: 1,
      version: "0.4.0",                  // 主包版本
      configMtime: 1762400000000,        // secrets.json mtime（插件据此刷新快照）
      entries: [ { name, aliases: [], description } ],
      rules: { guardPaths: [ "...", "..." ] },
      providers: [ "keychain", "bitwarden", "viking", "onepassword" ]
    }

secret-env inject                          # stdin: { protocol, command, session }
  → { command: ". '<envFile>'; <原命令>", envFile }           # exit 0
  → { error: "reason" }                                     # exit 2（单引号/倾泄/解析失败/占位符未配置）
  → { error: "protocol mismatch" }                          # exit 3

secret-env store                           # stdin: { protocol, name, provider, detail, alias, description, value }
  → { status: "stored", envName, uri }                       # exit 0
  → { status: "invalid"|"error", message }                   # exit 2
```

约束：

- 值只经 **stdin 管道** → 子进程 → provider / env 文件；不落 argv、不回 stdout；
- stdout 严格一行 JSON；`version` 用于启动握手，`protocol` 不匹配即拒绝注入（宁可失败，不放行）。

## 2. 改动清单

### 阶段 1：主包新增协议命令（可控、无行为变更，可独立发版）

| # | 文件 | 改动 |
|---|---|---|
| 1 | `core.mjs` | 新增 `export const PROTOCOL_VERSION = 1`；其余不动（`scanRefs` / `isDumpCommand` / `guardPaths` / `resolveValue` / `writeEnvFile` 复用） |
| 2 | `cli.mjs` | 新增 `cmdInfo()` / `cmdInject()` / `cmdStore()` 与分发（`info` / `inject` / `store`）；把 `cmdHookZcode` 的注入段抽成 `buildInjection(command, session)` 供 zcode 与 dsh 共用，避免两套语义 |
| 3 | `cli.mjs` | `info` 读 `loadConfig()` 生成 entries（不含 uri）与 `guardPaths()`；不读 provider 值 |
| 4 | `tests/cli-protocol.mjs`（新） | 临时 HOME + 假 secrets.json：info 快照/无值断言；inject 的单引号拒绝、倾泄拒绝、正常注入、env 文件 0600、未配置占位符；store 走假 keychain 条目（参考 `adapters/zcode/tests/write.mjs`）；protocol 不匹配 → exit 3 |

验收：`bun tests/cli-protocol.mjs` 全绿；现有 4 个测试文件不改仍全绿。

### 阶段 2：适配器改为协议客户端（仍单包，可回退）

| # | 文件 | 改动 |
|---|---|---|
| 5 | `adapters/dsh/client.mjs`（新，~100 行） | `resolveCli()`（`$SENV_BIN` → PATH `secret-env`）；`info()` / `inject()` / `store()`（`node:child_process.spawn`，超时 inject 5s、store 10s）；退出码映射；stderr 进插件日志 |
| 6 | `adapters/dsh/rules.mjs`（新） | 复制 `core.scanRefs`（38 行，注释标注同步来源）；`matchGuardPaths(text, fragments)` |
| 7 | `adapters/dsh/guards.mjs` | 删 `import { guardPaths, scanRefs } from core.mjs`；`evaluateCall(exec, snapshot)`、`promptText(snapshot)` 改吃快照 `{entries, guardPaths}`；pwsh `$env:` 特例改遍历 entries |
| 8 | `adapters/dsh/index.js` | 删 `import { envNameFromHuman, storeEntry } from cli.mjs` 与 `await import(core.mjs)`；启动 `await client.info()` 存快照；guard/promptText 用快照；bash 注入前比对 `configMtime`（变了后台刷新）；注入改 `client.inject`，非零退出 → throw（error tool result，文案取自 `error`）；add_secret 改 `client.store`（`envNameFromHuman` 逻辑随协议进 CLI，插件只做必填校验）；provider 校验用快照 `providers` |
| 9 | `tests/dsh-guard.mjs` | 用假快照构造，不再 import core；保留 16 项断言 |
| 10 | `tests/dsh-protocol.mjs`（新） | 假 CLI 脚本覆盖：CLI 不存在、超时、非零退出、协议版本不匹配、stdout 非 JSON；再跑一次真 CLI 的最小注入（临时 HOME + 假 keychain） |
| 11 | `tests/rules-sync.mjs`（新） | 一组 fixture 命令比较 `rules.scanRefs` 与 `core.scanRefs` 输出（token/inSingle 全等）——防判定漂移 |
| 12 | `package.json` | `test:all` 追加 `tests/cli-protocol.mjs tests/dsh-protocol.mjs tests/rules-sync.mjs` |

验收：

- `grep -rn "core.mjs\|cli.mjs\|entry.mjs" adapters/dsh/` 只剩注释与自身文件；
- `bun run test:all` 全绿；
- 真机 5 项：系统提示清单 / `$GH_TOKEN` 注入 / read 拒绝 / terminal_send 拒绝 / pwsh 拒绝；
- 一次含引用 bash 调用的端到端延迟记录（目标 <150ms）。

### 阶段 3（可选，取决于是否要独立发版）：拆薄包

| # | 动作 | 说明 |
|---|---|---|
| 13 | `adapters/dsh/package.json`（新）`@foperate/secret-env-dsh` | `files`: 适配器源码 + patch + locale + icon + skills 副本；`peerDependencies: @foperate/secret-env`（只声明兼容，不装依赖） |
| 14 | 根 `package.json` | 移除 `dsh` 字段与 `./dsh` exports（保留一个版本做兼容也可）；patch name 改 `@foperate/secret-env-dsh` |
| 15 | skill | bundle 包内放副本（与主包 `skills/secret-env` 逐字节一致）；`~/.dsh/skills/secret-env` 改指 bundle 包；`tests/skill-sync.mjs` 扩到 4 份 |
| 16 | 发布/文档 | 先发主包（协议）再发 bundle；`docs/INSTALL-DSH.md` 改两步安装 + 版本兼容矩阵（主包 protocol 1 ↔ bundle 版本） |
| 17 | 安装形态 | 主包全局一份（CLI）+ bundle 进 profile（薄包），不再重复装同一个包 |

### 阶段 4：回退与观察

- 阶段 1 是纯增量命令，出问题直接不调用即可；
- 阶段 2 保留一个版本的环境开关 `SENV_DSH_LEGACY=1` → 走旧进程内 import，下一版删除；
- 插件日志新增：`snapshot refresh` / `inject via cli` / `store via cli`（只记名字与耗时，不记值）。

## 3. 风险与对策

| 风险 | 对策 |
|---|---|
| 全局 CLI 缺失或版本不符 | 启动握手校验 `protocol`/`version`；注入路径报错而非放行（宁可失败）；安装文档把全局安装列为前置 |
| guard 与注入判定漂移 | `tests/rules-sync.mjs` 行为全等校验；`guardPaths` 由 CLI 数据单源提供 |
| 注入多一次进程启动 | 仅含引用命令触发，实测后确认；不引入长驻进程（过度设计） |
| 快照过期 | `configMtime` 变更后台刷新；最坏一次调用窗口与现状等价（现状每次调用读文件，更慢） |
| 子进程污染日志 | inject 只回 env 文件路径；日志沿用「只记名字」口径 |
| 拆包后 skill 副本漂移 | `skill-sync` 扩到 4 份逐字节校验 |

## 4. 明确不做

- **MCP 通道**：模型面工具通道，值会进上下文方向相反；插件也没有调用 MCP server 的 API。
- **长驻 `serve --stdio`**：注入是低频异步路径，spawn 成本可接受；生命周期/崩溃恢复成本不划算。
- **guard 外置**：同步回调 + 每次工具调用，进程化不可行。
