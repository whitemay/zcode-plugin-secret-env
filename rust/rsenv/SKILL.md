---
name: secret-env
description: 凭据引用与注入——密钥值永远不进模型上下文；命令守卫与一次性 token 注入链、按 backend 分轨的命令面与恢复指令
---

# secret-env（rsenv / senv）使用约定

本机用的是两个同协议实现之一，插件按 `rsenv info` 的 `backend` 字段区分，**行为差异只看 backend，不猜命令名**：

- **rsenv**：Rust 单二进制，turso 加密库，daemon 承载加密库与生命周期（login/logout）
- **senv**：bun/node CLI，keepassxc + secrets.json 后端，轻量 daemon 只做 token 内存槽（按需拉起，无 login）

## 核心不变量

- **你（agent）永远接触不到凭据明文**。命令文本里引用 `$NAME`，宿主钩子调 `<CLI> parse` 守卫并签发一次性 token，改写成注入链后值经 `eval` 进入子进程环境——不进 argv、不进你的上下文。
- 密码/口令类输入**一律让用户在终端完成**（`rsenv login`/`rsenv init`、`senv set` 的隐藏输入都是交互式的），不要试图替用户输入或经对话转述口令。

## 注入机制（parse / inject 两段，两端同构）

- **parse**（钩子时刻，插件壳调用）：命令守卫（文件提及/单引号/倾泻黑名单）+ 解析全部值 → **一次性 token**。值只存在于 daemon 内存（两端同构），你经手的只有 token。
- **inject**：`<CLI> inject <token>` 消费槽位输出 `export NAME='…'` 行，由同 shell 的 `eval` 消费。改写形态（两端逐字一致）：`_senv_inj="$($SENV_BIN inject <token>)" && eval "$_senv_inj" && { 原命令; }`——token 已消费/失效则短路，原命令不执行（fail-closed）。**token 一次性，重放不可能；不要自己拼这个链，宿主钩子会做**。
- 值只在子进程 env 内存活，不跨命令持久。

## 常用命令（按 backend 分轨）

**rsenv（backend=rsenv）：**

| 命令 | 说明 |
|---|---|
| `rsenv list` | 条目清单（名字+描述，**无值**） |
| `rsenv get NAME` | 终端取值打印（用户自查用。**agent 不要调用**——会把明文带进上下文） |
| `rsenv set NAME`（值经 stdin） | 入库 native 条目；`--desc` 加描述 |
| `rsenv set NAME --uri provider://路径` | 入库 provider 引用条目，无需 stdin |
| `rsenv remove NAME` / `rsenv import-secrets [路径]` | 删除 / 旧 secrets.json 迁移 |
| `rsenv run NAME... -- cmd args` | 具名注入执行器（手动场景） |
| `rsenv passwd` | 换口令（终端交互，整库闲置重加密） |
| `rsenv info` / `rsenv mcp` | 守卫快照 / stdio MCP 管理面（无值通道） |

**senv（backend=senv）：**

| 命令 | 说明 |
|---|---|
| `senv list` | 条目清单（名字+描述，**无值**） |
| `senv set NAME --provider keychain`（值经 stdin 或 TTY 隐藏输入） | 入库；`--provider viking/bitwarden/onepassword` 各带 --path/--item |
| `senv set NAME --uri provider://路径` | 登记 provider 引用条目 |
| `senv remove NAME` | 删除条目（`--purge` 支持 keychain） |
| `senv info` / `senv mcp` | 守卫快照 / MCP 管理面 |

## daemon（两端形态不同）

**rsenv**：daemon 承载加密库——只由 `rsenv login` 拉起（用户终端、隐藏输入口令；幂等）。**login 请在完整用户 shell 里执行**（provider 工具环境继承 login 终端的 PATH）。CLI 不会自行拉起 daemon：不在时取值命令直接失败，错误信息含恢复指令。`rsenv logout`：清 key 与槽位、停 daemon。`rsenv init`：仅首次建库。端点按平台：macOS/Linux=unix socket（`daemon.sock`），Windows=named pipe（`\\.\pipe\rsenv-<username>`，真机实测挂账）——文件守卫语义不变，Windows 下管道名不是文件路径、不受文件提及守卫约束。

**senv**：daemon 只做 token 内存槽，`parse` 按需自动拉起（有 socket 直接用，崩了自动重拉），**无需 login、无需管理**；agent 无感知，不必向用户提它。

## agent 行为约定（与 CLI 错误信息一一对应）

CLI 报 `vault is locked: ask the user to run "rsenv login" in their terminal` →
告知用户：在终端跑 `rsenv login`，输 vault 口令，然后重试命令。**不要自己跑 login**（口令必须由用户输入，你输了也没有 vault 口令）。

CLI 报 `vault is not initialized: ask the user to run "rsenv init" in their terminal` →
告知用户：首次使用需 `rsenv init` 建库设口令（终端交互，口令两次确认）。

CLI 报解析失败并列出「现有条目」→ 用清单里的名字重试，或让用户在终端用 `set` 登记缺失条目（agent 不经手值）。

## 守卫行为（为什么某些命令被拒）

- 单引号内引用 `$NAME` → 整条拒绝（完整性无法保证），改用双引号或不引用。
- 命令含引用且命令位置有 `printenv`/`set`/`export`（带引用参数）/裸 `env` → 倾泻拒绝，换目标文件输出等具体消费形态。
- 命令文本涉及受保护文件（info 的 guard_paths：rsenv=vault/audit/sock；senv=secrets.json/vault.kdbx/senv.sock）→ 拒绝，配置维护请在你的终端用 `set/remove`。

## 安全边界（对 agent 的说明）

- 本工具保证的是**数据流**：值不进命令文本/argv、不进你的上下文与日志（两端值都只存 daemon 内存，不落盘）。
- 它**不**限制"你如何使用密钥"：用在哪条命令、发往哪个端点、用多少次。这属于纪律与凭据权限问题，不在本工具的可强制范围。
- 以上守卫都是**防误触**的文本级规则，不是安全边界：**不要试图用脚本嵌套、编码、二次解析等方式绕过守卫**——即使技术上可行，也属于越权使用，用户会发现。
- 若某个任务需要"限制能力"，正确做法是让用户改用**短时/最小权限凭据**或按用途拆分的条目，而不是在命令里变通。
