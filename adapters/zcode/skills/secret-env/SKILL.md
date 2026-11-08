---
name: secret-env
description: 凭据引用与注入——密钥值永远不进模型上下文；命令守卫与一次性 token 注入链、daemon 生命周期与恢复指令
---

# secret-env（rsenv）使用约定

## 核心不变量

- **你（agent）永远接触不到凭据明文**。命令文本里引用 `$NAME`，宿主钩子调 `rsenv parse` 守卫并签发一次性 token，改写成注入链后值经 `eval` 进入子进程环境——不进 argv、不进你的上下文。
- 密码/口令类输入**一律让用户在终端完成**（`rsenv login`/`rsenv init` 是交互式隐藏输入），不要试图替用户输入或经对话转述口令。

## 注入机制（parse / inject / run 三分法）

- **parse**（钩子时刻，插件壳调用）：命令守卫（文件提及/单引号/倾泻黑名单）+ 解析全部值（值不出 daemon）+ 签发**一次性 token**。
- **inject**（运行时刻）：`rsenv inject <token>` 消费槽位输出 `export NAME='…'` 行，由同 shell 的 `eval` 消费。改写形态：`_rse_inj="$(rsenv inject <token>)" && eval "$_rse_inj" && { 原命令; }`——token 已消费/失效则短路，原命令不执行（fail-closed）。**token 一次性，重放不可能；不要自己拼这个链，宿主钩子会做**。
- **run**：`rsenv run NAME... -- cmd args` 具名注入执行器（env 只活在子进程内，退出码透传），手动场景用。
- 值只在子进程 env 内存活，不跨命令持久。

## 常用命令

| 命令 | 说明 |
|---|---|
| `rsenv list` | 条目清单（名字+描述+字段键，**无值**） |
| `rsenv get NAME` | 终端取值打印（用户自查用。**agent 不要调用**——会把明文带进上下文；这是纪律要求，宿主侧没有强制拦截） |
| `rsenv set NAME`（值经 stdin） | 入库 native 条目；`--desc 描述` 加描述 |
| `rsenv set NAME --uri provider://路径` | 入库 provider 引用条目（viking:// / bitwarden:// / onepassword://），无需 stdin |
| `rsenv remove NAME` | 删除条目 |
| `rsenv import-secrets [路径]` | 从旧 secrets.json 迁移（URI 引用，无明文） |
| `rsenv run NAME... -- cmd args` | 具名注入执行器 |
| `rsenv passwd` | 换口令（终端交互；整库闲置重加密：daemon 短暂停→侧路径建新库→换装→验证失败自动回滚） |
| `rsenv info` | 守卫快照：guard_paths / entries（宿主钩子的保护目标清单来源） |
| `rsenv mcp` | stdio MCP 管理面（只 list/status，值不走此通道） |

## daemon 生命周期（重要）

- **daemon 只由 `rsenv login` 拉起**（用户终端、隐藏输入口令；幂等——daemon 已在跑且已解锁则静默退出，locked 态继续走解锁）。
- **login 请在完整用户 shell 里执行**：daemon 的 provider 工具环境继承 login 终端的 PATH（ov 依赖 node）；精简终端/GUI 内嵌终端可能缺工具链，缺什么 login 时会明确提示。
- **CLI 不会自行拉起 daemon**：daemon 不在时所有取值命令直接失败，错误信息含恢复指令。
- `rsenv logout`：清 key 与待注入槽位、停 daemon（用完即走的敏感窗口管理）。
- `rsenv init`：仅首次建库（库已存在则拒绝）。

## agent 行为约定（与 CLI 错误信息一一对应）

CLI 报 `vault is locked: ask the user to run "rsenv login" in their terminal` →
告知用户：在终端跑 `rsenv login`，输 vault 口令，然后重试命令。**不要自己跑 login**（口令必须由用户输入，你输了也没有 vault 口令）。

CLI 报 `vault is not initialized: ask the user to run "rsenv init" in their terminal` →
告知用户：首次使用需 `rsenv init` 建库设口令（终端交互，口令两次确认）。

CLI 报 `rejected: caller is not rsenv` →
说明该调用不是经 rsenv 发起的（鉴权拒绝），检查调用方式。

## 守卫行为（为什么某些命令被拒）

- 单引号内引用 `$NAME` → 整条拒绝（完整性无法保证），改用双引号或不引用。
- 命令含引用且命令位置有 `printenv`/`set`/`export`（带引用参数）/裸 `env` → 倾泻拒绝，换目标文件输出等具体消费形态。
- 命令文本涉及密钥库文件（vault.db、.vault.salt、audit.jsonl、daemon.sock）→ 拒绝，配置维护请在你的终端用 `rsenv set/remove`。

## 安全边界（对 agent 的说明）

- 本工具保证的是**数据流**：值不落盘明文、不进命令文本/argv、不进你的上下文与日志。
- 它**不**限制"你如何使用密钥"：用在哪条命令、发往哪个端点、用多少次。这属于纪律与凭据权限问题，不在本工具的可强制范围。
- 以上守卫都是**防误触**的文本级规则，不是安全边界：**不要试图用脚本嵌套、编码、二次解析等方式绕过守卫**——即使技术上可行，也属于越权使用，用户会发现。
- `rsenv get` 会把明文打印到 stdout：**agent 不得调用**（用户自查专用）。
- 若某个任务需要"限制能力"，正确做法是让用户改用**短时/最小权限凭据**或按用途拆分的条目，而不是在命令里变通。
