# secret-env 插件设计记录

> 英文摘要（决策速览，面向贡献者）：[DESIGN.en.md](DESIGN.en.md)。本文为完整设计沿革（中文）。
> 2026-11-04 与用户讨论定稿的设计结论。探针插件（`secret-env-probe/`）验证机制可行性后，按本文档实现正式插件。
> 策略：先做成项目内插件（`plugins/secret-env/`），成熟后迁独立仓库（`~/github/zcode-plugins/` 形态）。

## 1. 问题定义

AI 会话中执行需要凭据的 Bash 命令时，凭据不能经过模型上下文：

- 现状：MCP 工具（如 openviking `privacy_resolve`）解析 `{{ov_privacy:...}}` 占位符后，明文必然进入模型上下文与会话记录
- 目标：凭据从私有库直达子进程环境，**模型上下文从头到尾只见占位符/变量名，永见不到值**

## 2. 核心机制决策

### 2.1 环境变量注入，不做命令文本替换（已定）

| 方案 | 判定 |
|---|---|
| 字符串替换（把真值写进命令文本） | ❌ 反模式：真值流经审计日志/会话记录/错误回显；shell 引号注入坑（`$`、反引号、引号破坏命令或泄露） |
| 环境变量注入（0600 临时 env 文件按引用原名 export + 命令前缀 source，命令文本零改写） | ✅ 定案：文本与值分离，日志照记无泄露；引号语义无关 |

细节：占位符落在**单引号内不展开**，钩子须检测并拒绝改写（提示改用双引号），不得静默产出不生效的引用。

> **2026-11-04 修订（用户拍板）：注入变量名 = 原始名。** 原实现把引用改写为 `${ZCODE_SECRET_n}`，偏离了「原命令不知道注入这件事」的设计意图。现改为：env 文件按命令中**实际引用的名字** export（别名引用注入别名名，周知引用注入周知名），命令文本零改写。隐式使用（工具自己读 GH_TOKEN）钩子扫不到，由 skill 引导 agent 显式化：`GH_TOKEN=${GH_TOKEN} git push`、`USE_TOKEN=${GH_TOKEN} cmd` 皆可——只要命令文本出现 `$GH_TOKEN`，注入即触发。

### 2.2 形态定案（2026-11-04 探针通过）

- 探针实测：PreToolUse 钩子 `updatedInput` 改写 Bash 命令**真实生效**（`echo PROBE_MARK` 返回 `HOOK_REWRITE_OK <时间戳>`）→ **纯钩子形态，MCP 退路不需要**
- harness 源码核查（zcode.cjs）两个附带结论：
  - Bash 工具入参 schema 无 `env` 字段 → 注入方式定为 **0600 临时 env 文件 + 命令前缀 `. <envfile>`**（文本与值分离保持成立，日志只见文件路径；陈旧文件 15 分钟自清）
  - PostToolUse 输出 schema 只有 `additionalContext`/`decision`，**没有 tool_result 改写** → §6 出口脱敏第 1 条**不可实现**，已从正式插件裁掉；防线 = 注入前移（值只存在于 env 文件与子进程环境）+ dump 黑名单 + skill 明令禁止 echo 凭据

## 3. 密钥来源：provider 抽象

三种后端可插拔，钩子层只认 scheme：

| scheme | 来源 | 说明 |
|---|---|---|
| `keychain://` | 系统密钥库（macOS `security` 命令） | 本机最简 |
| `viking://` | OpenViking privacy 层（`ov privacy resolve <category> <target>[/<field>]`，v0.5.1 CLI 实测在） | 跨设备 |
| `bitwarden://` | Bitwarden CLI（`bw get`） | 跨设备、团队共享 |

> scheme 命名拍板（2026-11-04）：OpenViking provider 直接用真实 scheme 标识 `viking://`，不自造 `ov://`。注意 privacy 条目按 category/target/field 三段寻址，并非 viking:// 资源树 URI，只是复用同一 scheme 字面。

### URI 一般化寻址（2026-11-04）

需求先行：账户信息也是 agent 常用载荷（构造 DSN、`-u` 参数、成对凭证的 id 侧如 AWS access key id），不止密钥本身。由此把 URI 从「`scheme://item` = 主密钥」推广为 `scheme://item[/field]`：

- **一级寻址（缺省）= 主密钥**，已登记 URI 全部不变，零迁移
- **二级寻址**：`keychain://<service>/account`（读属性表解析 `"acct"=` 行）；`viking://…/<field>`（既有能力，天然符合）；`bitwarden://<item>/<field>`——保留键 `password`/`username`/`totp` 走 `bw get` 子命令，其余按自定义字段在 `fields[]` 按 name 匹配（保留键优先，撞名改字段名消歧）
- keychain 写入侧配套：`secret-env add --user <acct>` 可选参数（account 非敏感，缺省仍为当前系统用户）；读侧对 `keychain://<svc>/account` 有实义的前提是 account 有被认真写入
- **防歧义**（探针实证）：macOS keychain 的 account 与 service 共同构成条目身份，`-U` 带新 account 不改旧条目而是新建第二条；`find-generic-password -s` 在多命中时只静默返回第一条——读前经 `dump-keychain` 计数（~20ms），>1 即报歧义错，password 与 account 两条路径统一拒绝
- 探针验证：bw 自定义字段（text/hidden、中文与带空格字段名）均可在 `fields[].value` 取到；`bw get item` 的 JSON 解析天然保留前导空格等值形态


### provider 写侧自治（2026-11-04 拍板的原则，先落文档后实现）

**原则：配置即能力。** 只要某 provider 的凭据链在配置里闭环（如 BW_SESSION 存钥匙串、ov 有 cli.conf），secret-env 自己的全部操作——读和写——都应踩着 provider 抽象自治完成，不把 raw 命令（`bw create`/`ov privacy upsert`）留给用户手工跑。`secret-env add` 对所有 provider 统一为「隐藏收值 → provider 写入 → 登记 uri」，值不经 Agent 上下文，secrets.json 是唯一事实源。

推论与边界：

- **读已自治**：resolveValue 统一注入 provider 凭据（BW_SESSION 配置记录优先于宿主环境变量）。
- **写的落位与读镜像**：写 password 位 ↔ 读一级寻址；写自定义字段/username ↔ 读二级寻址。
- **bitwarden 写语义**：`--item X`（不存在）→ 新建 login 条目，值进 password 位，`--user` 顺路写 username 位；`--item X --field F` → 已存在条目上 upsert 自定义字段（不存在则拒绝，不隐式建条目）。
- **viking 写的安全约束**：`ov privacy upsert` 值走 argv 有进程表暴露面，先探针 stdin 通道；不支持则 viking 写侧保持「值由用户在 ov 侧放好」，缺位如实入档，不接受 argv 风险换自治。
- **keychain 写已闭环**（backend.write），作为统一形态的参照实现。

### bitwarden:// 的两级解析（2026-11-04，0.1.1）

`bw get password` 需要 vault 解锁态（`BW_SESSION` 环境变量），而钩子进程环境里没有。解法是把 session key 本身登记为一条 secret-env 记录（`BW_SESSION → keychain://bw-session`，存本机钥匙串），`resolveValue(uri, config)` 解析任何 `bitwarden://` 条目前先查配置中的 `BW_SESSION` 记录、经其自身 provider 解析后注入 `bw` 子进程环境——真值不落 rc 文件、不进宿主环境。要点：

- **按名约定**：触发条件是配置里存在名为 `BW_SESSION` 的条目（名字硬编码）；第一级 provider 不限 keychain。
- **死循环守卫**：BW_SESSION 记录的 uri 不允许是 `bitwarden://`（需要 vault 先解锁才能解锁），显式拒绝。
- **session key 生命周期**：每次 `bw unlock` 换新值，重跑 `security add-generic-password -U -s bw-session -a "$USER" -w` 覆盖；过期后 bitwarden 凭据解析报 bw 原始错误。
- 条目名即 `bw get password` 的检索名（execFileSync argv 直传，空格/中文无需转义）；只取 login 条目的 password 字段，重名条目建议用 id。端到端（钩子链路 + Node/Bun 双运行时）已实测通过。

## 4. 命名与映射层

- **主键 = 周知环境变量名**（`GH_TOKEN`、`OPENAI_API_KEY`、`DATABASE_URL`…）——这些名字本身是事实标准，模型写命令零翻译、多工具共享同一凭据（gh/GitHub API/act 共用 `GH_TOKEN`）
- 别名表：`GITHUB_TOKEN` → 主键 `GH_TOKEN`；一个凭据喂多个惯用名（数组）
- 换后端只改 `uri`，命令与命名不动
- **配置文件位置（2026-11-04 实战修订）**：`~/.config/secret-env/secrets.json`（首选，700/600）→ 插件根 `secrets.json`（兼容）。放插件目录外是硬要求：安装缓存是安装时快照，marketplace refresh 即覆盖，凭据映射会凭空丢失（首次实弹 401 的根因）

## 5. 注入触发：只处理命令文本中的显式引用（已定，2026-11-04 简化）

| 路 | 触发条件 | 例子 |
|---|---|---|
| ① 占位符 | 命令文本含 `{{secret:NAME}}` | `curl -H "Authorization: Bearer {{secret:GH_TOKEN}}"` |
| ② 显式 $VAR 引用 | 命令文本含已配置的周知变量名 | `psql "$DATABASE_URL"`、`GH_TOKEN=$GH_TOKEN gh pr list` |

- **不做工具触发表、不做隐式注入**（原三路设计的第③路已砍）：命令隐式消费环境变量时（如裸 `gh pr list` 自己读 `GH_TOKEN`），由 **agent 负责把它显式构造出来**——skill 文件引导模型写成 `GH_TOKEN=$GH_TOKEN gh ...` 形式，钩子只认显式文本
- 职责划分：钩子=纯文本扫描的机械层（零静态知识库、零首词解析、不随工具生态漂移）；语义判断（哪个工具要什么变量）归模型，skill 承担
- 收益：钩子实现极简、行为可预期；代价：依赖 skill 引导质量——模型没写显式引用时注入不生效，宁可失败也不做魔法

## 6. 出口防线（2026-11-04 修订）

1. ~~PostToolUse 脱敏~~：**不可实现**——harness PostToolUse 输出 schema 无 tool_result 改写能力（见 §2.2）。诚实降级：值经输出回流入上下文（如 `echo $GH_TOKEN`）无自动防线，靠 skill 明令禁止
2. **倾泻黑名单**（PreToolUse 前置，已实现；2026-11-04 两轮收窄定稿）：
   - **初版**：会话注入过密钥后，命令文本命中 env/printenv/set/export 词 → 拒。按「词出现」匹配，实战连坐三次误伤（`set -e`、英文散文里的 `env;`、commit message 里的 dump 词）
   - **终版（用户拍板）**：仅「命令含密钥引用 **且** 命令位置有倾泻意图」才拦（同命令倾泻如 `GH_TOKEN=$GH_TOKEN env`）。会话状态机整体删除——每次 Bash 调用都是全新 shell，注入变量不跨调用存活，跨调用裸 env 无威胁。命令位置=首词/VAR=value 赋值前缀后/`;&&|||`分隔后；env/printenv 任意参数算，set/export 仅裸词或 -p。无引用命令什么都不注入、本 shell 无密钥可倾泻，直接放行
   - 配套 skill 指导：倾泻意图（查环境等）放独立 Bash 调用——独立调用是全新 shell，天然看不到注入值

## 7. 组件构成

| 组件 | 角色 | 说明 |
|---|---|---|
| hooks | 必备主体 | PreToolUse（显式引用注入+dump 黑名单+命令改写）、PostToolUse（出口脱敏） |
| mcpServers | 条件件 | 探针通过 → 零 MCP 纯钩子闭环；不生效 → `secret_exec` 退路主体（服务端解析+自执行+只回 stdout） |
| skills | 必备（与钩子同级） | 引导模型把隐式 env 消费显式化（`GH_TOKEN=$GH_TOKEN gh ...`）、教占位符语法/周知名清单/单引号禁忌/黑名单行为——显式化约定靠它落地；顺带 `/secrets` 命令列出已配置条目 |

## 8. 落地路线

1. ✅ 探针插件（`plugins/secret-env-probe/` + `plugins/marketplace.json` 本地市场 `dev-nuxt-high-school-plugins`）——**待用户 UI 安装**（Plugin Marketplace → Add 粘贴 `plugins/` 目录 → Install），验证钩子调用与 `updatedInput` 改写
2. 按 §2.2 结果定形态
3. 正式实现：provider 抽象 + 显式引用注入 + 出口防线
4. 成熟后迁独立仓库（市场根 = 仓库根），本项目内养熟期间只在 nuxt-high-school 会话生效

## 9. 已知约束

- 项目级插件不碰 `.zcode/config.json`（aidlc 钩子属地），两套钩子并行无冲突
- 探针/正式插件均需用户手动 UI 安装（plugin-creator 约定），本地市场基于目录，更新 = 改源码 + 市场里 refresh
