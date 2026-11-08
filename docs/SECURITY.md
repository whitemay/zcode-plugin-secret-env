# 安全模型与边界（Security model & non-goals）

> TL;DR — rsenv is a **data-flow guard**, not an access-control system. It guarantees that secret values do not land in plaintext on disk, in command text/argv, in the model context, or in logs. It does **not** restrict what an agent (or anyone with your shell) may *do* with a secret, and it is **not** designed to withstand a local attacker running as the same user.

本文说明：本工具保护什么、不保护什么、为什么某些"限制使用能力"的方案被明确放弃。所有结论都以 0.4.x（rsenv / Rust + daemon）实现为准。

## 1. 威胁模型

**保护目标**：降低"密钥值被迫暴露给模型上下文 / 明文落盘 / 进日志"的风险；防止 agent 误触（被提示注入诱导、手滑、理解偏差）。

**明确非目标**：

1. **不防御本机同用户攻击者。** 一旦攻击者能以你的 uid 执行代码，本工具的一切防护都失去意义：vault 口令可被键盘记录；`~/.local/bin/rsenv` 是用户可写文件，替换成同路径的二进制即可通过 daemon 的 peer-exe 检查（该检查是**路径比较**，不是签名/哈希）；`audit.jsonl` 同 uid 可改写；daemon 内存中的已解锁密钥可被读取（取决于平台权限）。这一层不对本工具提出要求，详见 §3。
2. **不限制"密钥的使用能力"**（谁能用、用在什么命令上、发往哪个端点、用多少次）。在"agent 拥有用户 shell"的现实下，这一层没有可强制边界；所有相关方案（子命令拦截、调用来源判别、审批协议）均已评估并放弃，理由见 §4。
3. **不做出口脱敏。** 值一旦进入消费端（例如被 `curl` 用法发送），是否外发不由本工具控制；脱敏需要 egress 代理或服务端策略。

## 2. 保证（A：数据流）及实现依据

| 保证 | 实现依据 |
|---|---|
| 值不以明文落盘 | `vault.db` 为 AEAD 加密库（aegis256），salt 独立存放；daemon 持解出值于内存，不写盘 |
| 值不进命令文本 / argv | `parse` 只签发一次性 token；`inject` 输出 `export NAME='…'` 行，在当前 shell 内 `eval` 消费；token 一次性消费，未消费残留 10s 后回收 |
| 值不进模型上下文 | 注入只写入子进程环境；工具结果、错误信息、审计与插件日志均不含值 |
| 值不进日志 | 插件日志只记 `names` 与 token 事件；`audit.jsonl` 只记事件、条目名与时间 |
| 一次会话窗口可控 | `rsenv logout` 清 key 与待注入槽位并停 daemon；槽位随会话清空 |

**守卫的真实定位（防误触，不是安全边界）**：

- 命令文本涉及密钥库文件（`vault.db` / `-wal` / `-shm` / `.vault.salt` / `audit.jsonl` / `daemon.sock`）→ 拒绝；
- 单引号内引用 `$NAME` → 整条拒绝（不会被展开，完整性无法保证）；
- 命令含引用且命令位置有 `printenv` / `set` / `export` / 裸 `env` → 倾泻拒绝。

这些规则是**文本级**的，用来把明显的误触挡在门外。它们挡不住刻意绕过：脚本嵌套（`sh x.sh` 内部的 `rsenv` 调用不经过宿主 parse）、编码、二次解析都可以绕过。请勿把它们当作安全保证。

**`rsenv get` 的定位**：它是给用户在自己的终端里自查用的取值出口，值直接打印到 stdout。agent 侧**没有**强制拦截（脚本嵌套即可绕过），拦截它只能防手滑。因此 agent 不使用 `rsenv get` 属于**纪律要求**（见 skill），不是机制保证。

## 3. 为什么连接级鉴权不是"授权"

`peer_exes_self()` 校验的是 peer 进程的可执行文件**路径**是否等于 daemon 自己的路径（`canonicalize` 比较）。它解决的是"其它程序误连/直连 socket"，不是"谁有权使用密钥"：

- 同 uid 的攻击者把 `rsenv` 二进制原地替换为同路径的自有程序，检查照样通过；
- agent 通过宿主 bash 调用 `rsenv` 时，peer 天然是合法 rsenv——这一层对它完全透明。

因此连接级鉴权只能保留为"防误连"，不应被描述为安全边界。

## 4. 为什么不提供"使用授权"（B）

逐条评估过的方案，以及放弃原因：

| 方案 | 问题 |
|---|---|
| caller 身份鉴权（argv/env 校验） | 可伪造；daemon 看到的 caller 永远是 rsenv |
| 调用来源判别（进程祖先链） | CLI harness 下整条链是 node/bun，判别退化；脚本可再造进程链 |
| 宿主 hook 侧子命令白名单 | 只能看到顶层命令文本，脚本嵌套绕过；注定是"防手滑" |
| login 时下发临时 token，受保护子命令需带 token | 只能保护管理类子命令（get/set/remove/passwd）；而 `parse`/`inject` 必须免 token 才能工作，**保护不到"使用"这一轴**；token 还会经 `ps -E`、终端 scrollback 泄漏 |
| 条目级 allow_commands / allow_hosts 策略 | 文本级匹配可绕；维护成本高；误伤正常用法 |

结论：**vault 不具备对"使用"的权威**。想真正约束使用能力，发力点在别处：

- **发行端**：fine-grained PAT、只读数据库账号、STS/OIDC 短时令牌、按用途分条目（`GH_TOKEN_RO` / `GH_TOKEN_ADMIN`）——约束的是"这把钥匙能开什么门"，与谁拿着、在哪台机器无关；
- **服务端**：只读数据库代理、只允许 push 指定分支的 Git 网关、按任务签发短时 token 的 broker——由服务端裁决"能不能做"；
- **宿主侧**：高风险/不可逆动作走人工审批或人工执行，而不是交给 agent 持长期密钥执行。

## 5. 推荐实践（不构成保证）

1. 给 agent 用的凭据尽可能是**短时、最小 scope、只读**的；长期全权凭据应由人持有。
2. 高价值与低价值用途**分开配置条目**，不要把 admin token 配成 agent 日常用的那一条。
3. 敏感窗口用完即关：`rsenv logout`；不要长期保持 daemon 解锁。
4. 需要"可追溯"时，把 `audit.jsonl` 接到你的日志系统——它记录**使用事实**（条目名、时间、事件），但不阻断，且同 uid 可改写，不能作为对抗性取证依据。

## 6. 漏洞与设计讨论

本项目的价值主张是"减少暴露面"，不是"提供安全隔离"。如果你需要后者，请按 §4 的方向在发行端/服务端/宿主侧解决。发现实现与本文档描述不一致的地方，欢迎提 issue（[GitHub](https://github.com/whitemay/zcode-plugin-secret-env/issues)）。
