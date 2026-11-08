# Rust daemon 架构方案（探讨稿）

> 状态：**探讨中，未定稿**。本文记录 turso 加密 PoC 结论与「核心协议 + 多门适配」架构方向；所有标注【待拍板】的条目均为开放问题，勿在未拍板前抢跑实现。
>
> 关联背景：senv agent daemon（2026-11-05，JS 形态）已实现后否决回退——否决理由是「脚本形态身份核验不可达」；本方案的 Rust 二进制形态恰好满足当年论证中的重启前提（编译二进制 → 内核 exe = 工具自身 → 第②级路径+hash 核验可达；签名 → 第③级跨 UID 强制可达）。论证全文见原 DESIGN.md。

## 1. 目标形态（已议定方向）

单二进制 Rust 应用，daemon 为唯一解密点，多门适配：

```
myapp login        # TTY 隐藏输入口令 → argon2 派生 hex key → detached spawn daemon → token 握手
myapp serve        # daemon：持派生 key + turso 加密库连接，unix socket + token 鉴权
myapp mcp          # stdio MCP 薄客户端 → socket 转发（ZCode/DSH/opencode 等宿主接入）
myapp get/set/list/…  # CLI 薄客户端 → 同一 socket
```

语义收敛：核心协议只写一次（§3），CLI/MCP/任意客户端都是传输适配层。之前 JS 版「同一语义在 CLI/MCP/钩子三处各实现一遍产生漂移」的问题被结构性消解。

## 2. turso 加密 PoC 结论（2026-11-07，已验证）

PoC 代码：`poc/turso-enc-poc/`（turso 0.8.3，aegis256 + aes256gcm 双 cipher）。

| 场景 | 结果 |
|---|---|
| 建加密库→写入→同连接读回 | ✅ |
| 关闭后同 key 重开读回+续写 | ✅ |
| 错误 key 重开 | ✅ open 即刻拒绝（`Decryption failed for page=1`），无惰性失败 |
| 无 key 重开 | ✅ open 即刻拒绝（`file is not a database`） |
| 密文落盘 | ✅ 无 SQLite 明文魔数、无明文值可 grep |

工程结论：
- **文件头 = `Turso\0`，非 SQLite 兼容**——加密库完全自包含，任何第三方工具（SQLCipher/sqlite3/DB browser）读不了。无第三方读取面，代价是与 turso 版本单点绑定。
- **key 是 hex 字节，无 KDF**——用户口令在 login 时由 daemon 侧 argon2 派生成 hex key，密钥与口令解耦（比 SQLCipher 口令直用更干净，KDF 参数自有可控）。
- **open 即刻校验 key**——login 握手直接用 open 当口令验证，无需额外探针。
- **turso 无 rekey API**——换口令 = 逻辑重加密：旧 key 开库导出 → 新 key 建新库回放 → 原子换名。已实测全通（数据保序、旧 key 换名后被拒）。附带发现一个生产级陷阱：**turso 是 WAL 架构，数据可能全在 `path.db-wal` 里（主文件可为 0 字节）**——任何备份/搬家/换名操作必须搬全文件组（`.db` + `-wal` + `-shm`），只搬主文件=静默丢数据。
- login 链路实测（argon2id 派生 → open 验证）：正确口令重开读写 OK、错口令 open 即刻拒绝；派生 key 建库与 login 共用同一入口成立（建库即首次 login）。
- 错 key / 无 key 的 open 尝试**不破坏库内容**（probe 后正确 key 照常读到全量数据）。
- 编译/运行：单二进制零外部依赖，arm64 macOS 无摩擦；argon2 crate（纯 Rust）加入后编译仍轻量。

一票否决项解除，turso 加密定为数据层基座。

## 2.1 已拍板项（2026-11-07）

- **A1 = 方案②**：Rust 版定位为 secret-env 的继任者（同一产品换引擎），保留对外概念（provider、URI 寻址、注入钩子），考虑兼容与迁移路径；宿主适配器指向新二进制，CLI 命令名沿用。
- **B4 = 行式 + JSON 列**：`entries(id, name, desc, fields_json, …)`——条目为原子单位（一 entry 一行），字段寻址落 JSON 键；daemon 全量加载进内存，SQL 只当存储层。schema 细节草案另出。


## 3. 核心 socket 协议（方向，细节待设计）

newline-JSON over unix socket，与当年 senv daemon 协议同构：

- 命令集（沿用当年口径作起点）：`login` / `resolve` / `write` / `remove` / `list` / `lock` / `status`
- 关键约束：**resolve 类命令返回「注入凭证」而非明文**——明文只在 daemon 内部流向注入通道（exec env 注入 / srun 式具名注入），任何门都拿不到值。
- daemon 定义统一错误码，各适配层翻译成宿主方言（CLI exit code / MCP tool result）。
- 协议语言无关：pi、脚本、socat 可直连调试。

【待拍板】协议版本握手、错误码表、注入通道的命令形态（是否沿用 `srun NAME -- cmd` 语义）。

### 3.1 socket 协议定稿（2026-11-07，随实现成文）

- 传输：unix socket（daemon.sock，0600），newline-JSON——每连接一请求一响应；**连接级鉴权 = peer-exe 实查**（macOS `LOCAL_PEERPID`→`proc_pidpath`；Linux `SO_PEERCRED`→`/proc/<pid>/exe`），非本二进制即刻断开（e2e 有 python3 攻击者断言）。无 token 文件（§7）。
- 请求 `{"op": ..., ...}`，响应 `{"ok": bool, ...}` 或 `{"ok": false, "error": "..."}`。
- op 表（值类）：`get{name}` / `set{name, value|uri, desc}`（value 与 uri 互斥）/ `remove{name}` / `list` / `import{entries:[{name,desc,uri}]}`。
- op 表（会话类）：`login`（login 进程内验证后经 serve stdin 传 key）/ `logout`（清 key+槽位，停 daemon）/ `status{unlocked}`。
- op 表（注入类）：`parse{command}` → `{action: pass|inject|reject, token?, names?, reason?}`（reject 退出码 2 由 CLI 翻译）；`redeem{token}` → `{env}`（消费一次即删）。
- 协议版本：`rsenv info` 的 `"protocol": 1` 字段即握手——适配器启动时 infoSync 校验，不匹配则插件拒绝加载。
- 错误口径（agent-actionable，CLI/daemon/MCP 三处一致）：`vault is locked: ask the user to run \`rsenv login\` in their terminal`；`vault is not initialized: ask the user to run \`rsenv init\` in their terminal`；`rejected: caller is not rsenv`（peer 拒绝）。SKILL.md 的行为约定与之一一对应。

## 4. 鉴权与安全边界

起点（当年 daemon 已实现的口径照搬）：
- token timingSafeEqual + socket 0600 同 UID；audit.jsonl 全量审计。

Rust 形态新增可达（当年 JS 做不到的）：
- Linux：SO_PEERCRED 拿真实 peer pid（内核绑定，非自报）。
- macOS：SCM_AUDIT_TOKEN / proc_pidpath——二进制形态下拿到的就是工具自身 exe，第②级「完整路径核验」真正成立。
- 第③级：Developer ID 签名 → 跨 UID 强制。

【待拍板】是否/何时上签名流程；peer pid 核验在 Linux/macOS 的具体实现与降级策略；TTL 与 lock 语义是否沿用（480min 默认 / 手动锁）。

## 5. 数据层

【待拍板】
## 5. 数据层

**已拍板（2026-11-07）**：
- B4 schema 形态 = 行式 + JSON 列：`entries(id, name UNIQUE, desc, fields_json, created_at, updated_at)`，条目为原子单位，字段寻址落 fields_json 键（`password` 对应 URI 一级）；daemon 全量加载进内存，SQL 只当存储层。原型已实现。
- **存储合并（secrets.json + vault.kdbx → 单 turso 库）**：凭据映射（含 provider URI 引用）全部进 entries 行；`$keychain` 后端配置**整个消失**（口令=login，路径=约定）；跨 provider 链式解析变为 daemon 单点内递归。「master 口令明文写配置」边界随之彻底消失。
- 语义变化（如实记录）：原 secrets.json 明文可手工编辑 → 配置进密文库后只能走 `rsenv set`/将来 add 流程，用户手工编辑通道取消；配置与凭据同锁同解锁。
- 【待拍板残留】config 类数据放 `$` 保留键还是独立 `config` 表（当前倾向后者）；guardPaths 改为从约定路径推导；KDF 档位（现原型 argon2id 19MiB/t=2）。

**元数据入库（2026-11-07 已实现）**：daemon `set` op 扩展 desc/uri——`{name, value, desc}`（native）或 `{name, uri, desc}`（provider 引用），value 与 uri 互斥（daemon 侧拒绝 + CLI 侧管道带值同拦，宁可失败）；ON CONFLICT 覆写 desc+fields_json。CLI：`printf '值' | rsenv set NAME --desc 描述` / `rsenv set NAME --uri provider://路径 --desc 描述`（uri 模式不消费 stdin）。新增 `rsenv remove NAME`（daemon DELETE + audit，不存在报 not configured）。e2e 已覆盖 desc 入库、uri 条目解析、互斥拒绝、remove 往返。add_secret / senv-mcp 的前置已解锁。

**换口令 = 闲置重加密（2026-11-07 终稿，取代信封模式）**：turso 无 rekey API。信封方案（K_data 随机密钥 + `.vault.key` AES-GCM 包裹）一度落地，用户否决——动机是绕开重加密，但引入 K_data/口令纠缠与旧库迁移问题。文件组换名方案经重新归因后复活：之前实测失败不在「改名」本身，而在**换装窗口内仍有活的库句柄**（daemon 持连接，后台 checkpoint 的 WAL 帧回写与文件置换打架；同进程先开后换也复现失败）。前提修正为「整个窗口无任何句柄存活」后成立：
- **passwd = 停 daemon（logout 自杀，句柄必然全释放）→ CLI 行级搬库**：旧口令开库读全量 entries → 新口令在侧路径 `vault.db.passwd` 建全新库写入 → 全部句柄关闭后换装（旧三件 db/wal/shm → `.bak` 三件，新三件改名就位）→ **全新子进程验证行数**（`_passwd-verify`，失败自动回滚 `.bak`）→ 按需重启 daemon（key 经 stdin 管道）
- **login/init 恢复单一天真模型**：口令派生密钥（argon2id + .vault.salt）直接加密库，验证 = 开库（打不开 = 口令错）；旧版建的库零迁移直接可用
- 守卫清单不含 `.vault.key`（文件已不存在）；临时侧路径文件（vault.db.passwd / .bak）只在 passwd 窗口内存在且 daemon 停机，不进守卫清单
- 代价如实声明：passwd 期间 daemon 停几秒（两轮 argon2id + 全量重写）；login 验证要开库（比信封慢）。换来：单一加密模型、无 K_data/口令纠缠、旧库零迁移
- e2e 已覆盖：换口令后数据/provider 条目保序、旧口令拒绝、新口令 relogin、`.bak`/侧路径文件清理、audit

**rsenv mcp（2026-11-07 已实现）**：stdio MCP 门（newline-JSON JSON-RPC 2.0，零依赖），`mcpServers` 配置 `command=rsenv, args=["mcp"]` 即接入。工具只开管理面：`rsenv_list`（条目名+desc）/ `rsenv_status`（解锁状态）；**resolve/get 类工具不开**——值永不进 MCP 通道（当年 daemon 拍板口径）。locked/daemon 缺失的 tool result 带 `rsenv login` 指引（agent-actionable 口径与 CLI 一致）。e2e：握手、tools/list、条目返回、无值泄漏、无 get 工具。

## 5.1 provider 解析层（2026-11-07 原型已实现）

**定位**：daemon 内的 URI 分发层——`get`/`inject` 查到 `fields_json.uri` 时按 scheme 分发，外部 provider 全部是「daemon 进程内子进程外调」，值不离开 daemon，只走注入/回包通道。这延续了 JS 版 provider 全子进程的格局，只是调用点从钩子进程挪进 daemon（结构性变化：同 UID 不可见进程表暴露，回包受 peer-exe 门保护）。

- **native**：turso 本库 `fields_json.password` 直取（内置密钥库，即原 keychain:// 的转正形态；存储合并后 kdbx 消失，`keychain://` 这个 scheme 不再存在，迁移工具把旧条目转 native 行）
- **viking://\<path\>**：子进程 `ov privacy resolve \<path\>`，输出 9 行元数据表、真值只在 value 行（空格对齐非冒号的坑照旧，只截该行）
- **bitwarden://\<item\>[\<field\>]**：子进程 `bw get \<field\> \<item\>`（field 默认 password），调前先解析库内 `BW_SESSION` 条目注入子进程 env——两级链式解析从 JS 版 resolveValue 跨 provider 调用链变成 daemon 单点内递归
- **onepassword://\<item\>[\<field\>]**：子进程 `op item get \<item\> --fields \<field\>`，session=库内 `OP_SESSION` 条目经 `--session` argv 传（**与 JS 版同等妥协，挂账**：op 的 session env 变量名带账号 shorthand 无法静态确定，真机探测后改 env 注入）；无 OP_SESSION 条目时依赖 biometric。totp 字段显式拒绝
- **递归深度上限 4**：URI 指向条目可再指向 URI，环引用宁可失败
- **宁可失败**：CLI 缺失 / 非零退出 / 未知 scheme / value 行缺失都显式报错并附可用条目清单；inject 对部分失败返回全部错误明细而非静默缺省
- e2e 已覆盖：viking 直连、bitwarden 两级链（BW_SESSION 条目→子进程 env）、op session 传递、未知 scheme 拒绝、inject 携带解析值

**功能性探讨项（不作为立即支持目标）**：totp——bitwarden 通道现成（`bw get totp` 官方生成，通用 field 分发天然覆盖）；op 的 TOTP 返回形态当年未真机验证故挂账；daemon 形态下 totp 无新增暴露面。待真机后一行补齐。file://（Rust aes-gcm）、kdbx 直读同理挂账。

## 5.2 bash 命令守卫与注入通道（2026-11-07 定稿：parse / inject / run 三分法）

**分层定稿（用户口径）**：与数据/密钥相关的功能集中在 daemon 内（取值、存储、provider、审计、槽位——标准明确）；与用户界面、agent 支持相关的功能集中在插件壳侧（各宿主 payload 翻译、协议 JSON——灵活多变，daemon 接口不因宿主膨胀）。rsenv 无宿主专用子命令。

**子命令三分（用户定稿）**：
- **parse**（钩子时刻，daemon op）：stdin `{"command"}` → 守卫判定（文件提及/单引号/倾泻黑名单）+ 解析全部值（provider 链在 daemon 内跑完，失败当场拒绝附可用清单）→ **签发一次性 token**（值存 daemon 内存槽位，不出 daemon）。输出 `{action: pass|inject|reject, token?, names?}`，reject exit 2。
- **inject**（运行时刻，daemon op=redeem）：`rsenv inject <token>` → 槽位消费一次（即删，无过期概念）→ stdout 输出 `export NAME='值'` 行，由同 shell 的 `eval` 消费，为同一次 bash 调用内的后续指令注入。**无 token 裸调 = 死命令**（daemon 拒绝）。
- **run**（运行时刻）：自己 spawn 子进程精确注入（env_clear+白名单），用户手动执行器，不动。

**注入槽位设计（用户定稿，讨论收敛）**：
- env 文件废除；槽位 = daemon 内存 `HashMap<token, (env_map, 签发时刻)>`。不走 turso 表——秒级临时物不进持久层，值活不过会话由结构保证（daemon 退出即消失），logout 全清。
- token 语义 = **消费一次**（redeem 即删）；GC 周期 10s 只回收未消费残留（权限框停留超时等场景），起 TTL 之效但非访问控制；GC 只清 age≥10s，新槽位必然存活。
- 改写命令形态（JS 壳拼）：`_rse_inj="$(rsenv inject <token>)" && eval "$_rse_inj" && { 原命令; }`——`&&` 链保 fail-closed：token 已消费/GC 回收/daemon 重启 → redeem 失败 → 短路 → 原命令不执行。
- token 可见于命令文本（tool result/权限框），但一次性消费使事后重放不可能；消费前的并发抢取 = 同 UID 恶意进程 = §7 停线外。**TTL 式可重复使用的 token 方案已否决**（持有物鉴权，§7 同理）。
- 残余面如实声明：agent 写 `echo $GH_TOKEN` 等命令让值进 stdout → 进上下文——恶意 agent 属超出保护目标档，与旧版同等，不设防。

- 引用扫描：`$NAME`/`${NAME}`（NAME ∈ 已配置清单才命中；`{{secret:X}}` 挂账）；单引号内引用 → 整条拒绝；倾泻黑名单 = 含引用 且 命令位置有倾泻意图（printenv/set/export 带引用参数照拦；裸 env 拦；`env VAR=x cmd` 与无引用裸 env 不拦——跨调用全新 shell 口径）。
- e2e 已覆盖：pass 旁路、token 签发+eval 链注入、一次性消费、GC 回收、裸调拒绝、单引号/dump/文件提及拒绝、ZCode 壳四断言。

**ZCode 适配（已切换）**：`adapters/zcode/hooks/secret-env-zcode.mjs` 单壳双模式（session-start / pretooluse），hooks.json 三条钩子全指向壳脚本；SessionStart 文案在壳内拼（素材=info 快照 entries）；CLI 不在 PATH/门报错 → 拒绝不静默放行。已 cp 至安装缓存与本地市场源。

**opencode 适配（2026-11-07 已切换）**：`adapters/opencode/index.ts` 的 `execute.before` 改调 `rsenv parse`（stdin `{command}`，stdout `{action, token?, reason?}`；inject → 拼同样的 eval 链改写命令，pass → 旁路，reject → 抛错）。CLI 不在 PATH / 无判定输出 → 抛错（宁可失败，不静默旁路）；`cliParse` 导出供离线回归（`adapters/opencode/tests/parse.test.ts`，bun 直跑 TS，假 rsenv 三态 + missing-CLI 子进程断言——BIN 在 import 时捕获 SENV_BIN，进程内改环境变量无效，故 missing 用例必须独立进程）。挂账不变：opencode 读写文件守卫仍未实现（工具入参字段名待核实）；包内 skill 副本仍指向旧 JS 版 SKILL.md，rsenv SKILL.md 改稿后统一换装。

**DSH 适配（2026-11-07 已切换）**：`adapters/dsh/` 协议客户端改 rsenv——`client.mjs` 的 `inject`→`parse`（bin 默认 `rsenv`，SENV_BIN 覆盖），`index.js` 的 `tools/execute` wrapper：`parse` inject 回复 → 改写 eval 链（同款 fail-closed），pass 旁路，reject/CLI 故障抛错（宁可失败）；`buildSnapshot` 映射 rsenv info 形态（`guard_paths` + `entries{name,desc}`，DSH 无 aliases）；`guards.mjs` 文案换 rsenv 口径（保护对象=vault.db/.vault.salt/audit.jsonl/daemon.sock）。**挂账：add_secret 工具未迁移**——rsenv 尚无元数据入库子命令（set 只收名字+值），等 add 流程成型（entry.mjs 文案保留未删）。离线回归 `adapters/dsh/tests/apply.test.mjs`（假 client+假 ctx：快照构建/改写三态/文件守卫/清单文案）。附带清理：rsenv info 的 `guard_prefixes`（env 文件时代 `env-inject-` 死规则）删除，ZCode 壳同步去掉该依赖并已 cp 缓存+市场源。

## 6. 与 JS 版（secret-env npm 包）的关系

**已拍板（A1=②继任者）**：同一产品换引擎，保留对外概念（provider、URI 寻址、注入钩子）；CLI 命令名沿用口径待最终定（原型暂名 `rsenv`）。迁移 = 一次性导入（kdbx 条目 + secrets.json 映射 → turso），用户提供旧库口令一次。

【待拍板残留】宿主适配器（hooks.json / opencode / DSH bundle）何时切换到新 CLI；两套系统并存期口径。

## 7. 威胁模型定稿（2026-11-07）

用户定调：**防御必须锚定「保护目标内的攻击者能力」，超出即不做**。攻击能力阶梯对照：

| 攻击者能力 | 是否在保护目标内 |
|---|---|
| 远程/网络攻击者 | ✅（无网络面：本地 unix socket） |
| 另一 UID 的本地进程 | ✅（0600 socket，内核强制） |
| 同 UID 的非 rsenv 程序（python3/脚本/任意二进制） | ✅（**连接级 peer-exe 实查拒绝**，e2e 已验证） |
| 同 UID 恶意进程（exec rsenv 伪装） | ❌ **超出目标**——已与用户同权限，OS 级边界失守不属于应用层防御领域 |

设计停线（2026-11-07 二次修订，用户定调）：**socket 0600 + 连接级 peer-exe 实查 + 宁可失败**，**无 token 文件**。

- token 方案已废除，理由（用户点破）：token 是「持有物」鉴权，持有可转移——任何同 UID 程序读了 agent.token 就能冒充客户端，**等于亲手给非 rsenv 程序开了调用 daemon 的通道**；它不增加安全能力，反而是漏洞面。
- peer-exe 鉴权 = 「身份」鉴权不可转移：连接 accept 时内核实查对端（macOS `LOCAL_PEERPID`→`proc_pidpath`；Linux `SO_PEERCRED`→`/proc/<pid>/exe`），exe 非本二进制即拒（e2e 有 python3 攻击者模拟断言）。这把当年 JS 版不可达的 peer 核验从「审计增强」升级为**主鉴权门**——Rust FFI 直达内核凭据是形态红利。
- 残余风险如实声明：同 UID 进程 exec rsenv 二进制再发请求可过 peer-exe 检——已定调超出保护目标，不设防；签名体系不立项。
- 不依赖任何隐蔽性（开源口径下全部机制公开，安全靠内核强制 + 密码学本身，Kerckhoffs 原则）。

同构结论：login 保护 at-rest 数据文件与 UID 边界外的误用；**不保护登录态下同 UID 恶意进程的取值**。缓解=即用即 logout；审计日志已实现（audit.jsonl 0600：daemon-start/get/set/logout/peer-rejected，只记事件与名字永不记值，e2e 断言无值泄漏）；**TTL 自杀不做（2026-11-07 用户定调）**——夜间长任务会被掐断，夜间攻击同 UID 持续能力同样超出保护目标等级，logout「即用即走」已覆盖敏感窗口管理。
