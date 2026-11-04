# 密钥库接入指南（面向用户/操作者）

各 provider 的准备工作与添加凭据条目的步骤。配置登记统一在 `~/.config/secret-env/secrets.json`（周知名 → {uri, aliases?, description?}，文件里只有名字和 uri，无真值）。推荐用 `secret-env add` 交互登记（值经隐藏输入，不经过 Agent 上下文）。

## URI 一般化寻址（2026-11-04 定案）

所有 provider 统一 `scheme://item[/field]`：

- **一级寻址（缺省）= 主密钥**：keychain → password；bitwarden → password；viking → 条目主值
- **二级寻址 = 次级字段**：
  - `keychain://<service>/account` — keychain account 属性（同 service 多 account 条目存在时报歧义错，不静默取第一条）
  - `viking://<category>/<target>/<field>` — privacy 条目字段（既有能力）
  - `bitwarden://<item>/username`、`/totp`、`/password` — 保留键，走 bw get 子命令；其余字段名按自定义字段在条目 `fields[]` 里按 name 匹配（保留键优先，撞名改字段名消歧）
- 字段段 URI 内不允许 `/` 与空格；bw 字段名含空格时建议改用无空格命名
- 账户信息（username/account/成对凭证的 id 侧）是 agent 真实需求（构造 DSN/`-u` 参数/成对 API 凭证），次级寻址为此而设

## keychain://（macOS 系统密钥库，本机最简）

准备：无需安装，macOS 自带 `security` 命令。

```bash
secret-env add -n "github token" --provider system            # 隐藏输入收值 → 钥匙串 → 登记
secret-env add -n "aws creds" --provider system --user "AKIA..."  # 可选：account 属性存指定值（缺省 = 当前系统用户）
```

更新值：同命令重跑覆盖（`--provider system` 对已存在条目强制重新收值；不带则进维护模式只改别名/描述）。

## viking://（OpenViking privacy 层，跨设备）

准备：`ov` CLI 已配置（`~/.openviking/ovcli.conf`）且服务可达。

写侧自治：`add` 收值后经 `ov privacy upsert` 写入（值走 0600 临时文件，不落 argv），再登记映射：

```bash
secret-env add -n openai --provider viking --path credential/openai/api_key   # 收值 → 写 privacy 字段 → 登记
secret-env add -n openai --provider viking --path credential/openai           # 无 field 段：主值落 value 字段
```

更新值：同命令重跑覆盖，或直接在 ov 侧更新（secrets.json 不动）。

## bitwarden://（Bitwarden CLI，跨设备/团队共享）

准备（一次性）：

```bash
npm i -g @bitwarden/cli        # 或 brew install bitwarden-cli
bw login                       # 登录（自建服务器先 bw config server <url>）
bw unlock                      # 解锁，末尾输出 export BW_SESSION="..."
```

登记 BW_SESSION（两级解析的基础设施条目，session key 存钥匙串）：

```bash
security add-generic-password -U -s bw-session -a "$USER" -w
# 交互提示时粘贴 unlock 输出里引号内的 session key（不带引号）
```

secrets.json 中登记 `"BW_SESSION": { "uri": "keychain://bw-session" }`（读写任何 bitwarden:// 条目时自动经配置链解析并注入 bw 子进程环境；其 uri 不可为 bitwarden://）。

写侧自治：`add` 收值后经 bw 写入 vault（JSON 走 stdin，不落 argv），再登记映射：

```bash
secret-env add -n myvar --provider bitwarden --item "条目名"            # 收值 → password 位（条目不存在则新建 login 条目）
secret-env add -n myvar.key --provider bitwarden --item "条目名" --field "api key"   # 收值 → 自定义字段（条目须已存在）
secret-env add -n myvar --provider bitwarden --item "条目名" --user "someone"        # 顺路写 username 位
```

要点：

- 写的落位与读镜像：password 位 ↔ 一级寻址；`--field`/username ↔ 二级寻址；`--field` 不隐式建条目
- 条目名需唯一；重名条目用 id（`bw get item <名> | jq -r .id` 查，界面里 Web Vault 地址栏 `itemId=` 可见）
- 名字含空格/中文无需转义（字段名含空格不建议用于 URI）
- **session key 生命周期**：每次 `bw unlock` 换新值 → 重跑上面的 `security add-generic-password` 覆盖；过期后 bitwarden 凭据读写报 bw 原始错误（locked/not unlocked 字样即此因）

## 验证

配置后在新命令里引用（值不出现在输出）：

```bash
printf '%s' "$MY_VAR" | wc -c    # 长度非 0 即注入成功
```

清单核对：`secret-env list`（显示名字与 uri，无真值）。
