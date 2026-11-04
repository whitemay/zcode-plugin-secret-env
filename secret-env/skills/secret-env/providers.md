# 密钥库接入指南（面向用户/操作者）

各 provider 的准备工作与添加凭据条目的步骤。配置登记统一在 `~/.config/secret-env/secrets.json`（周知名 → {uri, aliases?, description?}，文件里只有名字和 uri，无真值）。推荐用 `secret-env add` 交互登记（值经隐藏输入，不经过 Agent 上下文）。

## keychain://（macOS 系统密钥库，本机最简）

准备：无需安装，macOS 自带 `security` 命令。

```bash
secret-env add -n "github token" --provider system            # 隐藏输入收值，自动登记
# 等价裸命令：security add-generic-password -U -s <service> -a "$USER" -w
```

更新值：同命令重跑覆盖（`--provider system` 对已存在条目强制重新收值；不带则进维护模式只改别名/描述）。

## viking://（OpenViking privacy 层，跨设备）

准备：`ov` CLI 已配置（`~/.openviking/ovcli.conf`）且服务可达。

值由用户自行放入 privacy 区域（不经对话），secret-env 只登记映射：

```bash
ov privacy upsert credential openai --field-api_key sk-...   # 用户自行存值（值勿经对话）
secret-env add -n openai --provider viking --path credential/openai/api_key
```

更新值：在 ov 侧更新 privacy 条目即可，secrets.json 不动。

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

secrets.json 中登记 `"BW_SESSION": { "uri": "keychain://bw-session" }`（有本条时，解析任何 bitwarden:// 凭据会自动取它注入 bw 子进程环境；其 uri 不可为 bitwarden://）。

登记凭据：

```bash
secret-env add -n myvar --provider bitwarden --item "条目名"
```

要点：

- 只取 **login 条目的 password 字段**（username/notes/自定义字段取不到）
- 条目名需唯一；重名条目用 id（`bw get item <名> | jq -r .id` 查，界面里 Web Vault 地址栏 `itemId=` 可见）
- 名字含空格/中文无需转义
- **session key 生命周期**：每次 `bw unlock` 换新值 → 重跑上面的 `security add-generic-password` 覆盖；过期后 bitwarden 凭据解析报 bw 原始错误（locked/not unlocked 字样即此因）

## 验证

配置后在新命令里引用（值不出现在输出）：

```bash
printf '%s' "$MY_VAR" | wc -c    # 长度非 0 即注入成功
```

清单核对：`secret-env list`（显示名字与 uri，无真值）。
