# rsenv — secret-env 的 Rust 后端（可选）

rsenv 是 secret-env 的**可选后端实现**：Rust 单二进制 + turso 加密库 + 守护加密库的 daemon（login 生命周期）。它与本仓库缺省后端 `senv`（bun/node CLI，keepassxc + secrets.json）实现**同一宿主协议**（[../../docs/HOST-PROTOCOL.md](../../docs/HOST-PROTOCOL.md)），ZCode / opencode / DSH 三端插件按协议匹配、不按二进制名分支。

用户向的主文档见仓库根 [README.zh-CN.md](../../README.zh-CN.md)（按 senv 组织）；本文件只讲 rsenv 特有的部分。

## 安装

```bash
cargo install --path rust/rsenv   # 仓库内构建安装
# 或发布后：cargo install rsenv
```

## 启用

装好后**缺省不生效**（解析链缺省 senv 优先）。二选一：

```bashrc
# 方式一：secrets.json 顶层加 $backend 键（持久）
{ "$backend": "rsenv", ... }

# 方式二：环境变量（临时/覆盖，优先级最高）
export SENV_BIN="$(which rsenv)"
```

## 与 senv 的差异

| 能力 | rsenv | senv（缺省） |
|---|---|---|
| 存储 | turso 加密库（AES，daemon 内存密钥） | keepassxc（kdbx）+ secrets.json 映射 |
| daemon | 守护加密库 + token 槽，`rsenv login` 拉起 | 纯 token 内存槽，parse 按需自动拉起，无 login |
| 生命周期 | `init` / `login` / `logout` / `passwd`（闲置重加密） | 无（`passwd` 挂账） |
| 宿主外注入 | `rsenv run NAME... -- cmd args` | 无（走各自 provider 工具） |
| 迁移 | `rsenv import-secrets [路径]`（旧 secrets.json） | `senv set NAME --uri …` |

共有部分（注入链、守卫行为、agent 行为约定）见 SKILL.md 与主 README——两个后端语义一致。

## rsenv run — agent 宿主之外的注入通道

宿主之外——裸终端、脚本、cron、launchd/systemd 服务——用 `run` 具名注入执行器：stdio 继承、退出码透传，值不出现在命令行、rc 文件、shell 历史。

```bash
rsenv run GH_TOKEN -- gh pr list              # 解析单条并执行
rsenv run GH_TOKEN BW_SESSION -- ./deploy.sh  # 一次注入多条
rsenv run DEEPSEEK_API_KEY -- pi              # 带着密钥环境启动一个 agent 宿主
```

常驻服务可用作启动入口（systemd `ExecStart=/usr/local/bin/rsenv run BW_SESSION -- my-service`），服务定义文件不落明文。

## daemon 生命周期

- `rsenv init`：仅首次建库（终端交互设口令）；`rsenv login`：解锁并拉起 daemon（幂等，**请在完整用户 shell 里执行**——provider 工具环境继承 login 终端的 PATH）。
- CLI 不会自行拉起 daemon：不在时取值命令失败，错误信息含恢复指令。
- `rsenv logout`：清 key 与槽位、停 daemon；`rsenv passwd`：换口令（闲置重加密，失败自动回滚）。
