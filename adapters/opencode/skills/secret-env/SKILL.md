---
name: secret-env
description: 密钥注入约定——执行需要凭据的 Bash 命令时如何让 secret-env 插件把凭据送进子进程环境（模型上下文永不见值）。写涉及 GH_TOKEN/API key/DATABASE_URL 等凭据的命令前必读。
---

# secret-env：密钥显式引用约定

本项目的密钥从私有库（Keychain / OpenViking / Bitwarden）直接注入 Bash 子进程环境。
**你（模型）从头到尾只写变量名，永远不写、也永远看不到真值。**
注入使用周知原名（如 `GH_TOKEN`），命令文本零改写——拦截层只在命令前加 source 前缀。

> 宿主适配：ZCode 的拦截层是 PreToolUse 钩子，DSH 的是 host 插件，opencode 的是 V2 插件（`execute.before` 钩子）；三者注入语义一致，下文统一称「拦截层」。

## 两条注入触发（拦截层只认显式文本）

1. **占位符**：命令文本里写 `{{secret:NAME}}`（NAME 必须已配置）
2. **显式 $VAR**：命令文本里出现已配置的周知变量名

## 铁律

- **命令里禁止写死任何密钥明文**。需要凭据时写成 `"$GH_TOKEN"` 或 `{{secret:GH_TOKEN}}`。
- **禁止单引号包引用**：`'$GH_TOKEN'` 内不会展开，拦截层会直接拒绝整条命令。一律双引号：
  ```bash
  curl -H "Authorization: Bearer $GH_TOKEN" ...
  psql "$DATABASE_URL" -c '...'
  ```
- **隐式使用必须显式化**：拦截层只扫命令文本，隐式读环境变量的工具（`gh`、`git push` 等）扫不到、不会注入。必须让命令文本出现引用，例如变量名前缀或同义别名均可——副作用都是把真值以原名送进环境：
  ```bash
  GH_TOKEN=$GH_TOKEN gh pr list          # 同名显式化
  GITHUB_TOKEN=${GH_TOKEN} git push ...  # 工具认别的名字，别名映射
  USE_TOKEN=${GH_TOKEN} some-tool ...    # 任意名字皆可，注入的仍是原名 GH_TOKEN
  ```
  注意：拦截层按命令中**实际引用的名字**注入——引用 `$GITHUB_TOKEN` 就注入 `GITHUB_TOKEN`，引用 `$GH_TOKEN` 就注入 `GH_TOKEN`。需要哪个名字就在命令里写哪个名字的引用。
- **倾泻意图放独立调用**：查看环境变量、`set -e` 选项、`export FOO=1` 这类与密钥无关的操作，放在**单独一次 Bash 调用**里，不要和带密钥引用的命令拼在同一条。原因：① 每次调用是全新 shell，注入变量不跨调用存活，独立调 `env` 看不到任何密钥，天然安全；② 同一条命令里「密钥引用 + env/printenv/裸 set/裸 export」会被拦截层直接拒绝（同命令倾泻）。
- **不要 echo/打印凭据**：`echo $GH_TOKEN` 会把值送进你的上下文（出口防线尚未实现），等于绕过整个机制。

## 已配置条目

会话启动时，宿主会把已配置的**名字清单**（含别名，无真值）注入上下文——ZCode 经 SessionStart 钩子，DSH 经系统提示 section（opencode 暂无清单注入，以 `senv list` 或 `~/.config/secret-env/secrets.json` 为准）——以那份清单为准。配置本体在 `~/.config/secret-env/secrets.json`（周知名 → {uri, aliases?}，文件里也只有名字和 uri，没有真值）。配置为空时纯旁路、什么都不注入。清单里的 `BW_SESSION` 是基础设施条目（Bitwarden vault 解锁钥匙，bitwarden:// 凭据解析时自动使用），命令中无需引用它。

用户需要接入新密钥库或添加凭据条目时，按下面的流程走（provider 准备步骤见 [references/providers.md](references/providers.md)）。

## 登记新凭据：先问答，默认交终端执行

登记分两步：**你只负责元数据，密钥值永远不经过你的上下文**。

**第 1 步：元数据问答**——用宿主自带的问答工具（ZCode 的 `AskUserQuestion`、DSH 的 `ask_user_question`；都没有时直接在对话里问），一次问清三个字段：

- **key 题**：从上下文推断 well-known 候选作为选项（同一凭据的多个周知名都列出，如 Hugging Face → `HF_TOKEN`、`HUGGINGFACE_TOKEN`，标注互为别名）；用户也可自由输入，格式 `KEY, alias1, alias2`（逗号分隔，别名可省）。问题文案须说明该格式。
- **desc 题**：选项 1=你组织的一段描述，选项 2=不需要描述。文案须警示「描述会进入模型上下文，不得含敏感信息」。
- **provider 题**：keychain（KeePassXC 库）/ bitwarden（Bitwarden）/ viking（OpenViking）/ onepassword（1Password），无从推断时默认 keychain。

用户选完由**你**把答案解析成定稿：well-known 选项→该名字+已知别名；自由输入→按逗号拆出 name 和别名。

**第 2 步（默认兜底，所有宿主可用）：构造完整导入命令，交用户在终端执行**

```bash
# 例：bitwarden 条目
senv add -n "github token" --provider bitwarden --item "GitHub" --alias gh-token --desc "GitHub PAT"
```

命令的密钥值输入是隐藏的、不经过上下文，执行完登记即完成。转交时只需要给命令 + 一句「在终端运行，按提示输入密钥值」——提醒提示符要的是密钥原值，不是名字或说明文字。

**增强分支（仅当宿主满足条件）**：部分宿主能提供表单收值（值同样不进上下文）。先判宿主，再读对应 reference（与本 SKILL.md 同目录的 `references/`）：

- 若环境存在 `ZCODE_APP_VERSION`（ZCode）→ 读 [references/zcode.md](references/zcode.md)：senv-mcp 的 `add_secret` 两问题流程。
- 若环境存在 `DSH_PROFILE`（DSH）→ 读 [references/dsh.md](references/dsh.md)：当前仍走第 2 步兜底；插件版 `add_secret` 落地后按该文档更新。
- 无法判别宿主或对应 reference 不可用（含 opencode 等其它宿主）→ 直接走第 2 步兜底。

只有 reference 明确说明「该工具可用」时才走表单路径；否则一律兜底。**不要自己发明工具参数，也不要让用户把密钥值发给你。**

## 常见配方

```bash
# GitHub
GH_TOKEN=$GH_TOKEN gh pr list
curl -s -H "Authorization: Bearer {{secret:GH_TOKEN}}" https://api.github.com/user

# 数据库
psql "$DATABASE_URL" -c '\dt'

# OpenAI
OPENAI_API_KEY={{secret:OPENAI_API_KEY}} bun run script.ts
```

## 失败即信号

拦截层报错时按提示修正命令文本（多半是单引号或未配置的名字），**不要尝试绕过拦截层**（如把值写进文件再 cat、从代码里硬编码读取）。ZCode 的报错为 exit 2 + stderr；DSH 的报错为工具错误结果。
