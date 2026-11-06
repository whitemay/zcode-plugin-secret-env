---
name: secret-env
description: 密钥注入约定——执行需要凭据的 Bash 命令时如何让 secret-env 插件把凭据送进子进程环境（模型上下文永不见值）。写涉及 GH_TOKEN/API key/DATABASE_URL 等凭据的命令前必读。
---

# secret-env：密钥显式引用约定

本项目的密钥从私有库（Keychain / OpenViking / Bitwarden）直接注入 Bash 子进程环境。
**你（模型）从头到尾只写变量名，永远不写、也永远看不到真值。**
注入使用周知原名（如 `GH_TOKEN`），命令文本零改写——钩子只在命令前加 source 前缀。

## 两条注入触发（钩子只认显式文本）

1. **占位符**：命令文本里写 `{{secret:NAME}}`（NAME 必须已配置）
2. **显式 $VAR**：命令文本里出现已配置的周知变量名

## 铁律

- **命令里禁止写死任何密钥明文**。需要凭据时写成 `"$GH_TOKEN"` 或 `{{secret:GH_TOKEN}}`。
- **禁止单引号包引用**：`'$GH_TOKEN'` 内不会展开，钩子会直接拒绝整条命令。一律双引号：
  ```bash
  curl -H "Authorization: Bearer $GH_TOKEN" ...
  psql "$DATABASE_URL" -c '...'
  ```
- **隐式使用必须显式化**：钩子只扫命令文本，隐式读环境变量的工具（`gh`、`git push` 等）扫不到、不会注入。必须让命令文本出现引用，例如变量名前缀或同义别名均可——副作用都是把真值以原名送进环境：
  ```bash
  GH_TOKEN=$GH_TOKEN gh pr list          # 同名显式化
  GITHUB_TOKEN=${GH_TOKEN} git push ...  # 工具认别的名字，别名映射
  USE_TOKEN=${GH_TOKEN} some-tool ...    # 任意名字皆可，注入的仍是原名 GH_TOKEN
  ```
  注意：钩子按命令中**实际引用的名字**注入——引用 `$GITHUB_TOKEN` 就注入 `GITHUB_TOKEN`，引用 `$GH_TOKEN` 就注入 `GH_TOKEN`。需要哪个名字就在命令里写哪个名字的引用。
- **倾泻意图放独立调用**：查看环境变量、`set -e` 选项、`export FOO=1` 这类与密钥无关的操作，放在**单独一次 Bash 调用**里，不要和带密钥引用的命令拼在同一条。原因：① 每次调用是全新 shell，注入变量不跨调用存活，独立调 `env` 看不到任何密钥，天然安全；② 同一条命令里「密钥引用 + env/printenv/裸 set/裸 export」会被钩子直接拒绝（同命令倾泻）。
- **不要 echo/打印凭据**：`echo $GH_TOKEN` 会把值送进你的上下文（出口防线尚未实现），等于绕过整个机制。

## 已配置条目

每次 session 启动时，SessionStart 钩子会把已配置的**名字清单**（含别名，无真值）自动注入上下文——以那份清单为准。配置本体在 `~/.config/secret-env/secrets.json`（周知名 → {uri, aliases?}，文件里也只有名字和 uri，没有真值）。配置为空时钩子纯旁路、什么都不注入。清单里的 `BW_SESSION` 是基础设施条目（Bitwarden vault 解锁钥匙，bitwarden:// 凭据解析时自动使用），命令中无需引用它。

用户需要接入新密钥库或添加凭据条目时，按下面的流程走（详见 [providers.md](providers.md) 各 provider 准备步骤）。

## 会话内登记新凭据（add_secret 两问题流程）

登记新条目时调用 `senv-mcp` 的 `add_secret` 工具。**密钥值由该工具经宿主表单直接向用户收集，永远不经你的上下文——不要试图把值作为参数传入或让用户发给你。** 你的职责只有元数据终审，分两步：

**第 1 步：元数据问答（用宿主自带问答工具，如 AskUserQuestion）**，一次问清三个字段：

- **key 题**：从上下文推断 well-known 候选作为选项（同一凭据的多个周知名都列出，如 Hugging Face → `HF_TOKEN`、`HUGGINGFACE_TOKEN`，标注互为别名）；用户也可自由输入，格式 `KEY, alias1, alias2`（逗号分隔，别名可省）。问题文案须说明该格式。
- **desc 题**：选项 1=你组织的一段描述，选项 2=不需要描述。文案须警示「描述会进入模型上下文，不得含敏感信息」。
- **provider 题**：keychain（KeePassXC 库）/ bitwarden / viking / onepassword，无从推断时默认 keychain。

用户选完由**你**把答案解析成定稿：well-known 选项→该名字+已知别名；自由输入→按逗号拆出 name 和别名。

**第 2 步：调用 `add_secret` 传定稿入参**（name 必填；provider/detail/alias/description 可选）。工具随后弹一张收值卡：输入框收密钥（输入时可见但**不进你的上下文**）；用户若选「手工通过命令行输入」或取消，返回里带现成 `command`——转交用户在终端执行即可，**declined 不是失败，是用户选了终端通道**。返回 `status:"invalid"` 时按 message 里的原因（缺名/重名/provider 非法）回到第 1 步重问；`stored` 即收尾。

**通用兜底（任何宿主）**：宿主无问答/表单能力时，元数据在对话里直接问，然后构造完整 `senv add` 命令（含 --provider/--alias/--desc）交给用户在终端执行——命令自带隐藏输入，登记由命令完成。

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

钩子报错（exit 2）时按提示修正命令文本（多半是单引号或未配置的名字），**不要尝试绕过钩子**（如把值写进文件再 cat、从代码里硬编码读取）。
