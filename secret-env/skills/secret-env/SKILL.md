---
name: secret-env
description: 密钥注入约定——执行需要凭据的 Bash 命令时如何让 secret-env 插件把凭据送进子进程环境（模型上下文永不见值）。写涉及 GH_TOKEN/API key/DATABASE_URL 等凭据的命令前必读。
---

# secret-env：密钥显式引用约定

本项目的密钥从私有库（Keychain / OpenViking / Bitwarden）直接注入 Bash 子进程环境。
**你（模型）从头到尾只写变量名，永远不写、也永远看不到真值。**

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
- **工具隐式读环境变量时，必须显式化**：裸 `gh pr list` 自己读 `GH_TOKEN`，钩子扫不到。必须写成：
  ```bash
  GH_TOKEN=$GH_TOKEN gh pr list
  ```
- **倾泻意图放独立调用**：查看环境变量、`set -e` 选项、`export FOO=1` 这类与密钥无关的操作，放在**单独一次 Bash 调用**里，不要和带密钥引用的命令拼在同一条。原因：① 每次调用是全新 shell，独立调 `env` 看不到注入的 `ZCODE_SECRET_*`，天然安全；② 同一条命令里「密钥引用 + env/printenv/裸 set/裸 export」会被钩子直接拒绝（同命令倾泻）。也不要在倾泻命令里围绕 `ZCODE_SECRET`/`zcode` 词根探测或 grep。
- **不要 echo/打印凭据**：`echo $GH_TOKEN` 会把值送进你的上下文（出口防线尚未实现），等于绕过整个机制。

## 已配置条目

配置在 `~/.config/secret-env/secrets.json`（周知名 → {uri, aliases?}）。配置为空时钩子纯旁路、什么都不注入。

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
