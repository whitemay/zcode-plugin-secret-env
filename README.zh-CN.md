# zcode-plugin-secret-env

ZCode 插件：**密钥从私有库直达 Bash 子进程环境，模型上下文只见占位符/变量名，永不见值。**

简体中文 | [English](./README.md)

## 缘起

OpenViking 的 privacy 区域是密钥的理想存放地，但通过 `{{ov_privacy:...}}` 占位符消费密钥时，MCP 侧（`privacy_resolve`）解析出明文后**必然回流到模型上下文与会话记录**——存储端做得再严，消费端这一步就把值泄给了模型。本项目就是为了堵上这个缺口：密钥从 privacy 区域直达 Bash 子进程环境，解析链路完全绕开模型上下文。

## 机制

PreToolUse(Bash) 钩子扫描命令文本中的**显式引用**（`{{secret:NAME}}` 占位符或已配置的周知 `$VAR`），经 provider 解出真值写入 0600 临时 env 文件（按命令中实际引用的名字 export，即周知原名），命令仅加 source 前缀后放行：`. <envfile>; <原命令>`。命令文本零改写；隐式读环境变量的场景由 skill 引导 agent 显式化引用来触发。文本与值分离——审计日志只见 env 文件路径。

- **provider**：`keychain://`（macOS 钥匙串）/ `viking://`（OpenViking privacy 层，`ov privacy resolve`）/ `bitwarden://`（Bitwarden CLI）
- **dump 黑名单**：命令同时含密钥引用与倾泻意图（`env` / `printenv` / 裸 `set` / 裸 `export`）才拒绝
- **单引号禁忌**：引用落在单引号内不会被展开 → 整条命令拒绝（宁可失败，不做魔法）
- **显式化约定**：钩子是纯文本扫描的机械层；工具隐式消费环境变量（如裸 `gh pr list` 读 `GH_TOKEN`）由模型按 skill 引导显式写成 `GH_TOKEN=$GH_TOKEN gh pr list`

## 安装

本项目是 npm 包 + 各宿主薄壳。全局命令（真身）：

```bash
bun link   # 仓库内执行，注册 secret-env 全局命令（或 npm i -g .）
```

ZCode 壳：Plugin Marketplace → Add Marketplace 粘贴本仓库根 → Install **secret-env**（hooks.json 指向全局命令）。

凭据入库（用户终端执行，隐藏输入，值不经对话）：

```bash
secret-env add GH_TOKEN --provider keychain --desc 'GitHub 令牌' --alias GITHUB_TOKEN
secret-env list
```

## 配置

`~/.config/secret-env/secrets.json`（700 目录 / 600 文件；`secret-env add` 自动维护，也可手写）：

```json
{
  "GH_TOKEN": { "uri": "viking://credential/github-token/token" },
  "OPENAI_API_KEY": { "uri": "keychain://zcode-openai", "aliases": ["OPENAI_KEY"] }
}
```

模板见 [secret-env/secrets.example.json](./secret-env/secrets.example.json)。配置为空时钩子纯旁路。

## 已知边界（诚实声明）

- **出口无脱敏**：ZCode PostToolUse 输出无 tool_result 改写能力（harness 源码核查定案），`echo $GH_TOKEN` 这类值回流无自动防线，靠 skill 明令禁止
- **依赖 skill 引导质量**：模型没写显式引用时注入不生效——设计如此，宁可失败
- viking:// provider 依赖 `ov` CLI（≥0.5.1）与本地 OpenViking 服务

设计沿革与机制验证记录见 [docs/DESIGN.md](./docs/DESIGN.md)。
