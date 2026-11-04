# zcode-plugin-secret-env

ZCode 插件：**密钥从私有库直达 Bash 子进程环境，模型上下文只见占位符/变量名，永不见值。**

## 机制

PreToolUse(Bash) 钩子扫描命令文本中的**显式引用**（`{{secret:NAME}}` 占位符或已配置的周知 `$VAR`），经 provider 解出真值写入 0600 临时 env 文件，命令改写为 `. <envfile>; <引用替换为 ${ZCODE_SECRET_n}>` 后放行。文本与值分离——审计日志只见 env 文件路径。

- **provider**：`keychain://`（macOS 钥匙串）/ `viking://`（OpenViking privacy 层，`ov privacy resolve`）/ `bitwarden://`（Bitwarden CLI）
- **dump 黑名单**：本会话注入过密钥后，`env` / `printenv` / `set` / `export` 直接拒绝
- **单引号禁忌**：引用落在单引号内不会被展开 → 整条命令拒绝（宁可失败，不做魔法）
- **显式化约定**：钩子是纯文本扫描的机械层；工具隐式消费环境变量（如裸 `gh pr list` 读 `GH_TOKEN`）由模型按 skill 引导显式写成 `GH_TOKEN=$GH_TOKEN gh pr list`

## 安装

ZCode → Plugin Marketplace → Add Marketplace 粘贴本仓库根路径（市场根 = 仓库根）→ Install **secret-env**。

## 配置

`~/.config/secret-env/secrets.json`（700 目录 / 600 文件；放插件目录外——安装缓存是快照，refresh 即覆盖）：

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
