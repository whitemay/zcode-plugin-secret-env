# opencode 分支：senv-mcp 的 add_secret（表单收值）

适用前提：宿主是 opencode，且工具列表里有 `add_secret`（senv-mcp，由插件 `ctx.mcp.transform` 注册）。工具不可用时回到 SKILL.md 的默认兜底（构造 `senv add` 命令交终端）。

## 流程

**第 1 步：元数据问答**——同 SKILL.md 的「第 1 步」，opencode 无原生问答卡片，直接在对话里一次问清 key / desc / provider 三题，解析成定稿（name + 别名 / 描述 / provider / 条目定位）。

**第 2 步：调用 `add_secret`** 传定稿入参（`name` 必填；`provider` / `detail` / `alias` / `description` 可选）。

工具随后弹 MCP elicitation 收值表单：

- 输入框收密钥（输入时可见，但**不进入模型上下文**）；
- 用户若选「手工通过命令行输入」或取消，返回里带现成 `command`——转交用户在终端执行即可。**`declined` 不是失败**，是用户选了终端通道；
- 返回 `status:"invalid"` 时按 `message` 里的原因（缺名 / 重名 / provider 非法）回到第 1 步重问；
- `status:"stored"` 即收尾。

## 要点

- 密钥值永远不要作为参数传给 `add_secret`，也不要让用户发给你。
- 工具结果永远脱敏（`stored` 只带 `envName` / `uri`；`command-issued` 只带命令）。
- opencode 的 skill 与 MCP 由插件程序化注册（宿主不自动发现插件包内 skills/）；工具列表看不到 `add_secret` 说明宿主侧未接 senv-mcp，走兜底。
