# ZCode 分支：senv-mcp 的 add_secret（表单收值）

适用前提：宿主是 ZCode（`ZCODE_APP_VERSION` 存在），且工具列表里有 `add_secret`（senv-mcp，由 ZCode 插件壳 `.zcode-plugin/plugin.json` 的 `mcpServers` 声明）。工具不可用时回到 SKILL.md 的默认兜底（构造 `senv add` 命令交终端）。

## 流程

**第 1 步：元数据问答**——同 SKILL.md 的「第 1 步」，用 ZCode 的 `AskUserQuestion` 一次问清 key / desc / provider 三题，解析成定稿（name + 别名 / 描述 / provider / 条目定位）。

**第 2 步：调用 `add_secret`** 传定稿入参（`name` 必填；`provider` / `detail` / `alias` / `description` 可选）。

工具随后弹收值卡：

- 输入框收密钥（输入时可见，但**不进入模型上下文**）；
- 用户若选「手工通过命令行输入」或取消，返回里带现成 `command`——转交用户在终端执行即可。**`declined` 不是失败**，是用户选了终端通道；
- 返回 `status:"invalid"` 时按 `message` 里的原因（缺名 / 重名 / provider 非法）回到第 1 步重问；
- `status:"stored"` 即收尾。

## 要点

- 密钥值永远不要作为参数传给 `add_secret`，也不要让用户发给你。
- 工具结果永远脱敏（`stored` 只带 `envName` / `uri`；`command-issued` 只带命令）。
- ZCode 支持 MCP elicitation；DSH 不支持——DSH 见 [dsh.md](dsh.md)，不要在对 DSH 的对话里调用不存在的 `add_secret`。
