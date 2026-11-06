# DSH 分支：问答卡片直接消费（不走 MCP elicitation）

适用前提：宿主是 DSH（`DSH_PROFILE` 存在；系统提示里出现 secret-env 已配置清单，即由 DSH host 插件注入）。

## 设计

DSH 的收值路径是**插件内部调用问答卡片**，不是 MCP：

```
模型 → DSH 插件工具 add_secret（只传元数据）
     → 插件 ctx.userQuestions.ask() 弹卡片（用户输入密钥值）
     → 答案回到插件代码，程序化消费（写 keychain / Bitwarden / viking + 登记 secrets.json）
     → 工具结果只返回 { status, envName, uri }（脱敏，值不进模型上下文）
```

- **不用 MCP elicitation**：DSH 的 MCP 客户端不声明 elicitation 能力；`senv mcp` 的 `add_secret` 在 DSH 不可用。
- **即使将来经 MCP**：也不会用「提供选项」的 elicitation，而是由程序调用另一个 MCP 工具直接消费输入值。
- 卡片是无掩码文本输入：值在屏幕上可见，但**不进入模型上下文**；工具结果永远脱敏。

## 工具 `add_secret`（已实现）

参数（全部元数据，由模型在第 1 步问答后传入）：

| 参数 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 人读名（归一化为全大写下划线环境变量名） |
| `provider` | 否 | keychain / bitwarden / viking / onepassword（默认 keychain） |
| `detail` | 否 | bitwarden/onepassword 条目名[/字段]；viking=类目/目标[/字段]；keychain 留空自动命名 |
| `alias` | 否 | 别名，逗号分隔 |
| `description` | 否 | 描述（会进模型上下文，不得含敏感信息） |

执行：名称归一化 + 重名校验（不合法直接返回 `invalid`，不弹卡）→ `ctx.userQuestions.ask()` 弹收值卡 → 程序化入库。

返回（永不含值）：

- `{ status: "stored", envName, uri }`
- `{ status: "command-issued", command }`（用户在卡片里选了命令行）
- `{ status: "declined" }`（用户取消/跳过；不是失败。若用户直接关闭卡片面板，宿主可能把整个工具调用标记为 aborted——同样未落库）
- `{ status: "invalid", message }`（缺名/重名/provider 非法）
- `{ status: "error", message }`（入库失败等）

## 卡片交互

**必须填原值**：卡片提交的内容会原样写入凭据库、不经过模型——用户必须直接填密钥本身，不能填名字、描述、占位符或说明文字（否则这些文字会被当成密钥存进去，模型也无法校验或补全）。

一张卡，两个输入位置：

1. **显式选项**「我希望通过命令行来完成输入」——选中即返回 `command-issued`，给用户在终端执行的命令（隐藏输入）；
2. 卡片自动附加的**自由输入行**——用户在这里填密钥值，提交后直接入库。

判断规则（单选：`custom` 覆盖 `selected`）：

- `custom` 非空 → 消费该值，入库，返回 `stored`
- `custom` 为空且 `selected` 含命令行选项 → 返回命令
- 两者都空 → `declined`

这对应 ZCode 版第 2 屏形态裁断：ZCode 先试 password 掩码表单、被拒后降级到「命令 / 明文表单」选择屏；DSH 没有密码掩码形态，用「选项 + 自定义输入」一张卡完成同样的分流。

## 兜底

若 `add_secret` 工具不可用（旧版插件/安装异常），登记回到 SKILL.md 的默认路径：问完元数据后构造完整 `senv add ...` 命令交用户在终端执行。
