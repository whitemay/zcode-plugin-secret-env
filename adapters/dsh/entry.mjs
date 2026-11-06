// DSH 登记条目的纯逻辑：消息/选项文案与答案解释（参数/命令构造已收敛到仓库根 entry.mjs，三端共用）。
import { PROVIDERS, buildEntryOpts, entryCommandText } from "../../entry.mjs";
export { PROVIDERS, buildEntryOpts, entryCommandText };

const lang = (() => {
  const l = process.env.LC_ALL ?? process.env.LANG ?? "";
  return l.toLowerCase().startsWith("zh") ? "zh" : "en";
})();

export const T = {
  zh: {
    toolDescription:
      "会话内交互登记新凭据：元数据由本工具入参传入；密钥值由宿主问答卡片直接向用户收集并写入凭据库，永远不进入模型上下文——不要试图把密钥值作为参数传入，也不要让用户发给你。返回 status：stored=已入库 / command-issued=已给出终端命令 / declined=用户取消 / invalid=元数据有误 / error=执行失败。",
    paramName: "人读名（如 github token），归一化为全大写下划线环境变量名",
    paramProvider: "keychain（默认）/ bitwarden / viking / onepassword",
    paramDetail: "条目定位：bitwarden/onepassword=条目名[/字段]；viking=类目/目标[/字段]；keychain 留空自动命名",
    paramAlias: "别名（可选，逗号分隔）",
    paramDescription: "描述（可选。会进入模型上下文，不得含敏感信息）",
    cardHeader: "录入密钥值",
    cardQuestion:
      "secret-env 新条目登记：请选择密钥值录入方式。\n\n注意：这里提交的内容会原样写入凭据库、不经过模型，因此必须直接填写密钥本身——不要填名字、描述、占位符或「我的 token」之类的说明（模型无法校验或补全）。\n\n· 直接填写：在下方输入框填写密钥值——值明文显示在卡片中（介意旁观/录屏请改选命令行），提交后直接写入凭据库，不会进入模型上下文。\n· 命令行：选择「我希望通过命令行来完成输入」，我会给你一条在终端执行的命令（隐藏输入）。",
    commandLabel: "我希望通过命令行来完成输入",
    commandDescription: "随后给出一条 senv add 命令，在终端执行时隐藏输入密钥值。",
    missingName: "缺少 name（归一化后为空）",
    badProvider: `provider 只能是 ${PROVIDERS.join(" / ")}`,
    exists: "已存在同名条目，请换名后重调（维护已有条目请在终端用 senv add 不带 --provider）",
    noAgent: "无法定位调用方 agent，不能弹问答卡片",
  },
  en: {
    toolDescription:
      "Register a new credential interactively in this session: metadata comes from the tool arguments; the secret value is collected by the host's question card and written straight to the credential store — it never enters model context. Do not pass the secret value as an argument or ask the user to send it. Returns status: stored / command-issued / declined / invalid / error.",
    paramName: "Human-readable name (e.g. github token); normalized to UPPER_SNAKE env var",
    paramProvider: "keychain (default) / bitwarden / viking / onepassword",
    paramDetail: "Entry locator: bitwarden/onepassword=item[/field]; viking=category/target[/field]; keychain=leave blank",
    paramAlias: "Aliases (optional, comma-separated)",
    paramDescription: "Description (optional; enters model context — no sensitive info)",
    cardHeader: "Enter the secret value",
    cardQuestion:
      "secret-env new entry: choose how to enter the secret.\n\nNote: whatever is submitted here is written straight to the credential store without passing through the model, so it must be the secret value itself — not a name, description, placeholder, or note like \"my token\" (the model cannot validate or complete it).\n\n· Type it: fill the field below — the value is visible on the card (avoid if others can see your screen), and is written straight to the credential store without entering model context.\n· Command line: choose \"I'll enter it via the command line\" to get a command for your terminal (hidden input).",
    commandLabel: "I'll enter it via the command line",
    commandDescription: "Returns a senv add command that hides the input in your terminal.",
    missingName: "Missing name (empty after normalization)",
    badProvider: `provider must be one of ${PROVIDERS.join(" / ")}`,
    exists: "An entry with this name already exists — pick another name (to maintain an existing entry run senv add without --provider)",
    noAgent: "Cannot resolve the calling agent; the question card is unavailable",
  },
}[lang];

// 单选问答：custom 覆盖 selected（DSH 语义）。返回 value / command / declined。
export function interpretAnswer(item, commandLabel) {
  const custom = typeof item?.custom === "string" ? item.custom.trim() : "";
  if (custom !== "") return { kind: "value", value: custom };
  const selected = Array.isArray(item?.selected) ? item.selected : [];
  if (selected.includes(commandLabel)) return { kind: "command" };
  return { kind: "declined" };
}
