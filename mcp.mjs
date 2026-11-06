#!/usr/bin/env node
// secret-env MCP server（stdio）。会话内交互入库：elicitation 表单直达本进程 → provider，值不经模型上下文。
// 两问题拆解（2026-11-06 定案）：① 非敏感元数据（key/alias/desc/provider）由 agent 经宿主原生问答
//   （ZCode AskUserQuestion / DSH ask_user_question）终审后经 add_secret 入参传入——这些值本就公开，
//   进上下文无害；server 不再做第 1 屏表单，校验失败在 tool result 报原因由 agent 重问。
//   key 题形态=agent 构造 well-known 候选列表（如 HF_TOKEN/HUGGINGFACE_TOKEN）+自由输入（格式
//   `KEY, alias1, alias2` 逗号分隔）；② 密钥真值走本 server 的 elicitation（仅 accept 落库；宿主已知
//   无 password 掩码——收值屏一屏制：enum 唯一选项「手工命令行」+宿主强制附自由输入框收值，非 accept
//   回附带 senv add 命令由用户终端执行即兜底通道）。
// tool result 永远脱敏（不含值）。运行时中立：与 core.mjs 同规，不用 Bun 专属 API。
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import readline from "node:readline";
import { envNameFromHuman, storeEntry } from "./cli.mjs";
import { loadConfig } from "./core.mjs";
import { PROVIDERS, buildEntryOpts, entryCommandText } from "./entry.mjs";

const CONFIG_PATH = join(process.env.HOME ?? homedir(), ".config", "secret-env", "secrets.json");

// ---------- i18n：宿主子进程继承 env，读 LC_ALL/LANG 判语言，英文兜底 ----------
const lang = (() => {
  const l = process.env.LC_ALL ?? process.env.LANG ?? "";
  return l.toLowerCase().startsWith("zh") ? "zh" : "en";
})();
const T = {
  zh: {
    missingName: "缺少 name 入参——请先经宿主问答与用户终审环境变量名（well-known 候选或自定义，别名以逗号分隔）后再调用",
    exists: "已存在同名条目，请换名后重调（维护已有条目请在终端用 senv add 不带 --provider）",
    badProvider: "provider 不在支持列表",
    manualOption: "手工通过命令行输入",
    valueMessage: (name) =>
      `请在此输入 ${name} 的密钥。密钥不经模型上下文——模型接触不到此输入，所以这里只能填密钥本身，不要附带任何说明或其它内容。输入时屏幕可见，介意请选「手工通过命令行输入」。`,
  },
  en: {
    missingName: "Missing `name` argument — finalize the env var name with the user via the host's native Q&A (well-known candidates or custom; comma-separated aliases) before calling",
    exists: "An entry with this name already exists — pick another name and call again (to maintain an existing entry run `senv add` without --provider in a terminal)",
    badProvider: "provider not in the supported list",
    manualOption: "Enter manually via command line",
    valueMessage: (name) =>
      `Enter the secret for ${name} below. The secret bypasses model context — the model never sees this input, so enter the secret itself and nothing else. It is visible on screen while typing; prefer the command line? choose the manual option.`,
  },
}[lang];

// ---------- stdio JSON-RPC ----------
const rl = readline.createInterface({ input: process.stdin });
let nextId = 1;
const pending = new Map();
const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
const request = (method, params) => new Promise((resolve) => {
  const id = nextId++;
  pending.set(id, resolve);
  send({ jsonrpc: "2.0", id, method, params });
});

rl.on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id !== undefined && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
    return;
  }
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: msg.params?.protocolVersion ?? "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "secret-env", version: "0.2.0" },
    } });
    return;
  }
  if (msg.method?.startsWith("notifications/")) return;
  if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{
      name: "add_secret",
      description: "会话内交互登记新凭据。调用前先经宿主原生问答与用户终审元数据：① key 题=给出上下文相关的 well-known 候选（如 HF_TOKEN/HUGGINGFACE_TOKEN）供选，或自由输入 `KEY, alias1, alias2`（逗号分隔，alias 可省）；② desc 题=你组织的描述 / 不需要描述（desc 会进模型上下文，不得含敏感信息）；③ provider 从列表选。元数据定稿后由你组织成本工具入参传入；密钥值由本工具经宿主表单直接向用户收集，永远不要作为参数传入本工具。",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "环境变量名（终审定稿，将归一化为全大写下划线）" },
          provider: { type: "string", enum: PROVIDERS, description: "凭据库 provider" },
          detail: { type: "string", description: "条目定位（bitwarden/onepassword 的条目名[/字段] 或 viking 的 path；keychain 省略自动命名）" },
          alias: { type: "string", description: "别名（逗号分隔，可省）" },
          description: { type: "string", description: "描述（可省；会进模型上下文，不得含敏感信息）" },
        },
        required: ["name"],
      },
    }] } });
    return;
  }
  if (msg.method === "tools/call") {
    handleCall(msg);
    return;
  }
  if (msg.id !== undefined) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
  }
});

const replyJson = (id, obj, isError = false) =>
  send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(obj) }], ...(isError ? { isError: true } : {}) } });

async function elicit(message, schema) {
  const res = await request("elicitation/create", { message, requestedSchema: schema });
  if (res.error) return { error: res.error.message };
  return { action: res.result?.action ?? null, content: res.result?.content ?? {} };
}

const isAccepted = (r) => r.action === "accept";

// ---------- 元数据校验（无屏：入参即 agent 经宿主问答的定稿；失败在 tool result 报原因，agent 重问） ----------
function validateMeta(args) {
  const name = String(args.name ?? "").trim();
  const envName = envNameFromHuman(name);
  if (!envName) return { error: T.missingName };
  if (configEntries()[envName]) return { error: T.exists };
  const provider = args.provider ?? "keychain";
  if (!PROVIDERS.includes(provider)) return { error: `${T.badProvider}: ${provider}` };
  return {
    meta: {
      name,
      provider,
      detail: String(args.detail ?? "").trim(),
      alias: String(args.alias ?? "").trim(),
      description: String(args.description ?? "").trim(),
    },
  };
}

const configEntries = () => { try { return JSON.parse(readFileSync(CONFIG_PATH, "utf8")); } catch { return {}; } };

// ---------- add_secret 主流程（ZCode 通道，硬编码宿主已知形态：无掩码 → enum 收值屏一屏制） ----------
async function handleCall(msg) {
  const args = msg.params?.arguments ?? {};
  try {
    const { meta: picked, error: metaErr } = validateMeta(args);
    if (metaErr) return replyJson(msg.id, { status: "invalid", message: metaErr });

    // 收值屏一屏制：enum 唯一选项=手工命令行（选中即转终端通道），宿主强制附的自由输入框充当密钥输入。
    // 非 accept 一律回附带命令——用户放弃表单即选了终端通道，declined 不是失败。
    const r = await elicit(T.valueMessage(picked.name), {
      type: "object",
      properties: { secret: { type: "string", enum: [T.manualOption], title: "secret" } },
      required: ["secret"],
    });
    if (!isAccepted(r)) return replyJson(msg.id, { status: r.action ?? "no-answer", command: entryCommandText(picked) });
    if (r.content.secret === T.manualOption) return replyJson(msg.id, { status: "declined", command: entryCommandText(picked) });
    const { envName, uri } = await storeEntry(buildEntryOpts(picked), r.content.secret);
    return replyJson(msg.id, { status: "stored", envName, uri }); // 永不含值
  } catch (e) {
    replyJson(msg.id, { status: "error", message: e.message }, true);
  }
}

rl.on("close", () => process.exit(0));
