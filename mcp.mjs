#!/usr/bin/env node
// secret-env MCP server（stdio）。会话内交互入库：elicitation 表单直达本进程 → provider，值不经模型上下文。
// 表单永远只收数据（名字/provider/条目定位），提示词程序给出（按宿主 env 语言），tool result 永远脱敏（不含值）。
// 设计定案见项目记忆 host-elicit-probe.md：仅 accept 落库；第 1 屏终审 + 第 2 屏三形态裁断（选择屏/直接输入框/直接给命令）。
// 能力探测并入首用：第 2 屏先试 password 字段，被宿主协议校验拒绝即无感降级到选择屏并缓存。
// 运行时中立：与 core.mjs 同规，不用 Bun 专属 API。
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import readline from "node:readline";
import { envNameFromHuman, storeEntry } from "./cli.mjs";
import { loadConfig } from "./core.mjs";

const CONFIG_PATH = join(process.env.HOME ?? homedir(), ".config", "secret-env", "secrets.json");
const PROVIDERS = ["keychain", "bitwarden", "viking", "onepassword"];

// ---------- i18n：宿主子进程继承 env，读 LC_ALL/LANG 判语言，英文兜底 ----------
const lang = (() => {
  const l = process.env.LC_ALL ?? process.env.LANG ?? "";
  return l.toLowerCase().startsWith("zh") ? "zh" : "en";
})();
const T = {
  zh: {
    formTitle: "secret-env 新条目登记（第 1 步/共 2 步）：请核对以下信息，可修改预填值",
    nameLabel: "环境变量名（人读名，将归一化为全大写下划线）",
    providerLabel: "凭据库 provider",
    detailLabel: "条目定位（bitwarden/onepassword=条目名[/字段]，viking=类目/目标[/字段]，keychain 留空自动命名）",
    aliasLabel: "别名（可选，逗号分隔）",
    descLabel: "描述（可选。注意：描述会进入模型上下文，不得含敏感信息）",
    fixTitle: "信息有误，请确认后重试",
    exists: "已存在同名条目，请改名（维护已有条目请在终端用 senv add 不带 --provider）",
    valueTitlePw: "secret-env 新条目登记（第 2 步）：请输入密钥值（掩码显示，只写入凭据库，不会进入模型上下文）",
    valueTitlePlain: "secret-env 新条目登记（第 2 步）：请输入密钥值。注意：宿主不支持掩码输入，值将明文显示在表单中（介意旁观/录屏请勿选此项）；值不会进入模型上下文",
    choiceTitle: "secret-env 新条目登记（第 2 步）：请选择密钥值录入方式。command=命令行录入（随后给出命令，你在终端执行，隐藏输入屏幕不显示值）；form=表单直接录入（值明文显示在表单中，介意旁观/录屏勿选；同样不进模型上下文）",
  },
  en: {
    formTitle: "secret-env new entry (step 1/2): review the prefilled fields and correct if needed",
    nameLabel: "Env var name (human-readable; normalized to UPPER_SNAKE)",
    providerLabel: "Credential provider",
    detailLabel: "Entry locator (bitwarden/onepassword=item[/field], viking=category/target[/field], keychain=leave blank for auto name)",
    aliasLabel: "Aliases (optional, comma-separated)",
    descLabel: "Description (optional. Caution: description enters model context — no sensitive info)",
    fixTitle: "Invalid input, please review and retry",
    exists: "An entry with this name already exists — choose another name (to maintain an existing entry run `senv add` without --provider in a terminal)",
    valueTitlePw: "secret-env new entry (step 2): enter the secret (masked; stored to the credential store, never enters model context)",
    valueTitlePlain: "secret-env new entry (step 2): enter the secret. Caution: this host has no masked input — the value shows in the form (avoid if others can see your screen); it never enters model context",
    choiceTitle: "secret-env new entry (step 2): choose how to enter the secret. command=enter via command line (a command will be given for your terminal; hidden input, value never shown); form=type into the form (value shows in the form — avoid if others can see your screen; never enters model context)",
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
      description: "会话内交互登记新凭据：两步表单由用户在宿主 UI 确认，密钥值直达凭据库、不经模型上下文。入参仅作表单预填草稿；密钥值永远不要作为参数传入本工具。",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "人读名预填（如 github token）" },
          provider: { type: "string", enum: PROVIDERS, description: "provider 预填" },
          detail: { type: "string", description: "条目定位预填（bitwarden/onepassword 的条目名或 viking 的 path）" },
          alias: { type: "string", description: "别名预填（逗号分隔）" },
          description: { type: "string", description: "描述预填（不得含敏感信息）" },
        },
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

// ---------- 第 1 屏：终审（校验失败带原因重弹；decline/cancel 零写入） ----------
async function screenOne(args) {
  for (;;) {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string", title: T.nameLabel, default: args.name ?? "" },
        provider: { type: "string", enum: PROVIDERS, title: T.providerLabel, default: PROVIDERS.includes(args.provider) ? args.provider : "keychain" },
        detail: { type: "string", title: T.detailLabel, default: args.detail ?? "" },
        alias: { type: "string", title: T.aliasLabel, default: args.alias ?? "" },
        description: { type: "string", title: T.descLabel, default: args.description ?? "" },
      },
      required: ["name", "provider"],
    };
    const r = await elicit(T.formTitle, schema);
    if (!isAccepted(r)) return null;
    const envName = envNameFromHuman(String(r.content.name ?? "").trim());
    const exists = envName ? !!configEntries()[envName] : false;
    if (!envName || exists) {
      await elicit(`${T.fixTitle}${exists ? ` — ${T.exists}` : ""}`, { type: "object", properties: { ok: { type: "string", title: "OK" } } });
      continue;
    }
    return {
      name: String(r.content.name).trim(),
      provider: r.content.provider,
      detail: String(r.content.detail ?? "").trim(),
      alias: String(r.content.alias ?? "").trim(),
      description: String(r.content.description ?? "").trim(),
    };
  }
}

const configEntries = () => { try { return JSON.parse(readFileSync(CONFIG_PATH, "utf8")); } catch { return {}; } };

const buildOpts = (p) => {
  const o = { name: p.name, provider: p.provider, aliases: p.alias ? p.alias.split(",").map((s) => s.trim()).filter(Boolean) : [], description: p.description || undefined };
  if (p.provider === "viking") o.path = p.detail;
  else if (p.provider !== "keychain") o.item = p.detail;
  return o;
};

const commandText = (p) => {
  const o = buildOpts(p);
  let c = `senv add -n ${JSON.stringify(p.name)} --provider ${o.provider}`;
  if (o.item) c += ` --item ${JSON.stringify(o.item)}`;
  if (o.path) c += ` --path ${JSON.stringify(o.path)}`;
  if (o.aliases.length) c += ` --alias ${o.aliases.map((a) => JSON.stringify(a)).join(" --alias ")}`;
  if (o.description) c += ` --desc ${JSON.stringify(o.description)}`;
  return c;
};

// ---------- add_secret 主流程 ----------
let passwordSupport = null; // null=未探测；探测并入首用（第 2 屏先试 password 字段，被拒即知不支持并缓存）
async function handleCall(msg) {
  const args = msg.params?.arguments ?? {};
  try {
    const picked = await screenOne(args);
    if (!picked) return replyJson(msg.id, { status: "declined" });

    // 第 2 屏形态裁断：未探测过则先试 password 值表单——成功即直通（支持）；协议校验拒绝即无感降级选择屏（不支持）
    if (passwordSupport !== false) {
      const r = await elicit(T.valueTitlePw, { type: "object", properties: { value: { type: "string", format: "password", title: "secret" } }, required: ["value"] });
      if (!r.error) {
        passwordSupport = true;
        if (!isAccepted(r)) return replyJson(msg.id, { status: r.action ?? "no-answer" });
        const { envName, uri } = await storeEntry(buildOpts(picked), r.content.value);
        return replyJson(msg.id, { status: "stored", envName, uri }); // 永不含值
      }
      passwordSupport = false;
    }

    // 宿主无 password 形态：选择屏（命令行 / 明文表单），文案已含两者代价
    const c = await elicit(T.choiceTitle, { type: "object", properties: { mode: { type: "string", enum: ["command", "form"], title: "mode" } }, required: ["mode"] });
    if (!isAccepted(c)) return replyJson(msg.id, { status: c.action ?? "no-answer" });
    if (c.content.mode === "command") {
      // 命令行录入：给出精确命令由用户终端执行（read -s 隐藏输入），登记由命令自己完成
      return replyJson(msg.id, { status: "command-issued", command: commandText(picked) });
    }
    const r = await elicit(T.valueTitlePlain, { type: "object", properties: { value: { type: "string", title: "secret" } }, required: ["value"] });
    if (!isAccepted(r)) return replyJson(msg.id, { status: r.action ?? "no-answer" });
    const { envName, uri } = await storeEntry(buildOpts(picked), r.content.value);
    return replyJson(msg.id, { status: "stored", envName, uri });
  } catch (e) {
    replyJson(msg.id, { status: "error", message: e.message }, true);
  }
}

rl.on("close", () => process.exit(0));
