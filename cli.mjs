#!/usr/bin/env node
// secret-env 全局 CLI。与宿主无关的三个入口：
//   secret-env add <NAME> ...   用户终端执行：交互收值（隐藏输入）→ 入库 → 登记 secrets.json
//   secret-env list             打印名字+别名+描述清单（无真值）
//   secret-env hook zcode       ZCode PreToolUse 钩子协议壳（stdin/stdout JSON）
// 真值只在：用户终端输入 → provider 存储 → 子进程环境。任何环节不进模型上下文。
// 运行时中立（与 core.mjs 同规）：bin 须在 Bun/Node/pnpm 任意全局安装下可跑，不用 Bun 专属 API。
import { appendFileSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const argv = process.argv;
import { loadConfig, scanRefs, isDumpCommand, cleanStale, resolveValue, writeValue, writeEnvFile, shellSingleQuote, keychainBackend, guardPaths } from "./core.mjs";

const LOG = "/tmp/zcode-secret-env.log";
const CONFIG_PATH = join(process.env.HOME ?? "~", ".config", "secret-env", "secrets.json");

function log(msg) {
  try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {}
}

// ---------- add：收值 → provider 写入 → 登记（写侧自治，DESIGN §3） ----------
// 用法：secret-env add -n <name> [TOKEN] [--alias A]... [--desc D]
//        -n/--name 必选，人读名（如 "github token"）；位置参数只能是 token 本身（给了则不交互）
//        env 变量名 = name 归一化全大写下划线（github token → GITHUB_TOKEN）
//        --provider system    存本机钥匙串，service 缺省 = secret-env-<小写连字符名>；--user 可选（account 属性）
//        --provider bitwarden --item I [--field F]   写 vault：无 field → password 位（条目不存在则新建 login 条目）；
//                                                    有 field → 已存在条目上 upsert 自定义字段；--user 写 username 位
//        --provider viking --path c/t[/f]            写 OpenViking privacy（值经 0600 临时文件，不落 argv）；无 f 时主值落 value 字段
export function envNameFromHuman(name) {
  // 驼峰拆词 → 按非字母数字切词 → 大写下划线
  const words = name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).filter(Boolean);
  return words.join("_").toUpperCase();
}
function serviceFromHuman(name) {
  const s = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return s.startsWith("secret-env-") ? s : `secret-env-${s}`;
}

function parseAddArgs(args) {
  const opts = { aliases: [], provider: null };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-n" || a === "--name") opts.name = args[++i];
    else if (a === "--alias") opts.aliases.push(args[++i]);
    else if (a === "--desc") opts.description = args[++i];
    else if (a === "--provider") opts.provider = args[++i];
    else if (a === "--service") opts.service = args[++i];
    else if (a === "--path") opts.path = args[++i];
    else if (a === "--item") opts.item = args[++i];
    else if (a === "--field") opts.field = args[++i];
    else if (a === "--user") opts.user = args[++i];
    else if (!a.startsWith("-")) opts.token ??= a;
    else { console.error(`未知参数：${a}`); process.exit(2); }
  }
  return opts;
}

async function promptHiddenValue(label) {
  // 用户终端隐藏输入：read -rs 在 bash 子进程里关掉回显，值经 stdout 回到本进程内存
  const r = spawnSync("bash", ["-c", `read -rs -p ${JSON.stringify(label)} v && echo "$v"`], { stdin: "inherit", stdio: ["inherit", "pipe", "inherit"], encoding: "utf8" });
  const v = r.stdout.toString().replace(/\n$/, "");
  if (!v) { console.error("\n空值，放弃。"); process.exit(2); }
  console.log("");
  return v;
}

function updateConfig(name, def) {
  const raw = {};
  // 保留现有条目——只对稳定路径文件做增量改写
  try { Object.assign(raw, JSON.parse(readFileSync(CONFIG_PATH, "utf8"))); } catch {}
  raw[name] = def;
  writeFileSync(CONFIG_PATH, JSON.stringify(raw, null, 2) + "\n", { mode: 0o600 });
  return raw;
}

// 共用入库主体：校验 → provider 写入 → 登记。CLI 与 MCP server 共用（防漂移），错误一律 throw。
// value 由调用方收好传入（CLI=终端隐藏输入/位置参数；MCP=elicitation 表单），本函数不收值。
export async function storeEntry(opts, value) {
  if (!value) throw new Error("空值，放弃");
  const envName = envNameFromHuman(opts.name);
  if (!envName) throw new Error(`name 归一化后为空：${opts.name}`);
  if (opts.provider === "system") opts.provider = "keychain"; // 弃用别名，行为一致
  if (!["keychain", "bitwarden", "onepassword", "viking"].includes(opts.provider)) throw new Error(`未知 provider：${opts.provider}`);
  if (opts.user && !["keychain", "bitwarden"].includes(opts.provider)) throw new Error("--user 仅支持 keychain 与 bitwarden provider（account/username 位）");
  if (opts.provider === "bitwarden" || opts.provider === "onepassword") {
    if (!opts.item) throw new Error(`${opts.provider} 需要 --item <条目名>[，--field <字段> 二级写入]`);
    if (opts.user && opts.field) throw new Error("--user 与 --field 互斥（字段写入不带 username 位）");
  }
  let uri;
  if (opts.provider === "keychain") {
    const service = opts.service ?? serviceFromHuman(opts.name);
    const backend = await keychainBackend(loadConfig()); // kdbx 配置则写库，否则系统密钥库（二进制探测/库配置校验先于人话报错）
    await backend.write(service, value, opts.user);
    uri = `keychain://${service}`;
  } else if (opts.provider === "bitwarden") {
    // 写侧自治：经配置里的 BW_SESSION 记录解析 session 后写入 vault
    await writeValue({ provider: "bitwarden", item: opts.item, field: opts.field, user: opts.user }, value, loadConfig());
    uri = `bitwarden://${opts.item}${opts.field ? `/${opts.field}` : ""}`;
  } else if (opts.provider === "onepassword") {
    // 写侧自治：经配置里的 OP_SESSION 记录（或 biometric）写入 1Password。⚠️ 全线待真机验证。
    await writeValue({ provider: "onepassword", item: opts.item, field: opts.field, user: opts.user }, value, loadConfig());
    uri = `onepassword://${opts.item}${opts.field ? `/${opts.field}` : ""}`;
  } else {
    const parts = opts.path?.split("/") ?? [];
    if (parts.length < 2 || parts.length > 3) throw new Error("viking 需要 --path <category>/<target>[/<field>]");
    // 写侧自治：值经 0600 临时文件走 ov privacy upsert（不落 argv）
    await writeValue({ provider: "viking", parts: parts.length === 2 ? [...parts, "value"] : parts }, value);
    uri = `viking://${parts.join("/")}`;
  }
  const raw = updateConfig(envName, { uri, ...(opts.aliases.length ? { aliases: opts.aliases } : {}), ...(opts.description ? { description: opts.description } : {}) });
  return { envName, uri, raw };
}

async function cmdAdd(args) {
  const opts = parseAddArgs(args);
  if (!opts.name) {
    console.error("用法：secret-env add -n <name> [TOKEN] [--alias A]... [--desc D] [--provider keychain|viking|bitwarden|onepassword ...]\n  统一流程：收值（隐藏输入或位置参数）→ provider 写入 → 登记 uri。写侧自治：bitwarden 走配置里的 BW_SESSION，onepassword 走 OP_SESSION 或 biometric，viking 走本机 ov。\n  keychain：--service 可选（缺省自动命名），--user 可选（account/username 位，缺省 = 当前系统用户）；配置 $keychain 时写 kdbx 库，否则系统密钥库（system 为弃用别名）\n  bitwarden：--item <条目名> 必选；--field <字段> 二级写入（条目须已存在）；--user 写 username 位\n  onepassword：--item <条目名> 必选；--field <字段> 二级写入；--user 写 username 位（待真机验证）\n  viking：--path <category>/<target>[/<field>]；无 field 时主值落 value 字段\n  已存在条目不带 --provider 时进入维护模式（只改别名/描述），显式给 --provider 则强制重新收值");
    process.exit(2);
  }
  // system 是弃用别名：仍接受（向后兼容），打印迁移提示，行为完全一致
  if (opts.provider === "system") {
    console.error("⚠️  --provider system 已弃用，改用 --provider keychain（同一行为；system 将在后续版本移除）。本次仍按 keychain 执行。");
    opts.provider = "keychain";
  }
  const envName = envNameFromHuman(opts.name);
  const existing = JSON.parse(readFileSync(CONFIG_PATH, "utf8"))[envName];
  if (!opts.provider && !existing) { console.error(`新条目需要 --provider（keychain|viking|bitwarden）`); process.exit(2); }
  // 收值需要真终端；Agent 的 Bash 无 TTY，值必须由用户亲手输入（给了位置参数 token 则免交互）
  if (opts.provider && !opts.token && !process.stdin.isTTY) {
    console.error("收值需要交互终端（TTY）。请在你的终端里直接运行本命令（或把 token 作为位置参数传入），值不会经过 Agent。");
    process.exit(2);
  }

  if (!opts.provider && existing) {
    // 维护模式：保留 uri 与已存的值，只改别名/描述
    console.log(`维护模式：${envName} 已存在（${existing.uri}），值不动。`);
    const raw = updateConfig(envName, { uri: existing.uri, ...(opts.aliases.length ? { aliases: opts.aliases } : {}), ...(opts.description ? { description: opts.description } : {}) });
    console.log(`secrets.json 现有条目：${Object.keys(raw).join("、")}`);
    return;
  }

  const value = opts.token ?? await promptHiddenValue(`输入 ${envName} 的值（隐藏输入，回车确认）: `);
  try {
    const { envName: n, uri, raw } = await storeEntry(opts, value);
    console.log(`已登记 ${n} → ${uri}`);
    console.log(`secrets.json 现有条目：${Object.keys(raw).join("、")}`);
    console.log("下个 session 的清单注入将自动包含新条目。");
  } catch (e) {
    console.error(`入库失败：${e.message}`);
    process.exit(2);
  }
}

async function cmdRemove(args) {
  const name = args.filter((a) => !a.startsWith("--"))[0];
  const purge = args.includes("--purge");
  if (!name || args.some((a) => a.startsWith("--") && a !== "--purge")) {
    console.error("用法：secret-env remove <NAME> [--purge]   (--purge 连 provider 里的值一起删，目前支持 system)");
    process.exit(2);
  }
  const raw = (() => { try { return JSON.parse(readFileSync(CONFIG_PATH, "utf8")); } catch { return {}; } })();
  const def = raw[name];
  if (!def) { console.error(`未配置：${name}（现有：${Object.keys(raw).join("、") || "无"}）`); process.exit(2); }

  if (purge && def.uri.startsWith("keychain://")) {
    const service = def.uri.slice("keychain://".length);
    try {
      const backend = await keychainBackend(loadConfig());
      const hit = await backend.remove(service);
      console.log(hit ? `密钥库条目已删除（service=${service}）` : `删除未命中（service=${service}）——可能已不存在，继续`);
    } catch (e) {
      console.error(`--purge 失败：${e.message}（映射仍会删除）`);
    }
  } else if (purge) {
    console.log(`${def.uri} 的 --purge 暂未支持（system 以外请用各自工具清理），只删映射。`);
  }

  delete raw[name];
  writeFileSync(CONFIG_PATH, JSON.stringify(raw, null, 2) + "\n", { mode: 0o600 });
  console.log(`映射已删除：${name}。下个 session 的清单注入自动更新。`);
}

function cmdList() {
  const config = loadConfig();
  if (config.size === 0) { console.log("(空)"); return; }
  const entries = new Map();
  for (const [name, info] of config) {
    if (info.canonical === name) entries.set(name, { aliases: [], description: info.description });
    else entries.get(info.canonical)?.aliases.push(name);
  }
  for (const [name, { aliases, description }] of entries) {
    console.log(`${name}${aliases.length ? `（别名：${aliases.join("、")}）` : ""}${description ? `：${description}` : ""}`);
  }
}

// ---------- list --inject：SessionStart 注入壳（输出 JSON additionalContext） ----------
function cmdInjectList() {
  const config = loadConfig();
  if (config.size === 0) process.exit(0);
  const entries = new Map();
  for (const [name, info] of config) {
    if (info.canonical === name) entries.set(name, { aliases: [], description: info.description });
    else entries.get(info.canonical)?.aliases.push(name);
  }
  const lines = [
    "已配置密钥（secret-env，值永不出现在上下文，命令中显式引用即可注入子进程环境）：",
    ...[...entries].map(([name, { aliases, description }]) => {
      let line = `- ${name}`;
      if (aliases.length) line += `（别名：${aliases.join("、")}）`;
      if (description) line += `：${description}`;
      return line;
    }),
    "用法：命令文本写 $NAME 或 ${NAME}（双引号内），隐式读取的工具写成 NAME=$NAME cmd；禁止单引号包引用、禁止命令含 env/printenv/裸 set/export。",
    "详见 secret-env skill。",
  ];
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: lines.join("\n") } }));
}

// ---------- hook zcode：ZCode PreToolUse 协议壳 ----------
// 逻辑与旧 hooks/secret-env.mjs 完全一致：allow + updatedInput；拒绝 exit 2。
async function cmdHookZcode() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  let payload = null;
  try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { log("[parse-error] 放行"); process.exit(0); }

  const allow = (updated) => {
    const out = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } };
    if (updated) out.hookSpecificOutput.updatedInput = updated;
    console.log(JSON.stringify(out));
    process.exit(0);
  };
  const deny = (reason) => { console.error(reason); process.exit(2); };

  if (payload?.tool_name !== "Bash") {
    // 非 Bash 工具（Write/Edit/Read 经 hooks.json 同一入口）：只做文件守卫，扫 file_path
    const cfg = loadConfig();
    const fp = payload?.tool_input?.file_path ?? "";
    const hit = fp && guardPaths(cfg).some((f) => fp.includes(f));
    if (hit) deny(`secret-env：${fp} 是 secret-env 的配置/密钥库文件（含 master 口令与全部凭据映射），禁止 Agent 读写。配置维护请在你的终端运行 secret-env add/remove，或亲手编辑。`);
    allow();
  }
  const command = payload?.tool_input?.command ?? "";
  if (!command) allow();

  const config = loadConfig();
  if (config.size === 0) allow(); // 未配置 = 纯旁路

  // 文件守卫（Bash）：命令文本提及配置/密钥库文件即拒——这些文件含口令明文与全部映射，
  // 且这类命令通常不含 $VAR 引用，注入扫描盯不到它们
  const guardHit = guardPaths(config).find((f) => command.includes(f));
  if (guardHit) {
    deny(`secret-env：命令涉及受保护文件（片段「${guardHit}」）——secrets.json/vault.kdbx 含 master 口令明文与全部凭据映射，禁止 Agent 读写。配置维护请在你的终端运行 secret-env add/remove，或亲手编辑。`);
  }

  cleanStale();

  const sessionId = payload?.session_id ?? "";
  const tokens = scanRefs(command, config, deny);
  if (tokens.length === 0) allow(); // 无引用 = 零注入，无可倾泻

  const bad = tokens.filter((t) => t.inSingle);
  if (bad.length) {
    deny(`secret-env：引用位于单引号内不会被展开（${[...new Set(bad.map((t) => t.token))].join("、")}）。请改用双引号包裹，例如 "$GH_TOKEN"。`);
  }
  if (isDumpCommand(command)) {
    deny(`secret-env：命令同时含密钥引用与环境倾泻命令（env/printenv/set/export），会打印注入值。请把倾泻意图从命令中移除。`);
  }

  const canonicalNames = [...new Set(tokens.map((t) => t.name))];
  const values = new Map();
  for (const name of canonicalNames) {
    const info = config.get(name);
    try {
      values.set(name, await resolveValue(info.uri, config));
    } catch (e) {
      deny(`secret-env：解析 ${name}（${info.uri}）失败：${e.message}`);
    }
  }

  const exportNames = new Map();
  for (const t of tokens) {
    const refName = t.token.replace(/^\$\{?/, "").replace(/\}$/, "");
    exportNames.set(refName, t.name);
  }

  const envFile = writeEnvFile(sessionId, exportNames, values);
  const newCommand = `. ${shellSingleQuote(envFile)}; ${command}`;
  log(`inject session=${sessionId} names=${[...exportNames.keys()].join(",")} file=${envFile}`);

  allow({ ...payload.tool_input, command: newCommand });
}

// ---------- 入口（仅作为脚本直跑时分发；被 mcp.mjs import 时不执行，避免误入分发分支） ----------
const [cmd, ...rest] = argv.slice(2);
// 两边 realpath 再比：bun link / 全局安装下 argv[1] 是 shim symlink 路径，import.meta.url 是真实文件路径。
// 直接用字面量比较会让所有 `secret-env <cmd>` 调用静默退出（exit 0，无任何输出）。
let asMain = false;
if (process.argv[1]) {
  try {
    asMain = realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {}
}
if (!asMain) {
  // 被 import：只取导出，不进分发
} else if (cmd === "add") await cmdAdd(rest);
else if (cmd === "remove") await cmdRemove(rest);
else if (cmd === "list" && rest[0] === "--inject") cmdInjectList();
else if (cmd === "list") cmdList();
else if (cmd === "hook" && rest[0] === "zcode") await cmdHookZcode();
else {
  console.error("用法：secret-env add|remove|list [--inject]|hook zcode");
  process.exit(cmd ? 2 : 0);
}
