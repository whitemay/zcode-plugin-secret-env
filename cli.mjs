#!/usr/bin/env bun
// secret-env 全局 CLI。与宿主无关的三个入口：
//   secret-env add <NAME> ...   用户终端执行：交互收值（隐藏输入）→ 入库 → 登记 secrets.json
//   secret-env list             打印名字+别名+描述清单（无真值）
//   secret-env hook zcode       ZCode PreToolUse 钩子协议壳（stdin/stdout JSON）
// 真值只在：用户终端输入 → provider 存储 → 子进程环境。任何环节不进模型上下文。
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { argv } from "bun";
import { loadConfig, scanRefs, isDumpCommand, cleanStale, resolveValue, writeEnvFile, shellSingleQuote } from "./core.mjs";

const LOG = "/tmp/zcode-secret-env.log";
const CONFIG_PATH = join(process.env.HOME ?? "~", ".config", "secret-env", "secrets.json");

function log(msg) {
  try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {}
}

// ---------- add：交互入库 + 登记 ----------
// 用法：secret-env add -n <name> [TOKEN] [--alias A]... [--desc D]
//        -n/--name 必选，人读名（如 "github token"）；位置参数只能是 token 本身（给了则不交互）
//        env 变量名 = name 归一化全大写下划线（github token → GITHUB_TOKEN）
//        --provider system   存 macOS 钥匙串，service 缺省 = secret-env-<小写连字符名>（已带前缀不重复加）
//        --provider viking --path c/t[/f]     值已由用户在 OpenViking 放好，只登记映射
//        --provider bitwarden --item I        同上，只登记映射
function envNameFromHuman(name) {
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
    else if (!a.startsWith("-")) opts.token ??= a;
    else { console.error(`未知参数：${a}`); process.exit(2); }
  }
  return opts;
}

async function promptHiddenValue(label) {
  // 用户终端隐藏输入：read -rs 在 bash 子进程里关掉回显，值经 stdout 回到本进程内存
  const r = Bun.spawnSync(["bash", "-c", `read -rs -p ${JSON.stringify(label)} v && echo "$v"`], { stdin: "inherit", stdout: "pipe" });
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

async function cmdAdd(args) {
  const opts = parseAddArgs(args);
  if (!opts.name) {
    console.error("用法：secret-env add -n <name> [TOKEN] [--alias A]... [--desc D] [--provider system|viking|bitwarden ...]\n  name 为人读名（如 github token），env 变量名自动归一化为全大写下划线；位置参数只能是 token 本身\n  system 与 keychain 等价（本机系统密钥库）；已存在条目不带 --provider 时进入维护模式（只改别名/描述），显式给 --provider system 则强制重新收值");
    process.exit(2);
  }
  const envName = envNameFromHuman(opts.name);
  if (!envName) { console.error(`name 归一化后为空：${opts.name}`); process.exit(2); }
  // system 与 keychain 等价：都是本机系统密钥库；system 是显式别名——
  // 条目已存在时用它绕过维护模式，强制重新收值入库
  if (opts.provider === "keychain") opts.provider = "system";

  const existing = JSON.parse(readFileSync(CONFIG_PATH, "utf8"))[envName];
  if (!opts.provider && !existing) { console.error(`新条目需要 --provider（system|viking|bitwarden）`); process.exit(2); }
  // 收值需要真终端；Agent 的 Bash 无 TTY，值必须由用户亲手输入（给了位置参数 token 则免交互）
  const needsPrompt = opts.provider === "system" && !opts.token;
  if (needsPrompt && !process.stdin.isTTY) {
    console.error("收值需要交互终端（TTY）。请在你的终端里直接运行本命令（或把 token 作为位置参数传入），值不会经过 Agent。");
    process.exit(2);
  }

  let uri;
  if (!opts.provider && existing) {
    // 维护模式：保留 uri 与已存的值，只改别名/描述
    uri = existing.uri;
    console.log(`维护模式：${envName} 已存在（${uri}），值不动。`);
  } else if (opts.provider === "system") {
    const service = opts.service ?? serviceFromHuman(opts.name);
    const value = opts.token ?? await promptHiddenValue(`输入 ${envName} 的值（隐藏输入，回车确认）: `);
    const r = await Bun.$`security add-generic-password -a ${process.env.USER} -s ${service} -w ${value} -U`.nothrow();
    if (r.exitCode !== 0) { console.error(`钥匙串写入失败（exit=${r.exitCode}）：${r.stderr.toString().trim()}`); process.exit(2); }
    uri = `keychain://${service}`;
  } else if (opts.provider === "viking") {
    if (!opts.path) { console.error("viking 需要 --path <category>/<target>[/<field>]"); process.exit(2); }
    // 值由用户经 ov 自行放入 privacy 区域，这里只登记映射
    uri = `viking://${opts.path}`;
  } else if (opts.provider === "bitwarden") {
    if (!opts.item) { console.error("bitwarden 需要 --item <item>"); process.exit(2); }
    uri = `bitwarden://${opts.item}`;
  } else {
    console.error(`未知 provider：${opts.provider}`); process.exit(2);
  }

  const raw = updateConfig(envName, { uri, ...(opts.aliases.length ? { aliases: opts.aliases } : {}), ...(opts.description ? { description: opts.description } : {}) });
  console.log(`已登记 ${envName} → ${uri}`);
  console.log(`secrets.json 现有条目：${Object.keys(raw).join("、")}`);
  console.log("下个 session 的清单注入将自动包含新条目。");
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
    const r = await Bun.$`security delete-generic-password -s ${service}`.nothrow();
    console.log(r.exitCode === 0 ? `钥匙串条目已删除（service=${service}）` : `钥匙串删除未命中（service=${service}，exit=${r.exitCode}）——可能已不存在，继续`);
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

  if (payload?.tool_name !== "Bash") allow();
  const command = payload?.tool_input?.command ?? "";
  if (!command) allow();

  const config = loadConfig();
  if (config.size === 0) allow(); // 未配置 = 纯旁路

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
      values.set(name, await resolveValue(info.uri));
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

// ---------- 入口 ----------
const [cmd, ...rest] = argv.slice(2);
if (cmd === "add") await cmdAdd(rest);
else if (cmd === "remove") await cmdRemove(rest);
else if (cmd === "list" && rest[0] === "--inject") cmdInjectList();
else if (cmd === "list") cmdList();
else if (cmd === "hook" && rest[0] === "zcode") await cmdHookZcode();
else {
  console.error("用法：secret-env add|remove|list [--inject]|hook zcode");
  process.exit(cmd ? 2 : 0);
}
