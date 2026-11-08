#!/usr/bin/env node
// secret-env 全局 CLI。与宿主无关的入口（2026-11-08 收口为 rsenv 同构三分法）：
//   secret-env set NAME ...     统一入库（收编原 add/store；值经 stdin 或 TTY 隐藏输入）
//   secret-env list             打印名字+别名+描述清单（无真值）
//   secret-env parse            宿主命令门：守卫 + 解析全部值 → 一次性槽位 + token（rsenv 同构）
//   secret-env inject <token>   消费槽位输出 export 行（daemon 取即删，一次性）
//   secret-env info             宿主守卫快照（protocol 1，rsenv info 同形态 + backend/capabilities）
// 真值只在：用户终端输入 → provider 存储 → 子进程环境。任何环节不进模型上下文；
// 槽位 = 轻量 daemon 内存 map（值全程不落盘），插件与 shell 只经手 token。
// 运行时中立（与 core.mjs 同规）：bin 须在 Bun/Node/pnpm 任意全局安装下可跑，不用 Bun 专属 API。
import { appendFileSync, chmodSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
const argv = process.argv;
import { PROTOCOL_VERSION, configPaths, loadConfig, scanRefs, isDumpCommand, resolveValue, writeValue, shellSingleQuote, keychainBackend, guardPaths } from "./core.mjs";
import { PROVIDERS } from "./entry.mjs";

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
  // add 已收编进 set（2026-11-08）：转发并提示新口径
  console.error("⚠️  add 已收编进 set：secret-env set NAME [--provider ...] [--desc D] [--alias A]...，值经 stdin 或 TTY 隐藏输入。本次按 set 执行。");
  await cmdSet(args);
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

// 配置 Map → 主键清单（别名归并到 canonical 下）：list / list --inject / info 三处共用。
function canonicalEntries(config) {
  const entries = new Map();
  for (const [name, info] of config) {
    if (info.canonical === name) entries.set(name, { aliases: [], description: info.description });
    else entries.get(info.canonical)?.aliases.push(name);
  }
  return entries;
}

function cmdList() {
  const config = loadConfig();
  if (config.size === 0) { console.log("(空)"); return; }
  for (const [name, { aliases, description }] of canonicalEntries(config)) {
    console.log(`${name}${aliases.length ? `（别名：${aliases.join("、")}）` : ""}${description ? `：${description}` : ""}`);
  }
}

// ---------- 注入（2026-11-08 收口为 rsenv 同构三分法）：parse 签发一次性 token，inject 消费 ----------
// 槽位 = 轻量 daemon 内存 map（2026-11-08 用户定调）：值全程不出进程内存，与 rsenv 数据流安全等级拉平。
// daemon 无 login/无加密职责/不保活——parse 按需拉起，有 socket 直接用，崩了下次重拉（token 丢失 =
// inject fail-closed 短路，正是要的语义）。端点按平台分流：unix socket 0600 / win32 named pipe（ACL 限本用户）。

const TOKEN_TTL_MS = Number(process.env.SENV_TTL_MS ?? 10_000); // SENV_TTL_MS 仅测试用
const daemonEndpoint = () => process.platform === "win32"
  ? "\\\\.\\pipe\\secret-env-tokens"
  : join(process.env.HOME ?? "~", ".config/secret-env", "senv.sock");

// 单次请求-响应：connect → 一行 JSON → 读一行回包 → 关闭
function daemonCall(payload, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const sock = createConnection(daemonEndpoint());
    let buf = "";
    const done = (fn, arg) => { sock.destroy(); fn(arg); };
    sock.setTimeout(timeoutMs, () => done(reject, new Error("senv daemon 响应超时")));
    sock.on("connect", () => sock.write(JSON.stringify(payload) + "\n"));
    sock.on("data", (d) => {
      buf += d;
      if (!buf.includes("\n")) return;
      try { done(resolve, JSON.parse(buf)); } catch { done(reject, new Error("senv daemon 响应非 JSON")); }
    });
    sock.on("error", (e) => done(reject, e));
  });
}

const DAEMON_WAIT_MS = 1500;
async function ensureDaemon() {
  const probe = () => daemonCall({ op: "ping" }, 300).then(() => true, () => false);
  if (await probe()) return; // 有活 daemon 直接用（幂等）
  // 按需拉起：detached 脱离本进程生命周期，stdio 丢弃；不保活、不管退出
  const { spawn } = await import("node:child_process"); // 局部导入不构成顶层 await
  const self = fileURLToPath(import.meta.url);
  const child = spawn(process.execPath, [self, "daemon"], { detached: true, stdio: "ignore" });
  child.unref();
  // 轮询等就绪；超时报错（宁可失败，不回退文件槽）
  for (let waited = 0; waited < DAEMON_WAIT_MS; waited += 50) {
    if (await probe()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("senv daemon 拉起失败（socket 未就绪）");
}

// ---------- daemon 子命令：token 内存槽服务（put/redeem + TTL 清扫） ----------
async function cmdDaemon() {
  const endpoint = daemonEndpoint();
  const slots = new Map(); // token → { env, t }
  const server = createServer((sock) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d;
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        let reply;
        try {
          const req = JSON.parse(line);
          if (req.op === "ping") reply = { ok: true };
          else if (req.op === "put") {
            const token = randomBytes(16).toString("hex");
            slots.set(token, { env: req.env, t: Date.now() });
            reply = { ok: true, token };
          } else if (req.op === "redeem") {
            const hit = slots.get(req.token);
            slots.delete(req.token); // 取即删：一次性消费（单线程顺序处理，天然 exactly-once）
            reply = hit ? { ok: true, env: hit.env } : { ok: false, error: "invalid or already-consumed injection token" };
          } else reply = { ok: false, error: `unknown op: ${req.op}` };
        } catch { reply = { ok: false, error: "bad request" }; }
        sock.write(JSON.stringify(reply) + "\n");
      }
    });
  });
  const onListen = () => {
    if (process.platform !== "win32") {
      try { chmodSync(endpoint, 0o600); } catch {} // unix socket 权限随 umask，收紧到 0600
    }
    // TTL 清扫：只回收未消费残留
    setInterval(() => {
      const now = Date.now();
      for (const [t, s] of slots) if (now - s.t >= TOKEN_TTL_MS) slots.delete(t);
    }, 1000);
    log(`daemon listening (${process.platform})`);
  };
  server.on("error", async (e) => {
    if (e.code === "EADDRINUSE") {
      // 端点被占：探测是活 daemon（让位退出）还是死 socket 残留（unlink 后重 bind 一次）
      const alive = await daemonCall({ op: "ping" }, 300).then(() => true, () => false);
      if (alive) process.exit(0);
      try { rmSync(endpoint); } catch {}
      try { server.listen(endpoint, onListen); } catch { process.exit(1); }
      return;
    }
    console.error(`senv daemon: ${e.message}`);
    process.exit(1);
  });
  server.listen(endpoint, onListen);
}

const verdictOut = (verdict) => { console.log(JSON.stringify(verdict)); process.exit(0); };

// parse：钩子时刻命令门（守卫 + 解析全部值 → 一次性槽位 + token）。
// 响应形态与 rsenv parse 逐字对齐：{ok,action:pass|reject|inject,token?,names?} / {ok:false,error}。
async function cmdParse() {
  const payload = await readStdinJson();
  const command = typeof payload?.command === "string" ? payload.command : "";
  if (!command) protocolOut({ ok: false, error: "stdin 需要 {\"command\": \"...\"}" }, 2);
  try {
    // 文件提及守卫先于一切（静态保护不依赖解锁态；与 rsenv 判定顺序一致）
    const guardHit = guardPaths(loadConfig()).find((f) => command.includes(f));
    if (guardHit) {
      verdictOut({ ok: true, action: "reject", reason: `secret-env：命令涉及受保护文件（片段「${guardHit}」）——secrets.json/vault.kdbx 含 master 口令明文与全部凭据映射，禁止 Agent 读写。配置维护请在你的终端运行 secret-env add/remove，或亲手编辑。` });
    }
    const config = loadConfig();
    if (config.size === 0) verdictOut({ ok: true, action: "pass" });
    const tokens = scanRefs(command, config, (reason) => verdictOut({ ok: true, action: "reject", reason }));
    if (tokens.length === 0) verdictOut({ ok: true, action: "pass" });

    const bad = tokens.filter((t) => t.inSingle);
    if (bad.length) {
      verdictOut({ ok: true, action: "reject", reason: `secret-env：引用位于单引号内不会被展开（${[...new Set(bad.map((t) => t.token))].join("、")}）。请改用双引号包裹，例如 "$GH_TOKEN"。` });
    }
    if (isDumpCommand(command)) {
      verdictOut({ ok: true, action: "reject", reason: "secret-env：命令同时含密钥引用与环境倾泻命令（env/printenv/set/export），会打印注入值。请把倾泻意图从命令中移除。" });
    }

    // 解析全部值，失败当场拒绝并附可用清单（宁可失败，不做魔法）
    const env = {};
    for (const name of [...new Set(tokens.map((t) => t.name))]) {
      const info = config.get(name);
      try {
        env[name] = await resolveValue(info.uri, config);
      } catch (e) {
        verdictOut({ ok: false, error: `secret-env：解析 ${name}（${info.uri}）失败：${e.message}；现有条目：${[...config.keys()].join("、")}` });
      }
    }

    const reply = await (async () => {
      await ensureDaemon();
      return daemonCall({ op: "put", env });
    })();
    if (!reply?.ok) throw new Error(reply?.error ?? "senv daemon put 失败");
    const names = tokens.map((t) => t.token.replace(/^\$\{?/, "").replace(/\}$/, ""));
    log(`parse names=${names.join(",")}`);
    verdictOut({ ok: true, action: "inject", token: reply.token, names });
  } catch (e) {
    protocolOut({ ok: false, error: e.message }, 2);
  }
}

// inject：消费一次性槽位输出 export 行（sh_quote 包裹），由同 shell 的 eval 消费。
// 一次性 = daemon 取即删（单线程顺序处理，天然 exactly-once）；无 token/已消费 → 报错退出。
async function cmdInjectToken(token) {
  if (!token) { console.error("用法：secret-env inject <token>（token 由 parse 签发，宿主钩子改写链内调用，不要手工拼）"); process.exit(2); }
  let reply;
  try {
    await ensureDaemon();
    reply = await daemonCall({ op: "redeem", token });
  } catch (e) {
    console.error(`secret-env：${e.message}`);
    process.exit(2);
  }
  if (!reply?.ok) {
    console.error(`secret-env：${reply?.error ?? "invalid or already-consumed injection token"}`);
    process.exit(2);
  }
  for (const [k, v] of Object.entries(reply.env)) {
    console.log(`export ${k}=${shellSingleQuote(String(v))}`);
  }
  log(`inject consumed names=${Object.keys(reply.env).join(",")}`);
}

// ---------- 宿主协议（protocol 1）：info / inject / store ----------
// 宿主适配器（DSH）以子进程调用；stdout 严格一行 JSON，任何响应都不含凭据值。
// 退出码：0 成功；2 业务拒绝/参数错误（JSON 带 error 或 status）；3 协议版本不匹配。
const protocolOut = (payload, code = 0) => { console.log(JSON.stringify(payload)); process.exit(code); };
const protocolDeny = (code, message, extra) => protocolOut({ ...extra, error: message, code }, 2);

async function readStdinJson() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return null; }
}

// 协议版本握手：所有命令共用
function requireProtocol(payload) {
  if (!payload || typeof payload !== "object") protocolDeny("bad-payload", "stdin 需要 JSON 对象");
  if (payload.protocol !== PROTOCOL_VERSION) {
    protocolOut({ error: `协议版本不匹配：期望 ${PROTOCOL_VERSION}，收到 ${payload.protocol ?? "无"}`, code: "protocol" }, 3);
  }
}

function packageVersion() {
  try { return JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).version ?? "0.0.0"; }
  catch { return "0.0.0"; }
}

// 清单 + 规则 + 版本：宿主启动时拉一次，配置变更（configMtime）后再拉。
// 形态与 rsenv info 逐字对齐（HOST-PROTOCOL §info）：guard_paths 蛇形 + entries[{name,desc}]，
// 外加 backend/capabilities 两个增量字段（宿主与 SKILL 按此分支，不按二进制名）。
function cmdInfo() {
  const config = loadConfig();
  let configMtime = 0;
  for (const path of configPaths()) {
    try { configMtime = Math.max(configMtime, statSync(path).mtimeMs); } catch {}
  }
  protocolOut({
    protocol: PROTOCOL_VERSION,
    version: packageVersion(),
    configMtime,
    backend: "senv",
    capabilities: { daemon: true, providers: PROVIDERS },
    guard_paths: guardPaths(config),
    entries: [...canonicalEntries(config)].map(([name, { aliases, description }]) => ({
      name,
      desc: [aliases.length ? `别名：${aliases.join("、")}` : "", description].filter(Boolean).join("；"),
    })),
  });
}

// ---------- set：统一入库（收编原 add 交互流与 store 协议入口） ----------
// 形态一：set NAME --uri provider://路径 [--desc D] [--alias A]...   登记 provider 引用，无值通道
// 形态二：set NAME [--provider P ...] [--desc D] [--alias A]...     值经 stdin（管道一行）或 TTY 隐藏输入
// 已存在且未给 --provider/--uri = 维护模式（只改别名/描述）
async function cmdSet(args) {
  const opts = { aliases: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--alias") opts.aliases.push(args[++i]);
    else if (a === "--desc") opts.description = args[++i];
    else if (a === "--provider") opts.provider = args[++i];
    else if (a === "--service") opts.service = args[++i];
    else if (a === "--path") opts.path = args[++i];
    else if (a === "--item") opts.item = args[++i];
    else if (a === "--field") opts.field = args[++i];
    else if (a === "--user") opts.user = args[++i];
    else if (a === "--uri") opts.uri = args[++i];
    else if (!a.startsWith("-")) opts.name ??= a;
    else { console.error(`未知参数：${a}`); process.exit(2); }
  }
  if (opts.provider === "system") opts.provider = "keychain"; // 弃用别名，行为一致
  if (!opts.name || args.some((a) => a === "-h" || a === "--help")) {
    console.error("用法：secret-env set NAME [--provider keychain|viking|bitwarden|onepassword ...] [--desc D] [--alias A]...\n  值经 stdin 传入（echo '值' | secret-env set NAME），TTY 裸跑则隐藏输入；值不落 argv。\n  --uri provider://路径 直接登记引用条目（无值通道）；已存在条目不带 --provider/--uri = 维护模式。\n  provider 细节同旧 add：bitwarden/onepassword 需 --item，viking 需 --path。");
    process.exit(2);
  }
  const envName = envNameFromHuman(opts.name);
  if (!envName) { console.error(`name 归一化后为空：${opts.name}`); process.exit(2); }
  const existing = (() => { try { return JSON.parse(readFileSync(CONFIG_PATH, "utf8"))[envName]; } catch { return undefined; } })();

  // 形态一：--uri 直接登记（import-secrets 同语义，无 provider 写入）
  if (opts.uri) {
    if (!/^[a-z][a-z0-9-]*:\/\//.test(opts.uri)) { console.error(`--uri 需为 scheme:// 形态：${opts.uri}`); process.exit(2); }
    const raw = updateConfig(envName, { uri: opts.uri, ...(opts.aliases.length ? { aliases: opts.aliases } : {}), ...(opts.description ? { description: opts.description } : {}) });
    console.log(`已登记 ${envName} → ${opts.uri}`);
    console.log(`secrets.json 现有条目：${Object.keys(raw).join("、")}`);
    return;
  }

  if (!opts.provider && existing) {
    console.log(`维护模式：${envName} 已存在（${existing.uri}），值不动。`);
    const raw = updateConfig(envName, { uri: existing.uri, ...(opts.aliases.length ? { aliases: opts.aliases } : {}), ...(opts.description ? { description: opts.description } : {}) });
    console.log(`secrets.json 现有条目：${Object.keys(raw).join("、")}`);
    return;
  }
  if (!opts.provider && !existing) { console.error("新条目需要 --provider（keychain|viking|bitwarden|onepassword）或 --uri（引用条目）"); process.exit(2); }

  // 形态二：收值。管道 stdin 优先（脚本/宿主兜底），TTY 裸跑隐藏输入
  let value = "";
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    value = Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
  } else {
    value = await promptHiddenValue(`输入 ${envName} 的值（隐藏输入，回车确认）: `);
  }
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
} else if (cmd === "set") await cmdSet(rest);
else if (cmd === "add") await cmdAdd(rest);
else if (cmd === "remove") await cmdRemove(rest);
else if (cmd === "list") cmdList();
else if (cmd === "parse") await cmdParse();
else if (cmd === "daemon") await cmdDaemon();
else if (cmd === "info") cmdInfo();
else if (cmd === "inject") cmdInjectToken(rest[0]);
// 这里不能 await：mcp.mjs 反向 import 本文件（storeEntry/envNameFromHuman），await 会构成 ESM 循环死锁
// ——Node 报 unsettled top-level await 并 exit 13（Bun 侥幸能跑，真实安装形态的 shebang 是 node）。
// 不 await 时本模块先求值完毕，mcp.mjs 再启动；进程由 stdin readline 保活。
else if (cmd === "mcp") import("./mcp.mjs");
else {
  console.error("用法：secret-env set|remove|list|parse|info|inject <token>|mcp（add 为 set 的兼容别名）");
  process.exit(cmd ? 2 : 0);
}
