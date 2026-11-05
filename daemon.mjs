#!/usr/bin/env node
// senv agent daemon（可选组件）：master 口令只驻本进程内存，不落盘；
// 每次请求现场加载 vault（argon2 解密）→ 取值/写入 → 释放，不保留解密态。
// 协议 = unix socket + newline-JSON，功能独立：login/resolve/write/remove/lock/status，
// 无任何本仓库内部状态耦合（核心逻辑只经 core.mjs 的 kdbxBackend/loadConfig 复用），
// 将来可用任意语言（如 Rust）平替实现——只需实现同一 socket 路径与同一消息形状。
// 鉴权 = token 调用指纹（login 时构造、写 0600 token 文件、请求时携带、timingSafeEqual 判定）；
// 所有请求全量审计（audit.jsonl，含调用方自报 pid/exe）。
// 空闲 TTL 自动上锁（SENV_TTL_MINUTES，默认 480 = 8 小时；0 = 永不过期，仅手动 lock）。
import { createServer } from "node:net";
import { writeFileSync, readFileSync, unlinkSync, appendFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";

const { agentDir, agentSocketPath, agentTokenPath, agentAuditPath, vaultPath, loadConfig, kdbxBackend } = await import(new URL("./core.mjs", import.meta.url).href);

const TTL_MS = (Number(process.env.SENV_TTL_MINUTES) || 480) * 60_000;
const SOCK = agentSocketPath(), TOKEN_FILE = agentTokenPath(), AUDIT = agentAuditPath();
let master = null; // 口令字符串；lock 时清空——本 daemon 唯一秘密，除此之外无任何解密态
let token = null;
let ttlTimer = null;

const audit = (entry) => {
  try {
    mkdirSync(agentDir(), { recursive: true });
    appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), uid: process.getuid?.() ?? null, ...entry }) + "\n", { mode: 0o600 });
  } catch {}
};
const touchTTL = () => {
  if (ttlTimer) clearTimeout(ttlTimer);
  if (TTL_MS > 0) ttlTimer = setTimeout(() => { doLock("ttl"); }, TTL_MS);
  if (ttlTimer?.unref) ttlTimer.unref();
};
const doLock = (why) => {
  master = null;
  token = null;
  try { unlinkSync(TOKEN_FILE); } catch {}
  audit({ cmd: "lock", ok: true, note: why });
  console.error(`[${new Date().toISOString()}] locked (${why})`);
};

// 用口令现场加载 vault 验证（cache:false，验完即弃）
const vaultFile = () => process.env.SENV_VAULT_PATH ?? loadConfig().keychainBackend?.path ?? vaultPath();
async function verifyVault(password) {
  await kdbxBackend({ path: vaultFile(), password }, { cache: false }); // 抛错 = 口令不对/库损坏
}

function tokenOk(reqToken) {
  if (!token || !reqToken) return false;
  const a = Buffer.from(String(reqToken)), b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function handle(msg) {
  const claimed = { pid: msg._pid ?? null, exe: msg._exe ?? null };
  const reply = async (fn) => {
    try { const r = await fn(); audit({ cmd: msg.cmd, ok: true, name: msg.name ?? msg.service ?? null, ...claimed }); return { ok: true, ...r }; }
    catch (e) { audit({ cmd: msg.cmd, ok: false, name: msg.name ?? msg.service ?? null, error: e.message, ...claimed }); return { ok: false, error: e.message }; }
  };
  if (msg.cmd === "login") {
    const auditLogin = (ok, error) => audit({ cmd: "login", ok, name: null, error, ...claimed });
    if (typeof msg.master !== "string" || !msg.master) { auditLogin(false, "login 缺 master 口令"); return { ok: false, error: "login 缺 master 口令" }; }
    try {
      await verifyVault(msg.master); // 口令不对在此响亮失败，不改变任何状态
    } catch (e) {
      auditLogin(false, e.message);
      return { ok: false, error: e.message };
    }
    master = msg.master;
    token = randomBytes(32).toString("base64url");
    mkdirSync(agentDir(), { recursive: true });
    writeFileSync(TOKEN_FILE, token + "\n", { mode: 0o600 });
    touchTTL();
    auditLogin(true, null);
    return { ok: true };
  }
  if (msg.cmd === "status") return { ok: true, locked: master === null, socket: SOCK };
  if (msg.cmd === "lock") {
    const was = master !== null;
    if (was) doLock("request");
    return { ok: true, locked: true };
  }
  if (!tokenOk(msg.token)) {
    audit({ cmd: msg.cmd, ok: false, name: msg.name ?? msg.service ?? null, error: "token 不符", ...claimed });
    return { ok: false, error: "调用指纹（token）不符——先执行 senv login" };
  }
  if (master === null) { doLock("expired-manual"); return { ok: false, error: "agent 已锁定——先执行 senv login" }; }
  touchTTL();
  const backend = await kdbxBackend({ path: vaultFile(), password: master }, { cache: false }); // 每请求现场加载，不留解密态
  if (msg.cmd === "resolve") {
    const value = await backend.read(msg.name, msg.field ?? null);
    return { ok: true, value };
  }
  if (msg.cmd === "write") {
    if (typeof msg.value !== "string") return { ok: false, error: "write 缺 value" };
    await backend.write(msg.service, msg.value, msg.user ?? null);
    return { ok: true };
  }
  if (msg.cmd === "remove") {
    const hit = await backend.remove(msg.service);
    return { ok: true, hit };
  }
  return { ok: false, error: `未知 cmd：${msg.cmd}` };
}

// 启动：清理陈旧 socket 文件，同路径旧 daemon 存活时 bind 会失败 → 直接报错退出（单例语义）
mkdirSync(agentDir(), { recursive: true });
try { if (existsSync(SOCK) && statSync(SOCK).isSocket()) unlinkSync(SOCK); } catch {}
const server = createServer((sock) => {
  let buf = "";
  sock.on("data", async (d) => {
    buf += d.toString();
    if (!buf.endsWith("\n")) return;
    let msg = null, res;
    try { msg = JSON.parse(buf); } catch { res = { ok: false, error: "请求非合法 JSON" }; }
    if (msg) { try { res = await handle(msg); } catch (e) { res = { ok: false, error: e.message }; } }
    sock.end(JSON.stringify(res) + "\n");
  });
});
server.on("error", (e) => {
  console.error(`daemon 启动失败：${e.message}（socket=${SOCK}；若旧 daemon 仍在运行属正常，先 senv lock 或 kill 旧进程）`);
  process.exit(1);
});
server.listen(SOCK);
console.error(`[${new Date().toISOString()}] senv agent listening on ${SOCK} (ttl=${TTL_MS / 60000}min)`);
