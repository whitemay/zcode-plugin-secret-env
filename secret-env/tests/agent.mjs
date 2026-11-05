// agent（daemon）回归测试：bun/node secret-env/tests/agent.mjs
// 临时 agent 目录 + 假库现场生成即删；daemon 子进程结束即退。不碰真凭据。
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, readFileSync, statSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";

const dir = mkdtempSync(join(tmpdir(), "secret-env-agent-test-"));
const agentDir = join(dir, "agent");
const vaultPath = join(dir, "vault.kdbx");
// 本进程与 daemon 子进程共用同一 agent 目录（core 从 process.env 读 socket/token/审计路径）
process.env.SENV_AGENT_DIR = agentDir;
process.env.SENV_VAULT_PATH = vaultPath;
const MASTER = "agent-test-master";
let passed = 0, failed = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : "  — " + detail}`);
  ok ? passed++ : failed++;
};

// 假库（与 core 同一 argon2 注入）
const ns = await import("kdbxweb");
const kdbxweb = ns.Kdbx ? ns : ns.default;
const hw = await import("hash-wasm");
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
  const fn = type === 0 ? hw.argon2d : hw.argon2id;
  return fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: "binary" });
});
{
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(MASTER)), "agent-test");
  const e = db.createEntry(db.getDefaultGroup());
  e.fields.set("Title", "github-token");
  e.fields.set("Password", kdbxweb.ProtectedValue.fromString("ghp_AGENT_FAKE"));
  e.fields.set("env", "test");
  writeFileSync(vaultPath, Buffer.from(await db.save()), { mode: 0o600 });
}

// daemon 子进程（与宿主同运行时），agent 工件全部重定向到临时目录
const daemon = spawn(process.execPath, [join(import.meta.dirname, "..", "..", "daemon.mjs")], {
  env: { ...process.env, SENV_AGENT_DIR: agentDir, SENV_VAULT_PATH: vaultPath },
  stdio: ["ignore", "ignore", "pipe"],
});
let daemonErr = "";
daemon.stderr.on("data", (d) => { daemonErr += d.toString(); });
await new Promise((r) => setTimeout(r, 800)); // 等 socket 就绪

const { resolveValue, writeValue, agentRequest, agentTokenPath, agentAuditPath, agentSocketPath } =
  await import(join(import.meta.dirname, "..", "..", "core.mjs"));
const config = new Map();
config.keychainBackend = {}; // 无 password → daemon 模式（token 判定走文件）

const t = (name, fn) => fn().then(
  (v) => check(name, v !== false, typeof v === "string" ? v : ""),
  (e) => check(name, false, e.message)
);

await t("daemon status：运行中且锁定", async () => {
  const r = await agentRequest({ cmd: "status" }, 3000);
  return r.ok && r.locked === true;
});
await t("login 错误口令 → 响亮失败且不发 token", async () => {
  try { await agentRequest({ cmd: "login", master: "WRONG" }, 30000); return false; }
  catch (e) { return !existsSync(agentTokenPath()); }
});
await t("未登录时 resolve → 拒绝", async () => {
  try { await resolveValue("keychain://github-token", config); return false; }
  catch (e) { return e.message.includes("未登录") || e.message.includes("未运行"); }
});
await t("login 正确口令 → token 文件 0600 落盘", async () => {
  await agentRequest({ cmd: "login", master: MASTER }, 30000);
  const st = statSync(agentTokenPath());
  return existsSync(agentTokenPath()) && (st.mode & 0o777) === 0o600;
});
await t("daemon 读：一级寻址（经 core.resolveValue 路由）", async () =>
  (await resolveValue("keychain://github-token", config)) === "ghp_AGENT_FAKE");
await t("daemon 读：二级寻址自定义字段", async () =>
  (await resolveValue("keychain://github-token/env", config)) === "test");
await t("daemon 写：新条目落库（writeValue → daemon）", async () => {
  await writeValue({ provider: "keychain", service: "agent-new", user: "u1" }, "agent-pw", config);
  return (await resolveValue("keychain://agent-new", config)) === "agent-pw"
    && (await resolveValue("keychain://agent-new/username", config)) === "u1";
});
await t("错误 token → 拒绝且记审计", async () => {
  try { await agentRequest({ cmd: "resolve", token: "forged", name: "github-token" }, 3000); return false; }
  catch (e) { return e.message.includes("token"); }
});
await t("lock → token 清除 + resolve 拒绝", async () => {
  await agentRequest({ cmd: "lock" }, 3000);
  const gone = !existsSync(agentTokenPath());
  let rejected = false;
  try { await resolveValue("keychain://github-token", config); } catch { rejected = true; }
  return gone && rejected;
});
await t("审计日志含完整链路记录", async () => {
  const lines = readFileSync(agentAuditPath(), "utf8").trimEnd().split("\n").map((l) => JSON.parse(l));
  const cmds = new Set(lines.map((l) => l.cmd));
  const missing = ["login", "resolve", "write", "lock"].filter((c) => !cmds.has(c));
  const hasFailure = lines.some((l) => l.ok === false);
  if (missing.length || !hasFailure) return "cmds=[" + [...cmds].join(",") + "] missing=" + missing.join(",") + " hasFailure=" + hasFailure;
  return true;
});
await t("vault 文件 0600（写后保持）", async () => (statSync(vaultPath).mode & 0o777) === 0o600);

daemon.kill();
if (failed) console.error('daemon stderr:', daemonErr || '(空)');
rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed}/${passed + failed} checks passed, runtime=${typeof Bun !== "undefined" ? "bun" : "node " + process.version}`);
process.exit(failed ? 1 : 0);
