// kdbx 后端回归测试（读侧）：bun secret-env/tests/kdbx.mjs 或 node secret-env/tests/kdbx.mjs
// 临时假库（假口令假值）现场生成用完即删，不碰真凭据。
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const dir = mkdtempSync(join(tmpdir(), "secret-env-kdbx-test-"));
const dbPath = join(dir, "test.kdbx");
const MASTER = "test-master-pass";
let passed = 0, failed = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`);
  ok ? passed++ : failed++;
};

// ---------- 生成假库（kdbxweb，与 core 同一 argon2 注入路径） ----------
const ns = await import("kdbxweb");
const kdbxweb = ns.Kdbx ? ns : ns.default;
const hw = await import("hash-wasm");
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
  const fn = type === 0 ? hw.argon2d : hw.argon2id;
  return fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: "binary" });
});
{
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(MASTER)), "secret-env-test");
  const grp = db.getDefaultGroup();
  const sub = db.createGroup(grp, "sub");
  const mk = (g, title, fields) => {
    const e = db.createEntry(g);
    e.fields.set("Title", title);
    for (const [k, v] of Object.entries(fields)) e.fields.set(k, v);
  };
  mk(grp, "github-token", { UserName: "whitemay", Password: kdbxweb.ProtectedValue.fromString("ghp_FAKE_VALUE"), env: "production" });
  mk(grp, "plain-entry", { Password: kdbxweb.ProtectedValue.fromString("plain-pw") });
  mk(sub, "nested-entry", { UserName: "nested-user", Password: kdbxweb.ProtectedValue.fromString("nested-pw") }); // 子组条目也要可寻址
  mk(grp, "dup-entry", { Password: kdbxweb.ProtectedValue.fromString("dup-a") });
  mk(grp, "dup-entry", { Password: kdbxweb.ProtectedValue.fromString("dup-b") }); // 同名 → 歧义拒绝
  const data = await db.save();
  (await import("node:fs")).writeFileSync(dbPath, Buffer.from(data));
}

// ---------- 被测对象：core.resolveValue / writeValue / keychainBackend 走 kdbx 后端 ----------
const { loadConfig, resolveValue, writeValue, keychainBackend } = await import(join(import.meta.dirname, "..", "..", "core.mjs"));
const config = loadConfig();
config.keychainBackend = { backend: "kdbx", path: dbPath, password: MASTER };

const t = (name, fn) => fn().then(
  (v) => check(name, v !== false, typeof v === "string" ? v : ""),
  (e) => check(name, false, e.message)
);

await t("一级寻址：标题 → Password 位", async () => (await resolveValue("keychain://github-token", config)) === "ghp_FAKE_VALUE");
await t("二级寻址 /username → UserName", async () => (await resolveValue("keychain://github-token/username", config)) === "whitemay");
await t("二级寻址 /account 与 /username 同义", async () => (await resolveValue("keychain://github-token/account", config)) === "whitemay");
await t("二级寻址 /自定义字段", async () => (await resolveValue("keychain://github-token/env", config)) === "production");
await t("子组条目可寻址", async () => (await resolveValue("keychain://nested-entry", config)) === "nested-pw");
await t("不存在条目 → 人话错误", async () => {
  try { await resolveValue("keychain://no-such", config); return false; }
  catch (e) { return e.message.includes("无标题为「no-such」的条目"); }
});
await t("无此字段 → 列出现有字段", async () => {
  try { await resolveValue("keychain://github-token/nope", config); return false; }
  catch (e) { return e.message.includes("无字段「nope」") && e.message.includes("env"); }
});
await t("同名条目 → 歧义拒绝", async () => {
  try { await resolveValue("keychain://dup-entry", config); return false; }
  catch (e) { return e.message.includes("歧义"); }
});
await t("错误 master 口令 → InvalidKey 响亮失败", async () => {
  try { await resolveValue("keychain://github-token", Object.assign(new Map(), config, { keychainBackend: { backend: "kdbx", path: dbPath, password: "WRONG" } })); return false; }
  catch (e) { return /InvalidKey|invalid/i.test(e.message); }
});
await t("无 password 且未登录 agent → 人话错误提示 login", async () => {
  try { await resolveValue("keychain://x", Object.assign(new Map(), config, { keychainBackend: {} })); return false; }
  catch (e) { return e.message.includes("口令不可得") && e.message.includes("senv login"); }
});

// ---------- 写侧自治（system provider 经 keychain 分流写库） ----------
await t("写入：新建条目（writeValue system）", async () => {
  await writeValue({ provider: "keychain", service: "new-entry", user: "u1" }, "new-pw", config);
  return (await resolveValue("keychain://new-entry", config)) === "new-pw"
    && (await resolveValue("keychain://new-entry/username", config)) === "u1";
});
await t("写入：已存在条目 upsert（值轮换，user 不给不覆盖 UserName）", async () => {
  await writeValue({ provider: "keychain", service: "new-entry" }, "rotated-pw", config);
  return (await resolveValue("keychain://new-entry", config)) === "rotated-pw"
    && (await resolveValue("keychain://new-entry/username", config)) === "u1";
});
await t("写入：弃用别名 provider=system 仍可写（兼容路径）", async () => {
  await writeValue({ provider: "system", service: "alias-compat-entry" }, "alias-pw", config);
  return (await resolveValue("keychain://alias-compat-entry", config)) === "alias-pw";
});
await t("写入：同名多条 → 歧义拒绝", async () => {
  try { await writeValue({ provider: "keychain", service: "dup-entry" }, "x", config); return false; }
  catch (e) { return e.message.includes("歧义"); }
});
await t("删除：remove 命中 + 删除未命中返回 false", async () => {
  const backend = await keychainBackend(config);
  const hit = await backend.remove("new-entry");
  const miss = await backend.remove("new-entry");
  return hit === true && miss === false
    && !(await (async () => { try { await resolveValue("keychain://new-entry", config); return true; } catch { return false; } })());
});
await t("写入落盘后重开库仍可读（进程内缓存一致性）", async () => {
  await writeValue({ provider: "keychain", service: "persist-entry" }, "persist-pw", config);
  return (await resolveValue("keychain://persist-entry", config)) === "persist-pw";
});
// 回退路径：无 keychainBackend → 走系统密钥库（本机 macOS 应能解析已登记的真实条目，如 bw-session）
if (process.platform === "darwin") {
  await t("未配置 kdbx → 回退系统密钥库（真实条目 bw-session 只验非空，不打印）", async () => {
    const real = loadConfig();
    if (!real.has("BW_SESSION")) return "skip: 本机无 BW_SESSION 条目";
    const v = await resolveValue("keychain://bw-session", real);
    return v.length > 0 && !v.includes(" ");
  });
}

rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed}/${passed + failed} checks passed, runtime=${typeof Bun !== "undefined" ? "bun" : "node " + process.version}`);
process.exit(failed ? 1 : 0);
