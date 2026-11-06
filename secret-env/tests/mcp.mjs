// MCP server 协议冒烟：本测试扮演宿主（MCP client + elicitation 应答端），覆盖
//   ① 协议骨架 initialize/tools/list；② 第 1 屏 decline 零写入；③ password 支持宿主→直通表单→stored（假密钥链条目，用完即删）；
//   ④ password 拒绝宿主→无感降级选择屏→command 形态；⑤ stored 结果永不含值。
// 运行：bun secret-env/tests/mcp.mjs（HOME 重定向到临时目录，隔离真实配置）
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0, fail = 0;
const ok = (cond, label) => { cond ? pass++ : (fail++, console.error(`✗ ${label}`)); if (cond) console.log(`✓ ${label}`); };

const home = mkdtempSync(join(tmpdir(), "senv-mcp-test-"));
mkdirSync(join(home, ".config", "secret-env"), { recursive: true });
// stored 路径走 kdbx 后端（纯 JS 写入，无系统钥匙串 ACL 弹窗——无人值守测试不可用 security）
const dbPath = join(home, "test-vault.kdbx");
const MASTER = "test-master-pass";
{
  const ns = await import("kdbxweb");
  const kdbxweb = ns.Kdbx ? ns : ns.default;
  const hw = await import("hash-wasm");
  kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
    const fn = type === 0 ? hw.argon2d : hw.argon2id;
    return fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: "binary" });
  });
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(MASTER)), "secret-env-test");
  writeFileSync(dbPath, Buffer.from(await db.save()));
}
writeFileSync(join(home, ".config", "secret-env", "secrets.json"), JSON.stringify({ $keychain: { password: MASTER } }) + "\n");

const proc = spawn("node", [join(import.meta.dirname, "..", "..", "mcp.mjs")], {
  env: { ...process.env, HOME: home, LC_ALL: "zh_CN.UTF-8", SENV_VAULT_PATH: dbPath },
  stdio: ["pipe", "pipe", "inherit"],
});
let nextId = 100;
const waiters = [];
const send = (obj) => proc.stdin.write(JSON.stringify(obj) + "\n");
const request = (method, params) => new Promise((resolve) => {
  const id = nextId++;
  waiters.push({ id, resolve });
  send({ jsonrpc: "2.0", id, method, params });
});
// 扮演宿主对 elicitation 的应答策略（每个用例可改）
let respond = null;
// 通用消息泵：elicitation/create 请求按 respond 策略应答，其余带 id 消息配对给 request（行缓冲防 chunk 撕裂）
let lineBuf = "";
proc.stdout.on("data", (d) => {
  lineBuf += d.toString();
  const lines = lineBuf.split("\n");
  lineBuf = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === "elicitation/create") {
      const ans = respond(msg.params); // {action, content} | {error:true}（模拟协议校验拒绝）
      send({ jsonrpc: "2.0", id: msg.id, ...(ans.error ? { error: { code: -32602, message: "invalid schema" } } : { result: { action: ans.action, content: ans.content ?? {} } }) });
    } else {
      const w = waiters.find((x) => x.id === msg.id);
      if (w) { waiters.splice(waiters.indexOf(w), 1); w.resolve(msg); }
    }
  }
});
const inbox = [];
proc.stdout.on("data", (d) => {
  for (const line of d.toString().split("\n")) {
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === "elicitation/create") {
      const ans = respond(msg.params); // {action, content} | {error:true}（模拟协议拒绝）
      send({ jsonrpc: "2.0", id: msg.id, ...(ans.error ? { error: { code: -32602, message: "invalid schema" } } : { result: { action: ans.action, content: ans.content ?? {} } }) });
    } else {
      const w = waiters.find((x) => x.id === msg.id);
      if (w) { waiters.splice(waiters.indexOf(w), 1); w.resolve(msg); }
    }
  }
});

const cleanupKeychain = () => {}; // kdbx 临时库随 home 临时目录一起删

// ---------- ① 协议骨架 ----------
const init = await request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
ok(init.result?.serverInfo?.name === "secret-env", "① initialize 返回 serverInfo");
send({ jsonrpc: "2.0", method: "notifications/initialized" });
const list = await request("tools/list", {});
ok(list.result?.tools?.[0]?.name === "add_secret", "① tools/list 暴露 add_secret");

// ---------- ② 第 1 屏 decline：零写入 ----------
respond = () => ({ action: "decline", content: {} });
const r2 = await request("tools/call", { name: "add_secret", arguments: { name: "test x", provider: "keychain" } });
const out2 = JSON.parse(r2.result.content[0].text);
ok(out2.status === "declined", "② 第 1 屏 decline → status=declined");
ok(!readFileSync(join(home, ".config", "secret-env", "secrets.json"), "utf8").includes("TEST_X"), "② decline 零写入");

// ---------- ③ password 支持宿主：直通输入框 → stored（假密钥链条目） ----------
respond = (params) => {
  const props = params.requestedSchema?.properties ?? {};
  if (props.value?.format === "password") return { action: "accept", content: { value: "shmpw-test-123" } };
  if (props.name) return { action: "accept", content: { name: "test x", provider: "keychain", detail: "", alias: "ALT_X", description: "" } };
  return { action: "decline", content: {} };
};
const r3 = await request("tools/call", { name: "add_secret", arguments: {} });
const out3 = JSON.parse(r3.result.content[0].text);
ok(out3.status === "stored" && out3.envName === "TEST_X", "③ password 支持宿主直通 → stored TEST_X");
ok(!JSON.stringify(out3).includes("shmpw-test-123"), "③ 结果不含真值");
ok(readFileSync(join(home, ".config", "secret-env", "secrets.json"), "utf8").includes("keychain://secret-env-test-x"), "③ secrets.json 已登记");
cleanupKeychain();

// ---------- ④ password 拒绝宿主：无感降级选择屏 → command 形态 ----------
respond = (params) => {
  const props = params.requestedSchema?.properties ?? {};
  if (props.value?.format === "password") return { error: true }; // 模拟 zod 校验拒绝
  if (props.mode) return { action: "accept", content: { mode: "command" } };
  if (props.name) return { action: "accept", content: { name: "test y", provider: "keychain", detail: "", alias: "", description: "" } };
  return { action: "decline", content: {} };
};
const r4 = await request("tools/call", { name: "add_secret", arguments: {} });
const out4 = JSON.parse(r4.result.content[0].text);
ok(out4.status === "command-issued" && out4.command.startsWith("senv add -n"), "④ password 拒绝 → 选择屏 → command 形态");
ok(out4.command.includes(`--provider keychain`) && out4.command.includes('"test y"'), "④ 命令文本含名字与 provider");

// ---------- ⑤ 第 2 屏选择 decline ----------
respond = (params) => {
  const props = params.requestedSchema?.properties ?? {};
  if (props.value?.format === "password") return { error: true };
  if (props.mode) return { action: "cancel", content: {} };
  if (props.name) return { action: "accept", content: { name: "test z", provider: "keychain", detail: "", alias: "", description: "" } };
  return { action: "decline", content: {} };
};
const r5 = await request("tools/call", { name: "add_secret", arguments: {} });
ok(JSON.parse(r5.result.content[0].text).status === "cancel", "⑤ 选择屏 cancel → 不落库");

proc.stdin.end();
proc.kill();
rmSync(home, { recursive: true, force: true });
console.log(`\n${pass} 过 / ${fail} 败`);
process.exit(fail ? 1 : 0);
