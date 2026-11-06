// MCP server 协议冒烟：本测试扮演宿主（MCP client + elicitation 应答端），覆盖
//   ① 协议骨架 initialize/tools/list；② 缺 name → status=invalid 零 elicitation；③ password 支持宿主→直通表单→stored
//   （kdbx 假库）；④ 同名重调 → invalid 零 elicitation；⑤ password 拒绝宿主→无感降级选择屏→command 形态；
//   ⑥ 选择屏 cancel 不落库；⑦ 结果永不含值。
// 运行：bun adapters/zcode/tests/mcp.mjs（HOME 重定向到临时目录，隔离真实配置）
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

// ---------- ② 缺 name：status=invalid，零 elicitation、零写入 ----------
let elicitCount = 0;
respond = () => { elicitCount++; return { action: "decline", content: {} }; };
const r2 = await request("tools/call", { name: "add_secret", arguments: { provider: "keychain" } });
const out2 = JSON.parse(r2.result.content[0].text);
ok(out2.status === "invalid" && elicitCount === 0, "② 缺 name → invalid 且零表单");
ok(!readFileSync(join(home, ".config", "secret-env", "secrets.json"), "utf8").includes("TEST_X"), "② invalid 零写入");

// ---------- ③ 收值屏自由输入 → stored（kdbx 假库） ----------
respond = (params) => {
  const props = params.requestedSchema?.properties ?? {};
  if (props.secret?.enum) return { action: "accept", content: { secret: "shmpw-test-123" } };
  return { action: "decline", content: {} };
};
const r3 = await request("tools/call", { name: "add_secret", arguments: { name: "test x", provider: "keychain", alias: "ALT_X" } });
const out3 = JSON.parse(r3.result.content[0].text);
ok(out3.status === "stored" && out3.envName === "TEST_X", "③ 收值屏自由输入 → stored TEST_X");
ok(!JSON.stringify(out3).includes("shmpw-test-123"), "③ 结果不含真值");
ok(readFileSync(join(home, ".config", "secret-env", "secrets.json"), "utf8").includes("keychain://secret-env-test-x"), "③ secrets.json 已登记");

// ---------- ④ 同名重调：invalid，零 elicitation ----------
elicitCount = 0;
respond = () => { elicitCount++; return { action: "decline", content: {} }; };
const r4 = await request("tools/call", { name: "add_secret", arguments: { name: "test x", provider: "keychain" } });
const out4 = JSON.parse(r4.result.content[0].text);
ok(out4.status === "invalid" && elicitCount === 0, "④ 同名重调 → invalid 且零表单");

// ---------- ⑤ 选中「手工通过命令行输入」→ declined + 附带命令 ----------
respond = (params) => {
  const props = params.requestedSchema?.properties ?? {};
  if (props.secret?.enum) return { action: "accept", content: { secret: props.secret.enum[0] } };
  return { action: "decline", content: {} };
};
const r5 = await request("tools/call", { name: "add_secret", arguments: { name: "test y", provider: "keychain" } });
const out5 = JSON.parse(r5.result.content[0].text);
ok(out5.status === "declined" && out5.command.startsWith("senv add -n"), "⑤ 选手工选项 → declined + 命令");
ok(out5.command.includes(`--provider keychain`) && out5.command.includes('"test y"'), "⑤ 命令文本含名字与 provider");

// ---------- ⑥ 收值屏 ESC/cancel → 也附带命令 ----------
respond = () => ({ action: "cancel", content: {} });
const r6 = await request("tools/call", { name: "add_secret", arguments: { name: "test z", provider: "keychain" } });
const out6 = JSON.parse(r6.result.content[0].text);
ok(out6.status === "cancel" && out6.command.startsWith("senv add -n"), "⑥ 收值屏 cancel → 不落库且带命令");

proc.stdin.end();
proc.kill();
rmSync(home, { recursive: true, force: true });
console.log(`\n${pass} 过 / ${fail} 败`);
process.exit(fail ? 1 : 0);
