// DSH 协议客户端回归：假 CLI 脚本覆盖 成功/业务拒绝/非 JSON/超时/缺失二进制/协议不匹配。
// 现行协议（三分法）：info 握手 + parse（stdin {command} → {action: pass|inject|reject, token?}）。
// inject（redeem）由改写命令里的 eval 链消费，不经 client——client 无此方法。
// 运行：bun tests/dsh-protocol.mjs（不碰真凭据、不依赖真实安装）
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CliError, PROTOCOL, createClient, requireProtocol } from "../adapters/dsh/client.mjs";

const DIR = mkdtempSync(join(tmpdir(), "senv-dsh-proto-"));
const writeScript = (name, body) => {
  const path = join(DIR, name);
  writeFileSync(path, `#!/usr/bin/env bun\n${body}`, { mode: 0o755 });
  chmodSync(path, 0o755);
  return path;
};

const INFO = {
  protocol: 1,
  version: "test",
  entries: [{ name: "GH_TOKEN", desc: "demo" }],
  guard_paths: [".config/secret-env"],
};

const ok = writeScript("ok.mjs", `
const cmd = process.argv[2];
const info = ${JSON.stringify(INFO)};
if (cmd === "info") process.stdout.write(JSON.stringify(info));
else if (cmd === "parse") {
  const req = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
  if (req.command === "dump") process.stdout.write(JSON.stringify({ action: "reject", reason: "dump intent" }));
  else if (req.command.includes("$")) process.stdout.write(JSON.stringify({ action: "inject", token: "tok123", names: ["GH_TOKEN"] }));
  else process.stdout.write(JSON.stringify({ action: "pass" }));
}
`);
const mismatch = writeScript("mismatch.mjs", `process.stdout.write(JSON.stringify({ protocol: 99 }));`);
const badJson = writeScript("bad-json.mjs", `process.stdout.write("not json");`);
const slow = writeScript("slow.mjs", `
const cmd = process.argv[2];
if (cmd === "info") process.stdout.write(${JSON.stringify(JSON.stringify(INFO))});
else setTimeout(() => process.stdout.write(JSON.stringify({ action: "pass" })), 400);
`);
const missing = join(DIR, "does-not-exist.mjs");

const expectError = async (label, fn, code) => {
  try {
    await fn();
    assert.fail(`${label}：应报错却成功`);
  } catch (error) {
    assert.ok(error instanceof CliError, `${label}：应抛 CliError，实际 ${error?.name}`);
    if (code) assert.equal(error.code, code, `${label}：code 期望 ${code}，实际 ${error.code}`);
  }
};

// ---------- 正常路径 ----------
{
  const client = createClient({ bin: ok });
  const info = requireProtocol(client.infoSync());
  assert.equal(info.version, "test");
  assert.equal(info.guard_paths[0], ".config/secret-env");

  const asyncInfo = requireProtocol(await client.info());
  assert.deepEqual(asyncInfo.entries, INFO.entries);

  const injected = await client.parse({ command: "echo $GH_TOKEN" });
  assert.equal(injected.action, "inject");
  assert.equal(injected.token, "tok123");

  const passed = await client.parse({ command: "echo hi" });
  assert.equal(passed.action, "pass");
  console.log("  ✅ info/infoSync/parse（inject+pass）正常");
}

// ---------- 版本握手 ----------
{
  await expectError("协议不匹配", async () => requireProtocol(await createClient({ bin: mismatch }).info()), "protocol");
  await expectError("协议不匹配（同步）", async () => requireProtocol(createClient({ bin: mismatch }).infoSync()), "protocol");
  assert.equal(PROTOCOL, 1);
  console.log("  ✅ 版本握手拒绝");
}

// ---------- 错误映射 ----------
{
  // parse 的 reject 以 JSON action 表达（退出码仍 0），不映射为 CliError——判定在调用方
  const client = createClient({ bin: ok });
  const rejected = await client.parse({ command: "dump" });
  assert.equal(rejected.action, "reject");
  assert.match(rejected.reason, /dump/);
  console.log("  ✅ 业务拒绝（JSON action，exit 0）形态");
}
{
  await expectError("非 JSON", () => createClient({ bin: badJson }).parse({ command: "x" }), "bad-output");
  console.log("  ✅ 非 JSON 输出拒绝");
}
{
  await expectError("超时", () => createClient({ bin: slow, timeoutMs: 100 }).parse({ command: "x" }), "timeout");
  console.log("  ✅ 超时拒绝");
}
{
  await expectError("缺失二进制（同步）", async () => createClient({ bin: missing }).infoSync(), "spawn");
  await expectError("缺失二进制（异步）", () => createClient({ bin: missing }).parse({ command: "x" }), "spawn");
  try { createClient({ bin: missing }).infoSync(); } catch (e) { assert.match(e.message, /无法启动/); }
  console.log("  ✅ CLI 缺失时给出指引");
}

rmSync(DIR, { recursive: true, force: true });
console.log("OK dsh protocol client");
