// DSH 协议客户端回归：假 CLI 脚本覆盖 成功/业务拒绝/非 JSON/超时/缺失二进制/协议不匹配。
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
  entries: [{ name: "GH_TOKEN", aliases: ["GITHUB_TOKEN"], description: "demo" }],
  rules: { guardPaths: [".config/secret-env"] },
  providers: ["keychain", "bitwarden", "viking", "onepassword"],
};

const ok = writeScript("ok.mjs", `
const cmd = process.argv[2];
const info = ${JSON.stringify(INFO)};
if (cmd === "info") process.stdout.write(JSON.stringify(info));
else if (cmd === "inject") process.stdout.write(JSON.stringify({ command: ". /tmp/x.sh; ls", envFile: "/tmp/x.sh" }));
else process.stdout.write(JSON.stringify({ status: "ready", envName: "GH_TOKEN" }));
`);
const mismatch = writeScript("mismatch.mjs", `process.stdout.write(JSON.stringify({ protocol: 99 }));`);
const deny = writeScript("deny.mjs", `
process.stdout.write(JSON.stringify({ error: "引用位于单引号内", code: "inject" }));
process.exit(2);
`);
const badJson = writeScript("bad-json.mjs", `process.stdout.write("not json");`);
const slow = writeScript("slow.mjs", `
const cmd = process.argv[2];
if (cmd === "info") process.stdout.write(${JSON.stringify(JSON.stringify(INFO))});
else setTimeout(() => process.stdout.write(JSON.stringify({ command: "x", envFile: null })), 400);
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
  assert.equal(info.rules.guardPaths[0], ".config/secret-env");

  const asyncInfo = requireProtocol(await client.info());
  assert.deepEqual(asyncInfo.entries, INFO.entries);

  const injected = await client.inject({ command: "echo hi", session: "s1" });
  assert.equal(injected.command, ". /tmp/x.sh; ls");
  assert.equal(injected.envFile, "/tmp/x.sh");

  const stored = await client.store({ name: "x" });
  assert.equal(stored.status, "ready");
  assert.equal(stored.envName, "GH_TOKEN");
  console.log("  ✅ info/infoSync/inject/store 正常");
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
  const client = createClient({ bin: deny });
  await expectError("业务拒绝", () => client.inject({ command: "x" }), "inject");
  try { await client.inject({ command: "x" }); } catch (e) { assert.match(e.message, /单引号/); }
  console.log("  ✅ 业务拒绝（exit 2）映射");
}
{
  await expectError("非 JSON", () => createClient({ bin: badJson }).inject({ command: "x" }), "bad-output");
  console.log("  ✅ 非 JSON 输出拒绝");
}
{
  await expectError("超时", () => createClient({ bin: slow, timeoutMs: 100 }).inject({ command: "x" }), "timeout");
  console.log("  ✅ 超时拒绝");
}
{
  await expectError("缺失二进制（同步）", async () => createClient({ bin: missing }).infoSync(), "spawn");
  await expectError("缺失二进制（异步）", () => createClient({ bin: missing }).inject({ command: "x" }), "spawn");
  try { createClient({ bin: missing }).infoSync(); } catch (e) { assert.match(e.message, /全局安装/); }
  console.log("  ✅ CLI 缺失时给出安装指引");
}

rmSync(DIR, { recursive: true, force: true });
console.log("OK dsh protocol client");
