// DSH 适配器离线回归（node adapters/dsh/tests/apply.test.mjs）：假 client + 假 ctx 走 apply 流程。
// 断言：快照构建（rsenv info 形态：guard_paths / entries{name,desc}）、
// bash 命令门三态（inject 改写 eval 链 / pass 旁路 / reject 抛错）、
// 文件守卫（guard_paths 命中拒绝）、清单文案含条目名。
import { strict as assert } from "node:assert";
import { apply, buildSnapshot } from "../index.js";
import { evaluateCall } from "../guards.mjs";

const info = {
  protocol: 1,
  guard_paths: ["/home/u/.rsenv-vault/vault.db", "/home/u/.rsenv-vault/.vault.salt", "/home/u/.rsenv-vault/audit.jsonl"],
  entries: [{ name: "GH_TOKEN", desc: "gh token" }, { name: "BW_SESSION", desc: "" }],
};

// ---- 快照构建 ----
const snap = buildSnapshot(info);
assert.equal(snap.entries.length, 2);
assert.equal(snap.config.get("GH_TOKEN").description, "gh token");
assert.deepEqual(snap.guardPaths, info.guard_paths);
console.log("snapshot build OK");

// ---- 假 ctx：收集 guard / on("tools/execute") / systemPrompt 注册 ----
const registered = { guards: [], handlers: [], sections: [] };
const ctx = {
  tools: {
    guard: (fn) => { registered.guards.push(fn); return () => {}; },
    register: () => { throw new Error("add_secret 不应注册（挂账）"); },
  },
  systemPrompt: { section: (s) => { registered.sections.push(s); return () => {}; } },
  on: (event, fn) => { if (event === "tools/execute") registered.handlers.push(fn); return () => {}; },
};

const calls = [];
const client = {
  bin: "rsenv",
  infoSync: () => info,
  info: async () => info,
  parse: async ({ command }) => {
    calls.push(command);
    if (command.includes("REF_TOKEN")) return { action: "inject", token: "tok9", names: ["GH_TOKEN"] };
    if (command.includes("dump")) return { action: "reject", reason: "dump intent" };
    return { action: "pass" };
  },
};

apply(ctx, { client });
assert.equal(registered.handlers.length, 1, "bash handler registered");
assert.equal(registered.guards.length, 1, "guard registered");
assert.equal(registered.sections.length, 1, "prompt section registered");

// ---- inject 改写 ----
const exec = { name: "bash", arguments: { command: "curl -H 'x' https://api/$REF_TOKEN" }, callId: "c1" };
await registered.handlers[0](exec, async () => "next");
assert.ok(exec.arguments.command.includes("rsenv inject tok9"), "rewrite embeds rsenv inject");
assert.ok(exec.arguments.command.includes("eval"), "rewrite evals export lines");
assert.ok(exec.arguments.command.includes("{ curl -H 'x' https://api/$REF_TOKEN; }"), "original command preserved");
assert.deepEqual(calls, ["curl -H 'x' https://api/$REF_TOKEN"], "parse received original command");
console.log("inject rewrite OK:", exec.arguments.command);

// ---- pass 旁路 ----
const exec2 = { name: "bash", arguments: { command: "echo hello" } };
await registered.handlers[0](exec2, async () => "next");
assert.equal(exec2.arguments.command, "echo hello", "pass keeps command unchanged");
console.log("pass OK");

// ---- reject 抛错 ----
let threw = "";
try {
  await registered.handlers[0]({ name: "bash", arguments: { command: "printenv dump" } }, async () => "next");
} catch (e) { threw = String(e.message ?? e); }
assert.ok(threw.includes("dump intent"), `reject throws: ${threw}`);
console.log("reject OK");

// ---- 文件守卫（guard_paths 命中）----
const reason = registered.guards[0]({ name: "read", arguments: { file_path: "/home/u/.rsenv-vault/vault.db" } });
assert.ok(reason?.includes("受保护文件"), "file guard denies vault path");
const allow = registered.guards[0]({ name: "read", arguments: { file_path: "/tmp/normal.txt" } });
assert.equal(allow, undefined, "normal path allowed");
console.log("file guard OK");

// ---- 清单文案 ----
const text = registered.sections[0].text();
assert.ok(text.includes("GH_TOKEN"), "prompt lists entry name");
assert.ok(text.includes("gh token"), "prompt lists desc");
console.log("promptText OK");

console.log("ALL PASS");
