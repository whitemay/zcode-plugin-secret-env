// DSH 守卫与登记逻辑离线测试：不启动 DSH，直接验证 guards.mjs / entry.mjs 的判定与文案。
// 运行：bun tests/dsh-guard.mjs
import assert from "node:assert/strict";
import { evaluateCall, promptText } from "../adapters/dsh/guards.mjs";
import { T, buildEntryOpts, entryCommandText, interpretAnswer } from "../adapters/dsh/entry.mjs";
import { guardPaths } from "../core.mjs";

const config = new Map([
  ["GH_TOKEN", { canonical: "GH_TOKEN", uri: "viking://demo/gh", description: "demo token" }],
  ["GITHUB_TOKEN", { canonical: "GH_TOKEN", uri: "viking://demo/gh" }],
  ["NPM_TOKEN", { canonical: "NPM_TOKEN", uri: "viking://demo/npm" }],
]);

const call = (name, args) => ({ name, arguments: args, callId: "test-call" });
const fragments = guardPaths(config);
const protectedFragment = fragments.find((f) => f.includes(".config/secret-env"));
const vaultFragment = fragments[fragments.length - 1];
assert.ok(protectedFragment, "guardPaths 应包含 .config/secret-env 片段");
assert.ok(vaultFragment, "guardPaths 应包含 vault 路径");

let n = 0;
const check = (label, actual, expected) => {
  if (expected === "deny") assert.match(actual ?? "", /受保护文件|不注入密钥/, `${label}: 期望拒绝，实际 ${actual}`);
  else if (expected === "allow") assert.equal(actual, undefined, `${label}: 期望放行，实际 ${actual}`);
  else assert.match(actual ?? "", expected, `${label}: 未命中`);
  n++;
};

// 文件通道
check("read 受保护配置", evaluateCall(call("read", { file_path: "~/.config/secret-env/secrets.json" }), config), "deny");
check("read 普通文件", evaluateCall(call("read", { file_path: "/tmp/notes.md" }), config), "allow");
check("read_image 受保护库", evaluateCall(call("read_image", { file_path: vaultFragment }), config), "deny");
check("write 受保护配置", evaluateCall(call("write", { file_path: protectedFragment + "/secrets.json", content: "x" }), config), "deny");
check("edit 普通文件", evaluateCall(call("edit", { file_path: "/tmp/a.md", old_string: "a", new_string: "b" }), config), "allow");
check("apply_patch 命中受保护路径", evaluateCall(call("apply_patch", { patch: `*** Update File: ${protectedFragment}/secrets.json` }), config), "deny");
check("apply_patch 普通路径", evaluateCall(call("apply_patch", { patch: "*** Add File: notes.md\n+hi" }), config), "allow");

// 命令通道
check("bash 读受保护配置", evaluateCall(call("bash", { command: "cat ~/.config/secret-env/secrets.json" }), config), "deny");
check("bash 普通命令", evaluateCall(call("bash", { command: "gh pr list" }), config), "allow");
check("bash 密钥引用留给 execute 注入", evaluateCall(call("bash", { command: 'curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com' }), config), "allow");
check("terminal_send 引用密钥", evaluateCall(call("terminal_send", { sessionId: "s1", text: "echo $GH_TOKEN" }), config), "deny");
check("terminal_send 普通命令", evaluateCall(call("terminal_send", { sessionId: "s1", text: "ls -la" }), config), "allow");
check("pwsh 引用密钥", evaluateCall(call("pwsh", { command: "Write-Host $GH_TOKEN" }), config), "deny");
check("pwsh 的 $env: 读法", evaluateCall(call("pwsh", { command: "Write-Host $env:GH_TOKEN" }), config), "deny");
check("pwsh 普通命令", evaluateCall(call("pwsh", { command: "Get-Location" }), config), "allow");
check("其他工具不干预", evaluateCall(call("web_fetch", { url: "https://example.com" }), config), "allow");

// 清单文案
const text = promptText(config);
assert.match(text, /GH_TOKEN/);
assert.match(text, /GITHUB_TOKEN/);
assert.match(text, /secret-env/);
assert.match(promptText(new Map()), /没有已配置/);

// add_secret 答案判定：custom 优先（单选覆盖），其次命令行选项，否则取消/跳过
const label = T.commandLabel;
assert.deepEqual(interpretAnswer({ id: "value", selected: [], custom: "sekret" }, label), { kind: "value", value: "sekret" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [label], custom: "sekret" }, label), { kind: "value", value: "sekret" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [label], custom: "" }, label), { kind: "command" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [], custom: "   " }, label), { kind: "declined" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [] }, label), { kind: "declined" });

// 条目参数与命令构造（与 mcp.mjs 同形）
const picked = { name: "github token", provider: "bitwarden", detail: "GitHub", alias: "gh-token, gh", description: "PAT" };
const opts = buildEntryOpts(picked);
assert.equal(opts.provider, "bitwarden");
assert.deepEqual(opts.aliases, ["gh-token", "gh"]);
assert.equal(opts.item, "GitHub");
assert.equal(opts.path, undefined);
const cmd = entryCommandText(picked);
assert.match(cmd, /^senv add -n "github token" --provider bitwarden/);
assert.match(cmd, /--item "GitHub"/);
assert.match(cmd, /--alias "gh-token" --alias "gh"/);
assert.match(cmd, /--desc "PAT"/);
const keychainOpts = buildEntryOpts({ name: "x", provider: "keychain", detail: "", alias: "", description: "" });
assert.equal(keychainOpts.item, undefined);
assert.equal(keychainOpts.path, undefined);

// 插件装配（mock ctx）：确认 apply 注册 guard / systemPrompt section / tools/execute 包装 / add_secret 工具。
const { apply } = await import("../adapters/dsh/index.js");
const registered = {};
const ctx = {
  tools: {
    guard(fn) { registered.guard = fn; return () => {}; },
    register(def) { registered.tool = def; return () => {}; },
  },
  systemPrompt: { section(sec) { registered.section = sec; return () => {}; } },
  userQuestions: { ask: async () => ({ answers: [] }) },
  on(name, fn) { registered[name] = fn; return () => {}; },
};
apply(ctx);
assert.equal(typeof registered.guard, "function", "apply 应注册 tools.guard");
assert.equal(typeof registered["tools/execute"], "function", "apply 应注册 tools/execute 包装");
assert.equal(registered.section?.name, "secret-env", "apply 应注册 systemPrompt section");
assert.ok(registered.section.text().length > 0, "systemPrompt 文案不应为空");
assert.equal(registered.tool?.name, "add_secret", "apply 应注册 add_secret 工具");
assert.equal(typeof registered.tool.execute, "function");
assert.equal(registered.tool.parameters?.required?.[0], "name");
console.log("OK apply wiring (+ add_secret)");
console.log(`OK ${n} guard checks + promptText + entry decisions`);
