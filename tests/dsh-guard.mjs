// DSH 守卫与登记逻辑离线测试：不启动 DSH、不 spawn CLI（假客户端），验证 guards.mjs / entry.mjs / 装配。
// 运行：bun tests/dsh-guard.mjs
import assert from "node:assert/strict";
import { evaluateCall, promptText } from "../adapters/dsh/guards.mjs";
import { T, interpretAnswer } from "../adapters/dsh/entry.mjs";
import { buildEntryOpts, entryCommandText } from "../entry.mjs";
import { buildSnapshot } from "../adapters/dsh/index.js";

// 快照夹具：entries 与 config 由 buildSnapshot 生成（与生产同一条构造路径）
const entries = [
  { name: "GH_TOKEN", aliases: ["GITHUB_TOKEN"], description: "demo token" },
  { name: "NPM_TOKEN", aliases: [] },
];
const PROTECTED = ".config/secret-env";
const VAULT = "~/.config/secret-env/vault.kdbx";
const GUARD_PATHS = [PROTECTED, "/opt/pkg/secret-env/secrets.json", VAULT, "/home/u/.config/secret-env/vault.kdbx"];
const snapshot = { ...buildSnapshot({ entries }), guardPaths: GUARD_PATHS };

const call = (name, args) => ({ name, arguments: args, callId: "test-call" });

let n = 0;
const check = (label, actual, expected) => {
  if (expected === "deny") assert.match(actual ?? "", /受保护文件|不注入密钥/, `${label}: 期望拒绝，实际 ${actual}`);
  else if (expected === "allow") assert.equal(actual, undefined, `${label}: 期望放行，实际 ${actual}`);
  else assert.match(actual ?? "", expected instanceof RegExp ? expected : new RegExp(expected), `${label}: 未命中`);
  n++;
};

// 文件通道
check("read 受保护配置", evaluateCall(call("read", { file_path: "~/.config/secret-env/secrets.json" }), snapshot), "deny");
check("read 普通文件", evaluateCall(call("read", { file_path: "/tmp/notes.md" }), snapshot), "allow");
check("read_image 受保护库", evaluateCall(call("read_image", { file_path: VAULT }), snapshot), "deny");
check("write 受保护配置", evaluateCall(call("write", { file_path: `${PROTECTED}/secrets.json`, content: "x" }), snapshot), "deny");
check("edit 普通文件", evaluateCall(call("edit", { file_path: "/tmp/a.md", old_string: "a", new_string: "b" }), snapshot), "allow");
check("apply_patch 命中受保护路径", evaluateCall(call("apply_patch", { patch: `*** Update File: ${PROTECTED}/secrets.json` }), snapshot), "deny");
check("apply_patch 普通路径", evaluateCall(call("apply_patch", { patch: "*** Add File: notes.md\n+hi" }), snapshot), "allow");

// 命令通道
check("bash 读受保护配置", evaluateCall(call("bash", { command: "cat ~/.config/secret-env/secrets.json" }), snapshot), "deny");
check("bash 普通命令", evaluateCall(call("bash", { command: "gh pr list" }), snapshot), "allow");
check("bash 密钥引用留给 execute 注入", evaluateCall(call("bash", { command: 'curl -H "Authorization: Bearer $GH_TOKEN" https://api.github.com' }), snapshot), "allow");
check("terminal_send 引用密钥", evaluateCall(call("terminal_send", { sessionId: "s1", text: "echo $GH_TOKEN" }), snapshot), "deny");
check("terminal_send 普通命令", evaluateCall(call("terminal_send", { sessionId: "s1", text: "ls -la" }), snapshot), "allow");
check("pwsh 引用密钥", evaluateCall(call("pwsh", { command: "Write-Host $GH_TOKEN" }), snapshot), "deny");
check("pwsh 的 $env: 读法", evaluateCall(call("pwsh", { command: "Write-Host $env:GH_TOKEN" }), snapshot), "deny");
check("pwsh 普通命令", evaluateCall(call("pwsh", { command: "Get-Location" }), snapshot), "allow");
check("其他工具不干预", evaluateCall(call("web_fetch", { url: "https://example.com" }), snapshot), "allow");
check("空快照不误伤", evaluateCall(call("bash", { command: "ls" }), { entries: [], guardPaths: [], config: new Map() }), "allow");
check("未配置占位符 → 拒绝", evaluateCall(call("terminal_send", { text: "echo {{secret:NOPE}}" }), snapshot), "占位符");

// 清单文案
const text = promptText(snapshot);
assert.match(text, /GH_TOKEN/);
assert.match(text, /GITHUB_TOKEN/);
assert.match(text, /secret-env/);
assert.match(promptText(buildSnapshot({ entries: [] })), /没有已配置/);

// add_secret 答案判定：custom 优先（单选覆盖），其次命令行选项，否则取消/跳过
const label = T.commandLabel;
assert.deepEqual(interpretAnswer({ id: "value", selected: [], custom: "sekret" }, label), { kind: "value", value: "sekret" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [label], custom: "sekret" }, label), { kind: "value", value: "sekret" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [label], custom: "" }, label), { kind: "command" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [], custom: "   " }, label), { kind: "declined" });
assert.deepEqual(interpretAnswer({ id: "value", selected: [] }, label), { kind: "declined" });

// 条目参数与命令构造（已下沉到主包 entry.mjs，由 CLI 的 store ready/command 形态使用）
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

// ---------- 装配（mock ctx + 假客户端）：不 spawn CLI ----------
const { apply } = await import("../adapters/dsh/index.js");
const info = { protocol: 1, version: "test", configMtime: 0, entries, rules: { guardPaths: GUARD_PATHS }, providers: ["keychain", "bitwarden", "viking", "onepassword"] };
const makeClient = (overrides = {}) => ({
  bin: "fake",
  infoSync: () => info,
  info: async () => info,
  inject: async () => ({ command: ". /tmp/x.sh; ls", envFile: "/tmp/x.sh" }),
  store: async () => ({ status: "ready", envName: "GH_TOKEN" }),
  ...overrides,
});
const makeCtx = (answer) => {
  const registered = {};
  const ctx = {
    tools: {
      guard(fn) { registered.guard = fn; return () => {}; },
      register(def) { registered.tool = def; return () => {}; },
    },
    systemPrompt: { section(sec) { registered.section = sec; return () => {}; } },
    userQuestions: { ask: async () => answer },
    on(name, fn) { registered[name] = fn; return () => {}; },
  };
  return { ctx, registered };
};

{
  const { ctx, registered } = makeCtx({ answers: [{ custom: "sekret-value" }] });
  apply(ctx, { client: makeClient() });
  assert.equal(typeof registered.guard, "function", "apply 应注册 tools.guard");
  assert.equal(typeof registered["tools/execute"], "function", "apply 应注册 tools/execute 包装");
  assert.equal(registered.section?.name, "secret-env", "apply 应注册 systemPrompt section");
  assert.ok(registered.section.text().length > 0, "systemPrompt 文案不应为空");
  assert.equal(registered.tool?.name, "add_secret", "apply 应注册 add_secret 工具");
  assert.equal(registered.tool.parameters?.required?.[0], "name");

  // 守卫：同步判定用快照，不 spawn（execute 里的 client 调用才算 spawn）
  assert.match(registered.guard(call("read", { file_path: "~/.config/secret-env/secrets.json" })) ?? "", /受保护文件/);
  assert.equal(registered.guard(call("read", { file_path: "/tmp/ok" })), undefined);

  // bash 注入：无引用（envFile=null）→ 原样 next；有引用 → 命令被替换
  {
    const { ctx: ctxPlain, registered: regPlain } = makeCtx({});
    apply(ctxPlain, { client: makeClient({ inject: async () => ({ command: "echo hi", envFile: null }) }) });
    let seen;
    await regPlain["tools/execute"]({ name: "bash", arguments: { command: "echo hi" }, callId: "c1" }, async () => { seen = "next"; });
    assert.equal(seen, "next");
  }
  {
    const exec = { name: "bash", arguments: { command: "echo hi" }, callId: "c2" };
    await registered["tools/execute"](exec, async () => "next");
    assert.equal(exec.arguments.command, ". /tmp/x.sh; ls", "注入命令应被替换");
  }

  // add_secret：校验 → 收值 → 入库
  {
    const calls = [];
    const client = makeClient({
      store: async (payload) => { calls.push(payload); return payload.value === undefined ? { status: "ready", envName: "GH_TOKEN" } : { status: "stored", envName: "GH_TOKEN", uri: "keychain://x" }; },
    });
    const { ctx: ctx2, registered: reg2 } = makeCtx({ answers: [{ custom: "sekret-value" }] });
    apply(ctx2, { client });
    const out = await reg2.tool.execute({ name: "github token" }, { agent: "a1", callId: "c9" });
    assert.equal(out.status, "stored");
    assert.equal(out.envName, "GH_TOKEN");
    assert.equal(calls.length, 2, "应有校验 + 入库两次调用");
    assert.equal(calls[0].value, undefined, "校验阶段不带值");
    assert.equal(calls[1].value, "sekret-value", "入库阶段的值为卡片输入");
  }

  // 命令行兜底：commandOnly 返回命令
  {
    const client = makeClient({
      store: async (payload) => payload.commandOnly ? { status: "command", command: "senv add -n x" } : { status: "ready", envName: "GH_TOKEN" },
    });
    const { ctx: ctx3, registered: reg3 } = makeCtx({ answers: [{ selected: [label] }] });
    apply(ctx3, { client });
    const out = await reg3.tool.execute({ name: "github token" }, { agent: "a1", callId: "c10" });
    assert.equal(out.status, "command-issued");
    assert.equal(out.command, "senv add -n x");
  }

  // 重复名称：CLI 的 exists 错误码 → T.exists
  {
    const client = makeClient({ store: async () => { const e = new Error("exists"); e.code = "exists"; throw e; } });
    const { ctx: ctx4, registered: reg4 } = makeCtx({ answers: [] });
    apply(ctx4, { client });
    const out = await reg4.tool.execute({ name: "github token" }, { agent: "a1", callId: "c11" });
    assert.equal(out.status, "invalid");
    assert.equal(out.message, T.exists);
  }

  // 初始化失败 = 插件不加载（宁可失败）：协议不匹配 / CLI 缺失都不静默放行
  {
    const { ctx: ctx5 } = makeCtx({ answers: [] });
    assert.throws(() => apply(ctx5, { client: makeClient({ infoSync: () => ({ protocol: 99 }) }) }), /协议版本不匹配/);
  }
  {
    const { ctx: ctx6 } = makeCtx({ answers: [] });
    const boom = new Error("无法启动 secret-env（ENOENT）");
    boom.code = "spawn";
    assert.throws(() => apply(ctx6, { client: makeClient({ infoSync: () => { throw boom; } }) }), /无法初始化/);
  }
}

console.log("OK apply wiring (+ add_secret)");
console.log(`OK ${n} guard checks + promptText + entry decisions`);
