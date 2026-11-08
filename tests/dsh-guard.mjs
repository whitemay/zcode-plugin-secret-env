// DSH 守卫与登记逻辑离线测试：不启动 DSH、不 spawn CLI（假客户端），验证 guards.mjs / entry.mjs / 装配。
// 运行：bun tests/dsh-guard.mjs
import assert from "node:assert/strict";
import { evaluateCall, promptText } from "../adapters/dsh/guards.mjs";
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
check("bash 受保护路径交给 CLI inject（本地放行）", evaluateCall(call("bash", { command: "cat ~/.config/secret-env/secrets.json" }), snapshot), "allow");
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
// rsenv info 快照只有 name+desc（无 aliases 概念），清单只列名字
assert.doesNotMatch(text, /GITHUB_TOKEN/);
assert.match(promptText(buildSnapshot({ entries: [] })), /没有已配置/);

// add_secret 流程断言挂账：rsenv 尚无元数据入库子命令（set 只收名字+值），流程成型后随实现补测试。

// ---------- 装配（mock ctx + 假客户端）：不 spawn CLI ----------
const { apply } = await import("../adapters/dsh/index.js");
const info = { protocol: 1, version: "test", entries, guard_paths: GUARD_PATHS };
const makeClient = (overrides = {}) => ({
  bin: "fake",
  infoSync: () => info,
  info: async () => info,
  parse: async () => ({ action: "pass" }),
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
  assert.equal(registered.section?.name, "rsenv", "apply 应注册 systemPrompt section");
  assert.ok(registered.section.text().length > 0, "systemPrompt 文案不应为空");
  // add_secret 挂账（rsenv 尚无元数据入库子命令），工具未注册，流程成型后补断言

  // 守卫：同步判定用快照，不 spawn（execute 里的 client 调用才算 spawn）
  assert.match(registered.guard(call("read", { file_path: "~/.config/secret-env/secrets.json" })) ?? "", /受保护文件/);
  assert.equal(registered.guard(call("read", { file_path: "/tmp/ok" })), undefined);

  // bash 门：parse pass → 原样 next；inject → 命令改写为一次性 token eval 链
  {
    const { ctx: ctxPlain, registered: regPlain } = makeCtx({});
    apply(ctxPlain, { client: makeClient({ parse: async () => ({ action: "pass" }) }) });
    let seen;
    await regPlain["tools/execute"]({ name: "bash", arguments: { command: "echo hi" }, callId: "c1" }, async () => { seen = "next"; });
    assert.equal(seen, "next");
  }
  {
    const client = makeClient({ parse: async () => ({ action: "inject", token: "tok123", names: ["GH_TOKEN"] }) });
    const { ctx: ctxInj, registered: regInj } = makeCtx({});
    apply(ctxInj, { client });
    const exec = { name: "bash", arguments: { command: "echo hi" }, callId: "c2" };
    await regInj["tools/execute"](exec, async () => "next");
    assert.match(exec.arguments.command, /_senv_inj="\$\(fake inject tok123\)"/, "注入命令应改写为 eval 链");
    assert.match(exec.arguments.command, /\{ echo hi; \}/, "原命令应在链尾");
  }
  // 命令守卫由 CLI parse 执行：即使没有配置条目也要走一次（否则受保护路径漏拦）
  {
    const calls = [];
    const client = makeClient({
      parse: async (payload) => { calls.push(payload); return { action: "pass" }; },
    });
    const { ctx: ctxEmpty, registered: regEmpty } = makeCtx({});
    apply(ctxEmpty, { client });
    await regEmpty["tools/execute"]({ name: "bash", arguments: { command: "cat guarded" }, callId: "c3" }, async () => "next");
    assert.equal(calls.length, 1, "无配置条目时也要调 parse（命令守卫在 CLI）");
  }
  // parse 的守卫拒绝 → 转成 tool error（宁可失败）
  {
    const client = makeClient({ parse: async () => ({ action: "reject", reason: "secret-env：命令涉及受保护文件" }) });
    const { ctx: ctxGuard, registered: regGuard } = makeCtx({});
    apply(ctxGuard, { client });
    await assert.rejects(
      regGuard["tools/execute"]({ name: "bash", arguments: { command: "cat guarded" }, callId: "c4" }, async () => "next"),
      /受保护文件/,
    );
  }

  // add_secret 流程断言挂账（工具未注册），rsenv 元数据入库子命令成型后随实现补测试。

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

console.log("OK apply wiring");
console.log(`OK ${n} guard checks + promptText + apply wiring`);
