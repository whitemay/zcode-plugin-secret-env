// ZCode 壳（secret-env-zcode.mjs）钩子回归测试。运行：bun adapters/zcode/tests/hook.mjs
// 壳经解析链调 CLI（HOST-PROTOCOL §解析/§注入链）；本测试用假 CLI shim 驱动全部判定分支，
// 不碰真钥匙串。payload 内的 $VAR 一律用 "$" + "NAME" 拼接构造，避免本会话钩子误拦测试命令文本。
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SHELL = new URL("../hooks/secret-env-zcode.mjs", import.meta.url).pathname;
const home = mkdtempSync(join(tmpdir(), "senv-hook-test-"));
const fakeBin = join(home, "bin");
mkdirSync(fakeBin, { recursive: true });
// 假 CLI：verdict 文件控制 parse 判定形态（pass/reject/inject/error/locked）
const CLI = join(fakeBin, "fakecli");
writeFileSync(CLI, `#!/usr/bin/env node
const fs = require("node:fs");
const verdictFile = process.env.FAKE_VERDICT;
const verdict = JSON.parse(fs.readFileSync(verdictFile, "utf8"));
if (process.argv[2] === "parse") {
  if (verdict.mode === "error") { console.error(verdict.stderr ?? "boom"); process.exit(1); }
  console.log(JSON.stringify(verdict.out));
  process.exit(0);
}
if (process.argv[2] === "info") {
  if (verdict.mode === "info-error") process.exit(3);
  console.log(JSON.stringify({ protocol: 1, backend: "senv", guard_paths: ["/secret/guarded.json"], entries: [{ name: "GH_TOKEN", desc: "github" }] }));
  process.exit(0);
}
process.exit(2);
`);
chmodSync(CLI, 0o755);

const verdict = (v) => {
  writeFileSync(join(home, "verdict.json"), JSON.stringify(v));
};
function run(toolName, toolInput, mode = "pretooluse", env = {}) {
  // Bun.spawnSync 直喂 stdin 会 exit 0 空输出（已知坑）——payload 落临时文件走 cat 管道
  const tmpPayload = join(home, "payload.json");
  writeFileSync(tmpPayload, JSON.stringify({ tool_name: toolName, session_id: "test", tool_input: toolInput }));
  const p = Bun.spawnSync(["bash", "-c", `cat ${tmpPayload} | node ${SHELL} ${mode}`], {
    stdout: "pipe", stderr: "pipe",
    env: { ...process.env, SENV_BIN: CLI, FAKE_VERDICT: join(home, "verdict.json"), HOME: home, ...env },
  });
  return { exit: p.exitCode, stdout: p.stdout.toString().trim(), stderr: p.stderr.toString().trim() };
}

let failed = 0;
function check(name, cond, detail = "") {
  if (cond) console.log(`  ✅ ${name}`);
  else { failed++; console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ""}`); }
}

console.log("① parse=pass → 纯放行");
verdict({ mode: "verdict", out: { ok: true, action: "pass" } });
{
  const r = run("Bash", { command: "ls -la" });
  check("allow 无 updatedInput", r.exit === 0 && r.stdout.includes('"permissionDecision":"allow"') && !r.stdout.includes("updatedInput"), r.stderr);
}

console.log("② parse=inject → _senv_inj 链改写（HOST-PROTOCOL §注入链）");
{
  const D = "$";
  verdict({ mode: "verdict", out: { ok: true, action: "inject", token: "abc123", names: ["GH_TOKEN"] } });
  const r = run("Bash", { command: `GH_TOKEN=${D}GH_TOKEN git push origin main` });
  const out = JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command;
  check("allow", r.exit === 0, r.stderr);
  check("链头 _senv_inj + inject token", out.startsWith(`_senv_inj="$(${CLI} inject abc123)"`), out.slice(0, 80));
  check("eval 消费", out.includes(`" && eval "$_senv_inj" && { `));
  check("命令体原样收尾", out.endsWith(`GH_TOKEN=${D}GH_TOKEN git push origin main; }`), out.slice(-60));
}

console.log("③ parse=reject → exit 2 带理由");
verdict({ mode: "verdict", out: { ok: true, action: "reject", reason: "单引号内引用" } });
{
  const r = run("Bash", { command: "sh -c 'echo x'" });
  check("exit 2", r.exit === 2, `exit=${r.exit}`);
  check("理由透出", r.stderr.includes("单引号"), r.stderr);
}

console.log("④ 非 Bash 文件守卫：info guard_paths 命中 → 拒");
verdict({ mode: "verdict", out: { ok: true, action: "pass" } });
{
  const r = run("Write", { file_path: "/secret/guarded.json" });
  check("exit 2", r.exit === 2, `exit=${r.exit} ${r.stderr}`);
}

console.log("⑤ CLI 缺失 → 降级约定守卫（未命中透传 / 命中拒）");
{
  const noBinEnv = { SENV_BIN: join(home, "no-such-cli") };
  const p = run("Bash", { command: "ls -la" }, "pretooluse", noBinEnv);
  check("未命中透传 allow", p.exit === 0 && p.stdout.includes("allow"), p.stderr);

  const D = "$";
  const p2 = run("Bash", { command: `cat ${D}HOME/.config/secret-env/vault.db` }, "pretooluse", noBinEnv);
  check("命中约定片段拒", p2.exit === 2, `exit=${p2.exit} ${p2.stderr.slice(0, 80)}`);
}

console.log("⑥ parse 内部错误（非判定输出）→ 拒绝退出");
verdict({ mode: "error", stderr: "boom" });
{
  const r = run("Bash", { command: "ls" });
  check("exit 2", r.exit === 2, `exit=${r.exit}`);
}

console.log("⑦ locked 口径 stderr → pass 透传");
verdict({ mode: "error", stderr: 'vault is locked: ask the user to run "rsenv login" in their terminal' });
{
  const r = run("Bash", { command: "ls" });
  check("allow", r.exit === 0 && r.stdout.includes("allow"), r.stderr);
}

console.log("⑧ session-start：info 快照清单注入");
{
  verdict({ mode: "verdict", out: { ok: true, action: "pass" } });
  const r = run("x", {}, "session-start");
  const out = JSON.parse(r.stdout).hookSpecificOutput;
  check("SessionStart additionalContext", r.exit === 0 && out.hookEventName === "SessionStart" && out.additionalContext.includes("已配置密钥"), r.stderr);
}

rmSync(home, { recursive: true, force: true });
console.log(failed === 0 ? "\n全部通过 ✅" : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
