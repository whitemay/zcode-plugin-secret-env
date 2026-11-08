// ZCode 宿主适配壳（harness 专属逻辑集中于此，CLI 宿主无关）：
//   node secret-env-zcode.mjs session-start   → SessionStart 清单注入（additionalContext）
//   node secret-env-zcode.mjs pretooluse      → PreToolUse 分流：Bash=命令门 / 其余=文件守卫
// 运行时中立（node），零依赖；CLI 经解析链调用（HOST-PROTOCOL §解析：SENV_BIN > rsenv > secret-env）。
// 协议与 rsenv/senv 0.4 同构（parse/inject/info，protocol 1）；口径：CLI 不在 PATH 或门报错 → 拒绝退出
// （宁可失败，不静默放行）；解析失败放行。

import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// 二进制解析链（HOST-PROTOCOL §解析）：SENV_BIN 显式指定 > secrets.json $backend 键 > 默认 senv。
// 探测 = PATH 逐目录找可执行文件（不 spawn，避免探测开销进钩子路径）。
function configuredBackend() {
  try {
    const cfg = JSON.parse(readFileSync(join(process.env.HOME ?? "", ".config/secret-env", "secrets.json"), "utf8"));
    return cfg?.$backend === "rsenv" ? "rsenv" : null; // 其余值一律视为未配置（senv 是缺省）
  } catch { return null; }
}

const BIN = (() => {
  if (process.env.SENV_BIN) return process.env.SENV_BIN;
  // $backend 显式指定时该后端优先；缺省 senv（secret-env）优先，装了什么用什么
  const order = configuredBackend() === "rsenv" ? ["rsenv", "secret-env"] : ["secret-env", "rsenv"];
  for (const name of order) {
    for (const dir of (process.env.PATH ?? "").split(":")) {
      if (!dir) continue;
      try {
        const p = `${dir}/${name}`;
        if (existsSync(p)) return p;
      } catch {}
    }
  }
  return order[0]; // 双缺省兜底：后续 spawn ENOENT 走降级/拒绝路径
})();

// 注入链模板（HOST-PROTOCOL §注入链，两端逐字一致）：token 一次性、&& 链 fail-closed
const injectChain = (command, token) => `_senv_inj="$(${BIN} inject ${token})" && eval "$_senv_inj" && { ${command}; }`;
const LOG = "/tmp/rsenv-zcode.log";
const log = (msg) => { try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {} };

// 降级守卫（2026-11-08 用户定调）：rsenv 不可用时保护缺省工作目录——约定路径（声明不可配），
// 与 rsenv guard_fragments 同源，约定变更须双侧同步（opencode 适配器有同款常量）
const FALLBACK_FRAGMENTS = (() => {
  const dir = `${process.env.HOME ?? ""}/.config/secret-env`;
  return [
    ".config/secret-env",
    ...["vault.db", "vault.db-wal", "vault.db-shm", ".vault.salt", "audit.jsonl", "daemon.sock"].map((f) => `${dir}/${f}`),
  ];
})();

const allow = (updated) => {
  const out = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } };
  if (updated) out.hookSpecificOutput.updatedInput = updated;
  console.log(JSON.stringify(out));
  process.exit(0);
};
const deny = (reason) => { console.error(`secret-env: ${reason}`); process.exit(2); };

function runRsenv(args, input) {
  const r = spawnSync(BIN, args, { input: input ?? "", encoding: "utf8", timeout: 15000 });
  if (r.error && r.error.code === "ENOENT") {
    return { missing: true };
  }
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// ---------- session-start：清单注入（文案在插件侧拼，素材来自 rsenv info 快照） ----------
function sessionStart() {
  const r = runRsenv(["info"]);
  if (r.missing || r.code !== 0) { log(`session-start: rsenv unavailable, pass-through`); process.exit(0); }
  let info = null;
  try { info = JSON.parse(r.stdout); } catch { process.exit(0); }
  const entries = info.entries ?? [];
  if (!entries.length) process.exit(0);
  const lines = [
    "已配置密钥（rsenv，值永不出现在上下文，命令中显式引用即可注入子进程环境）：",
    ...entries.map((e) => `- ${e.name}${e.desc ? `：${e.desc}` : ""}`),
    "用法：命令文本写 $NAME 或 ${NAME}（双引号内），隐式读取的工具写成 NAME=$NAME cmd；禁止单引号包引用、禁止命令含 env/printenv/裸 set/export。",
    "详见 secret-env skill。",
  ];
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: lines.join("\n") } }));
  process.exit(0);
}

// ---------- pretooluse：Bash=命令门（rsenv hook），其余=文件守卫（info 快照本地匹配） ----------
async function preToolUse() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  let payload = null;
  try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { log("[parse-error] 放行"); process.exit(0); }

  const tool = payload?.tool_name ?? "";
  const toolInput = payload?.tool_input ?? {};

  if (tool !== "Bash") {
    // 文件守卫：file_path 碰守卫清单即拒（guard_paths 精确路径 + guard_prefixes 前缀）
    const fp = toolInput?.file_path ?? "";
    if (fp) {
      const r = runRsenv(["info"]);
      // 降级判定（2026-11-08 用户定调）：info 不可用（CLI 缺失/报错）→ 保护缺省工作目录
      // （约定路径常量，与 rsenv guard_fragments 同源），而非瘫痪或裸奔。
      // info daemon-free 原则上不应失败——失败即环境异常，降级前必须留痕
      let fragments = null;
      if (r.code === 0) {
        try { fragments = JSON.parse(r.stdout).guard_paths ?? null; }
        catch (e) { log(`info degraded: unparseable output (exit=0): ${String(e).slice(0, 120)}`); }
      } else {
        log(`info degraded: missing=${r.missing ? 1 : 0} code=${r.code} stderr=${(r.stderr ?? "").trim().slice(0, 160)}`);
      }
      const hit = (fragments ?? FALLBACK_FRAGMENTS).some((f) => fp.includes(f));
      if (hit) deny(`${fp} 是 rsenv 的密钥库/审计文件，禁止 agent 读写。配置维护请在你的终端用 rsenv set/list，或亲手操作。`);
    }
    allow();
  }

  const command = toolInput?.command ?? "";
  if (!command) allow();

  // 命令门：rsenv parse（宿主无关，钩子时刻守卫+取值+签发一次性 token）
  // 改写形态：一次性 token 经 eval 链消费；&& 短路保 fail-closed（token 已消费/GC/daemon 重启 → 原命令不执行）
  const r = runRsenv(["parse"], JSON.stringify({ command }));
  if (r.missing) {
    // CLI 缺失 → 降级：命令文本按约定片段匹配（保护缺省工作目录），未命中透传
    if (FALLBACK_FRAGMENTS.some((f) => command.includes(f))) {
      deny("command touches protected files (rsenv unavailable, convention guard) — vault/audit files are forbidden to the agent");
    }
    allow();
  }
  let out = null;
  try { out = JSON.parse(r.stdout); } catch { /* 非判定输出按失败处理 */ }
  if (out?.action === "inject" && out.token) {
    log(`parse → token injection, names=${(out.names ?? []).join(",")}`);
    allow({ ...toolInput, command: injectChain(command, out.token) });
  }
  if (out?.action === "reject") deny(out.reason ?? "command rejected by rsenv guard");
  if (out?.action === "pass") allow();
  // 用户定调（2026-11-08）：daemon 不在/未解锁 → 钩子不生效，pass 透传（CLI parse 已有同口径，
  // 此处兜底覆盖 CLI 缺失/老版本二进制场景）
  if (/ask the user to run/.test(r.stderr)) {
    log(`parse → pass-through (daemon unavailable)`);
    allow();
  }
  log(`parse non-verdict: code=${r.code} stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 200)}`);
  deny(r.stderr.trim() || `rsenv parse failed (exit=${r.code})`);
}

const mode = process.argv[2] ?? "";
if (mode === "session-start") sessionStart();
else if (mode === "pretooluse") await preToolUse();
else { console.error("usage: secret-env-zcode.mjs session-start|pretooluse"); process.exit(2); }
