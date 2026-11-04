// secret-env：密钥从私有库直达子进程环境，模型上下文永不见值。
// 机制（DESIGN.md §2/§5/§6）：PreToolUse(Bash) 扫描命令文本中的显式引用
// （{{secret:NAME}} 占位符 或 已配置的 $NAME / ${NAME}），真值写入 0600 临时 env 文件
// （按引用原名 export），命令前缀 source 放行。命令文本零改写。
// 本文件是 ZCode 宿主壳；扫描/provider/env 文件/dump 黑名单等与宿主无关的逻辑在 core.mjs。
// 输出口径：allow + updatedInput；拒绝一律 exit 2 + stderr 提示（宁可失败，不做魔法）。
import { appendFileSync } from "node:fs";
import { loadConfig, scanRefs, isDumpCommand, cleanStale, resolveValue, writeEnvFile, shellSingleQuote } from "../core.mjs";

const LOG = "/tmp/zcode-secret-env.log";

function log(msg) {
  try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {}
}
function allow(updated) {
  const out = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } };
  if (updated) out.hookSpecificOutput.updatedInput = updated;
  console.log(JSON.stringify(out));
  process.exit(0);
}
function deny(reason) {
  console.error(reason);
  process.exit(2);
}

// ---------- 主流程 ----------
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const raw = Buffer.concat(chunks).toString("utf8");

let payload = null;
try { payload = JSON.parse(raw); } catch { log("[parse-error] 放行"); process.exit(0); }

if (payload?.tool_name !== "Bash") { allow(); }
const command = payload?.tool_input?.command ?? "";
if (!command) allow();

const config = loadConfig();
if (config.size === 0) { allow(); } // 未配置 = 纯旁路

cleanStale();

const sessionId = payload?.session_id ?? "";

const tokens = scanRefs(command, config, deny);
if (tokens.length === 0) {
  // 无引用命令：什么都不注入，本 shell 里没有任何密钥可倾泻，直接放行。
  allow();
}

// 单引号内引用 → 拒绝（不生效的引用比失败更危险）
const bad = tokens.filter((t) => t.inSingle);
if (bad.length) {
  deny(`secret-env：引用位于单引号内不会被展开（${[...new Set(bad.map((t) => t.token))].join("、")}）。请改用双引号包裹，例如 "$GH_TOKEN"。`);
}

// 同命令倾泻拦截：命令含密钥引用且命令位置有倾泻意图（如 GH_TOKEN=$GH_TOKEN env）
if (isDumpCommand(command)) {
  deny(`secret-env：命令同时含密钥引用与环境倾泻命令（env/printenv/set/export），会打印注入值。请把倾泻意图从命令中移除。`);
}

// 解析真值（canonical 去重）
const canonicalNames = [...new Set(tokens.map((t) => t.name))];
const values = new Map();
for (const name of canonicalNames) {
  const info = config.get(name);
  try {
    values.set(name, await resolveValue(info.uri));
  } catch (e) {
    deny(`secret-env：解析 ${name}（${info.uri}）失败：${e.message}`);
  }
}

// 注入名 = 命令中实际引用的名字（原名，含花括号剥离）
const exportNames = new Map();
for (const t of tokens) {
  const refName = t.token.replace(/^\$\{?/, "").replace(/\}$/, "");
  exportNames.set(refName, t.name);
}

// 前缀 source env 文件，命令文本原样保留
const envFile = writeEnvFile(sessionId, exportNames, values);
const newCommand = `. ${shellSingleQuote(envFile)}; ${command}`;
log(`inject session=${sessionId} names=${[...exportNames.keys()].join(",")} file=${envFile}`);

allow({ ...payload.tool_input, command: newCommand });
