// secret-env：密钥从私有库直达子进程环境，模型上下文永不见值。
// 机制（DESIGN.md §2/§5/§6）：
//   - PreToolUse(Bash)：扫描命令文本中的显式引用（{{secret:NAME}} 占位符 或 已配置的 $NAME），
//     经 provider 解出真值写入 0600 临时 env 文件（export 周知原名），命令前缀 source：
//     `. <envfile>; <原命令>`。命令文本零改写，原名注入——隐式读取（如 git 认 GH_TOKEN）
//     由 SKILL 引导 agent 显式化引用来触发。文本与值分离，日志只见路径。
//   - 单引号内引用不展开 → 直接拒绝（exit 2），不静默产出无效引用。
//   - dump 黑名单：命令同时含密钥引用与倾泻意图（env/printenv/裸 set/裸 export/-p）→ 拒绝；
//     跨调用裸 env 不拦（每次 Bash 调用全新 shell，注入变量不跨调用存活）。
// 输出口径：allow + updatedInput；拒绝一律 exit 2 + stderr 提示（宁可失败，不做魔法）。
import { appendFileSync, mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const LOG = "/tmp/zcode-secret-env.log";
const ENV_DIR = join(tmpdir(), "secret-env-injections");
const HERE = dirname(fileURLToPath(import.meta.url));
const STALE_MS = 15 * 60 * 1000;

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

// ---------- 配置（secrets.json：周知名 → {uri, aliases?}） ----------
// 加载顺序：~/.config/secret-env/secrets.json（稳定路径，marketplace refresh 不覆盖）→ 插件根（兼容旧位）。
// 两处合并（稳定路径优先，同名后者不覆盖前者）：凭据映射不随插件版本走——安装缓存是快照，refresh 即覆盖。
function loadConfig() {
  const candidates = [join(process.env.HOME ?? "~", ".config", "secret-env", "secrets.json"), join(HERE, "..", "secrets.json")];
  const map = new Map(); // 别名/主键 → {canonical, uri}
  for (const path of candidates) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8"));
      for (const [name, def] of Object.entries(raw)) {
        if (map.has(name)) continue;
        map.set(name, { canonical: name, uri: def.uri });
        for (const a of def.aliases ?? []) if (!map.has(a)) map.set(a, { canonical: name, uri: def.uri });
      }
    } catch {}
  }
  return map;
}

// ---------- provider 抽象（scheme 路由） ----------
async function resolveValue(uri) {
  const scheme = uri.split("://")[0];
  const rest = uri.slice(scheme.length + 3);
  if (scheme === "keychain") {
    // keychain://<service> → security find-generic-password
    const r = await Bun.$`security find-generic-password -s ${rest} -w`.quiet().nothrow();
    const out = r.stdout.toString().trim();
    if (r.exitCode !== 0 || !out) throw new Error(`keychain 未取到 ${rest}（exit=${r.exitCode} err=${r.stderr.toString().slice(0, 120)}）`);
    return out;
  }
  if (scheme === "viking") {
    // viking://<category>/<target>[/<field>] → ov privacy resolve
    // （privacy 条目按 category/target/field 三段寻址，非 viking:// 资源树 URI；scheme 复用同一标识避免双轨命名）
    // resolve 输出是多行元数据表，真值在 value 行：`value<空白>真值`；只截该行，绝不整表返回
    const parts = rest.split("/");
    if (parts.length < 2) throw new Error(`viking:// URI 需为 <category>/<target>[/<field>]：${uri}`);
    const args = ["privacy", "resolve", ...parts];
    const r = await Bun.$`ov ${args}`.quiet().nothrow();
    const out = r.stdout.toString();
    if (r.exitCode !== 0 || !out.trim()) throw new Error(`ov privacy resolve 未取到 ${rest}（exit=${r.exitCode} err=${r.stderr.toString().slice(0, 120)}）`);
    const valueLine = out.split("\n").find((l) => l.startsWith("value"));
    if (!valueLine) throw new Error(`ov privacy resolve 输出无 value 行（${rest}），输出形状疑似变更`);
    const value = valueLine.slice("value".length).trim();
    if (!value) throw new Error(`ov privacy resolve 的 value 为空（${rest}）`);
    return value;
  }
  if (scheme === "bitwarden") {
    // bitwarden://<item> → bw get password
    const r = await Bun.$`bw get password ${rest}`.quiet().nothrow();
    const out = r.stdout.toString().trim();
    if (r.exitCode !== 0 || !out) throw new Error(`bw 未取到 ${rest}（exit=${r.exitCode} err=${r.stderr.toString().slice(0, 120)}）`);
    return out;
  }
  throw new Error(`未知 provider scheme：${scheme}://`);
}

// ---------- shell 扫描：定位引用位置与单引号上下文 ----------
// 返回每个引用 token 的 {token, index}，及单引号内命中列表。
function scanRefs(command, config) {
  const tokens = []; // {token, start, inSingle}
  const unknownPlaceholders = [];

  // 逐字符扫描建立单引号区间（shell 语义：单引号内无转义）
  const singleRanges = [];
  let inSingle = false, rangeStart = -1;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "'") {
      if (inSingle) { singleRanges.push([rangeStart, i]); inSingle = false; }
      else { inSingle = true; rangeStart = i; }
    }
  }
  const inSingleQuote = (i) => singleRanges.some(([a, b]) => i > a && i < b);

  // ① 占位符 {{secret:NAME}}
  const phRe = /\{\{secret:([A-Za-z0-9_]+)\}\}/g;
  let m;
  while ((m = phRe.exec(command))) {
    const name = m[1];
    if (!config.has(name)) { unknownPlaceholders.push(name); continue; }
    tokens.push({ token: m[0], start: m.index, name, inSingle: inSingleQuote(m.index) });
  }
  if (unknownPlaceholders.length) {
    deny(`secret-env：占位符 {{secret:${unknownPlaceholders.join("、")}}} 未在 secrets.json 配置。宁可失败：请修正名字或先配置。`);
  }

  // ② 显式 $NAME / ${NAME}（词边界；\$ 转义跳过）
  for (const [alias, info] of config) {
    const re = new RegExp(`(?<![A-Za-z0-9_\\$])\\$\{?${alias}(?![A-Za-z0-9_])`, "g");
    while ((m = re.exec(command))) {
      if (m.index > 0 && command[m.index - 1] === "\\") continue;
      tokens.push({ token: m[0], start: m.index, name: info.canonical, inSingle: inSingleQuote(m.index) });
    }
  }
  return tokens;
}

// ---------- dump 黑名单（2026-11-04 用户拍板收窄） ----------
// 仅当命令**同时含密钥引用与倾泻意图**才拦（同命令倾泻：如 GH_TOKEN=$GH_TOKEN env 会打印值）。
// 跨调用裸 env 不拦——每次 Bash 调用都是全新 shell，注入变量不跨调用存活，拦了纯属误伤。
// 倾泻意图按命令位置判定：首词 / VAR=value 赋值前缀后 / ;&&||| 分隔后的词。
// env/printenv 任意参数都算；set 仅裸词或 -p（set -e 无输出）；export 仅裸词或 -p（export FOO=1 无输出）。
function isDumpCommand(command) {
  const segments = command.split(/\||&&|\|\||;/).map((s) => s.trim()).filter(Boolean);
  for (const seg of segments) {
    let rest = seg;
    let m;
    while ((m = rest.match(/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]*)\s+/))) rest = rest.slice(m[0].length);
    const first = rest.match(/^([^\s]+)/);
    if (!first) continue;
    const word = first[1];
    if (word === "env" || word === "printenv") return true;
    if (word === "set") {
      const args = rest.slice(3).trim();
      if (args === "" || args.startsWith("-p")) return true;
    }
    if (word === "export") {
      const args = rest.slice(6).trim();
      if (args === "" || args === "-p") return true;
    }
  }
  return false;
}

// ---------- env 文件与清理 ----------
function cleanStale() {
  try {
    for (const f of readdirSync(ENV_DIR)) {
      const p = join(ENV_DIR, f);
      if (Date.now() - statSync(p).mtimeMs > STALE_MS) unlinkSync(p);
    }
  } catch {}
}
function shellSingleQuote(v) {
  // 单引号安全包装：' → '\''
  return `'${v.replaceAll("'", `'\\''`)}'`;
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

const tokens = scanRefs(command, config);
if (tokens.length === 0) {
  // 无引用命令：什么都不注入，本 shell 里没有任何密钥可倾泻，直接放行。
  allow();
}

// 单引号内引用 → 拒绝改写（不生效的引用比失败更危险）
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

// 写 env 文件（0600），单引号安全包装。注入用命令文本中实际引用的名字（原名）：
// 别名引用（$GITHUB_TOKEN）按别名注入，canonical 引用按周知名注入——原命令零改写。
const exportNames = new Map(); // 引用名 → canonical
for (const t of tokens) {
  const refName = t.token.replace(/^\$\{?/, "").replace(/\}$/, "");
  exportNames.set(refName, t.name);
}
mkdirSync(ENV_DIR, { recursive: true });
const envFile = join(ENV_DIR, `${sessionId || "anon"}-${Date.now()}.sh`);
const lines = [...exportNames].map(([refName, canonical]) => `export ${refName}=${shellSingleQuote(values.get(canonical))}`);
writeFileSync(envFile, lines.join("\n") + "\n", { mode: 0o600 });

// 前缀 source env 文件，命令文本原样保留
const newCommand = `. ${shellSingleQuote(envFile)}; ${command}`;
log(`inject session=${sessionId} names=${canonicalNames.join(",")} file=${envFile}`);

allow({ ...payload.tool_input, command: newCommand });
