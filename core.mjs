// secret-env 核心层：与宿主无关的引用扫描 / provider / env 文件 / dump 黑名单。
// 宿主适配层（ZCode 钩子 / opencode 插件 / DSH Cordis 插件）引用本模块，
// 只各自实现「拦截点 + 把 source 前缀写进命令」的壳。deny 为宿主注入的拒绝回调。
import { mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

export const ENV_DIR = join(tmpdir(), "secret-env-injections");
export const STALE_MS = 15 * 60 * 1000;
const HERE = dirname(fileURLToPath(import.meta.url));

// ---------- 配置（secrets.json：周知名 → {uri, aliases?}） ----------
// 加载顺序：~/.config/secret-env/secrets.json（稳定路径，marketplace refresh 不覆盖）→ 插件根（兼容旧位）。
// 两处合并（稳定路径优先，同名后者不覆盖前者）：凭据映射不随插件版本走——安装缓存是快照，refresh 即覆盖。
export function loadConfig() {
  const candidates = [join(process.env.HOME ?? "~", ".config", "secret-env", "secrets.json"), join(HERE, "secret-env", "secrets.json")];
  const map = new Map(); // 别名/主键 → {canonical, uri}
  for (const path of candidates) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8"));
      for (const [name, def] of Object.entries(raw)) {
        if (map.has(name)) continue;
        map.set(name, { canonical: name, uri: def.uri, description: def.description });
        for (const a of def.aliases ?? []) if (!map.has(a)) map.set(a, { canonical: name, uri: def.uri });
      }
    } catch {}
  }
  return map;
}

// ---------- provider 抽象（scheme 路由） ----------
// system provider（uri scheme 沿用 keychain://）：按平台路由到本机密钥库。
// 执行前先做平台判断 + 二进制探测，探测失败给出人话指引——不等运行失败。
export function systemBackend() {
  const platform = process.platform;
  const requireBin = (cmd, hint) => {
    if (!Bun.which(cmd)) throw new Error(`本机系统密钥库需要 ${cmd}，未找到。${hint}`);
    return cmd;
  };
  if (platform === "darwin") {
    requireBin("security", "macOS 自带，通常不会缺。");
    return {
      backend: "macos-keychain",
      read: async (service) => {
        const r = await Bun.$`security find-generic-password -s ${service} -w`.quiet().nothrow();
        if (r.exitCode !== 0) throw new Error(`security find-generic-password 未取到 ${service}（exit=${r.exitCode} err=${r.stderr.toString().slice(0, 120)}）`);
        return r.stdout.toString().trim();
      },
      write: async (service, value) => {
        const r = await Bun.$`security add-generic-password -a ${process.env.USER} -s ${service} -w ${value} -U`.quiet().nothrow();
        if (r.exitCode !== 0) throw new Error(`security add-generic-password 失败（exit=${r.exitCode} err=${r.stderr.toString().slice(0, 120)}）`);
      },
      remove: async (service) => {
        const r = await Bun.$`security delete-generic-password -s ${service}`.quiet().nothrow();
        return r.exitCode === 0;
      },
    };
  }
  if (platform === "linux") {
    requireBin("secret-tool", "安装 libsecret-tools（Debian/Ubuntu）或 libsecret（Arch），并确保 gnome-keyring 在运行；无头服务器建议改用 bitwarden provider。");
    return {
      backend: "linux-secret-service",
      read: async (service) => {
        const r = await Bun.$`secret-tool lookup service ${service}`.quiet().nothrow();
        const out = r.stdout.toString().trim();
        if (r.exitCode !== 0 || !out) throw new Error(`secret-tool lookup 未取到 ${service}（exit=${r.exitCode}）——确认 keyring daemon 已解锁`);
        return out;
      },
      write: async (service, value) => {
        // 值经 stdin 传递，不落 argv
        const proc = Bun.spawn(["secret-tool", "store", "--label", service, "service", service], { stdin: "pipe" });
        proc.stdin.write(value);
        proc.stdin.end();
        const code = await proc.exited;
        if (code !== 0) throw new Error(`secret-tool store 失败（exit=${code}）`);
      },
      remove: async (service) => {
        const r = await Bun.$`secret-tool clear service ${service}`.quiet().nothrow();
        return r.exitCode === 0;
      },
    };
  }
  if (platform === "win32") {
    throw new Error("Windows 暂无 system provider 实现（Credential Manager 需 PowerShell 模块）。请改用 bitwarden provider。");
  }
  throw new Error(`未知平台：${platform}，无 system provider。`);
}

export async function resolveValue(uri) {
  const scheme = uri.split("://")[0];
  const rest = uri.slice(scheme.length + 3);
  if (scheme === "keychain") {
    const backend = systemBackend(); // 探测失败 → 人话错误，而非命令跑失败
    const out = await backend.read(rest);
    if (!out) throw new Error(`系统密钥库未取到 ${rest}`);
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
// 返回每个引用 token 的 {token, index}，及单引号内命中列表。deny 为宿主拒绝回调（占位符未配置时调用）。
export function scanRefs(command, config, deny) {
  const tokens = []; // {token, start, inSingle, name}
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

// ---------- dump 黑名单 ----------
// 仅当命令**同时含密钥引用与倾泻意图**才拦（同命令倾泻：如 GH_TOKEN=$GH_TOKEN env 会打印值）。
// 跨调用裸 env 不拦——每次调用全新 shell，注入变量不跨调用存活，拦了纯属误伤。
// 倾泻意图按命令位置判定：首词 / VAR=value 赋值前缀后 / ;&&||| 分隔后的词。
// env/printenv 任意参数都算；set 仅裸词或 -p（set -e 无输出）；export 仅裸词或 -p（export FOO=1 无输出）。
export function isDumpCommand(command) {
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
export function cleanStale() {
  try {
    for (const f of readdirSync(ENV_DIR)) {
      const p = join(ENV_DIR, f);
      if (Date.now() - statSync(p).mtimeMs > STALE_MS) unlinkSync(p);
    }
  } catch {}
}

export function shellSingleQuote(v) {
  // 单引号安全包装：' → '\''
  return `'${v.replaceAll("'", `'\\''`)}'`;
}

// 写 env 文件（0600），单引号安全包装。注入用命令文本中实际引用的名字（原名）：
// 别名引用（$GITHUB_TOKEN）按别名注入，canonical 引用按周知名注入——原命令零改写。
export function writeEnvFile(sessionId, exportNames, values) {
  mkdirSync(ENV_DIR, { recursive: true });
  const envFile = join(ENV_DIR, `${sessionId || "anon"}-${Date.now()}.sh`);
  const lines = [...exportNames].map(([refName, canonical]) => `export ${refName}=${shellSingleQuote(values.get(canonical))}`);
  writeFileSync(envFile, lines.join("\n") + "\n", { mode: 0o600 });
  return envFile;
}
