// secret-env 核心层：与宿主无关的引用扫描 / provider / env 文件 / dump 黑名单。
// 宿主适配层（ZCode 钩子 / opencode 插件 / DSH Cordis 插件）引用本模块，
// 只各自实现「拦截点 + 把 source 前缀写进命令」的壳。deny 为宿主注入的拒绝回调。
import { mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";

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
// 运行时中立：全部走 node:child_process（Node 与 Bun 原生都支持）——
// ZCode 钩子在 Bun 下跑，opencode/DSH 适配器可能在 Node/Electron 下跑，core 不得依赖 Bun 全局。
const runBin = (cmd, args, opts = {}) => {
  // execFileSync：非零退出抛错（携带 stderr），值不经过 shell
  try {
    return { ok: true, stdout: execFileSync(cmd, args, { encoding: "utf8", ...opts }).toString() };
  } catch (e) {
    return { ok: false, exitCode: e.status ?? -1, stderr: (e.stderr?.toString?.() ?? e.message).slice(0, 160) };
  }
};
const whichBin = (cmd) => {
  // 轻量 which：扫 PATH 找可执行文件（避免依赖 Bun.which / 独立 which 包）
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (!dir) continue;
    try {
      const p = join(dir, cmd);
      if (statSync(p).isFile() && statSync(p).mode & 0o111) return p;
    } catch {}
  }
  return null;
};

// system provider（uri scheme 沿用 keychain://）：按平台路由到本机密钥库。
// 执行前先做平台判断 + 二进制探测，探测失败给出人话指引——不等运行失败。
export function systemBackend() {
  const platform = process.platform;
  const requireBin = (cmd, hint) => {
    if (!whichBin(cmd)) throw new Error(`本机系统密钥库需要 ${cmd}，未找到。${hint}`);
    return cmd;
  };
  if (platform === "darwin") {
    requireBin("security", "macOS 自带，通常不会缺。");
    return {
      backend: "macos-keychain",
      // 同 service 可挂多个 account（不同 -a 是不同条目），find-generic-password 只静默返回第一条——
      // 读前先经 dump-keychain 计数防歧义（~20ms 开销，可忽略）；宁失败不魔法。
      read: async (service, field) => {
        const dup = runBin("security", ["dump-keychain"]);
        if (dup.ok) {
          const n = dup.stdout.split(`"svce"<blob>="${service}"`).length - 1;
          if (n > 1) throw new Error(`keychain 存在 ${n} 条同 service 的 ${service} 条目（不同 account），寻址歧义——请手动消歧`);
        }
        if (!field) {
          const r = runBin("security", ["find-generic-password", "-s", service, "-w"]);
          if (!r.ok) throw new Error(`security find-generic-password 未取到 ${service}（exit=${r.exitCode} err=${r.stderr}）`);
          return r.stdout.trim();
        }
        // 次级字段寻址：account 属性（不带 -w 读属性表，值是明文 blob）
        if (field !== "account") throw new Error(`keychain provider 次级字段只支持 account，收到：${field}`);
        const r = runBin("security", ["find-generic-password", "-s", service]);
        if (!r.ok) throw new Error(`security find-generic-password 未取到 ${service}（exit=${r.exitCode} err=${r.stderr}）`);
        const vals = [...new Set([...r.stdout.matchAll(/"acct"<blob>="([^"]*)"/g)].map((m) => m[1]))];
        if (vals.length === 0) throw new Error(`keychain 条目 ${service} 无 account 属性`);
        return vals[0];
      },
      write: async (service, value, account) => {
        const r = runBin("security", ["add-generic-password", "-a", account ?? process.env.USER ?? "", "-s", service, "-w", value, "-U"]);
        if (!r.ok) throw new Error(`security add-generic-password 失败（exit=${r.exitCode} err=${r.stderr}）`);
      },
      remove: async (service) => {
        const r = runBin("security", ["delete-generic-password", "-s", service]);
        return r.ok;
      },
    };
  }
  if (platform === "linux") {
    requireBin("secret-tool", "安装 libsecret-tools（Debian/Ubuntu）或 libsecret（Arch），并确保 gnome-keyring 在运行；无头服务器建议改用 bitwarden provider。");
    return {
      backend: "linux-secret-service",
      read: async (service, field) => {
        if (field) throw new Error(`linux secret-tool 暂不支持次级字段寻址（${field}）——多值请多存条目`);
        const r = runBin("secret-tool", ["lookup", "service", service]);
        const out = r.ok ? r.stdout.trim() : "";
        if (!out) throw new Error(`secret-tool lookup 未取到 ${service}（exit=${r.exitCode}）——确认 keyring daemon 已解锁`);
        return out;
      },
      write: async (service, value, account) => {
        // 值经 stdin 传递，不落 argv；account 存为附加属性（与 macOS 语义对齐）
        const args = ["store", "--label", service, "service", service];
        if (account) args.push("account", account);
        const r = spawnSync("secret-tool", args, { input: value, encoding: "utf8" });
        if (r.status !== 0) throw new Error(`secret-tool store 失败（exit=${r.status}）`);
      },
      remove: async (service) => {
        const r = runBin("secret-tool", ["clear", "service", service]);
        return r.ok;
      },
    };
  }
  if (platform === "win32") {
    throw new Error("Windows 暂无 system provider 实现（Credential Manager 需 PowerShell 模块）。请改用 bitwarden provider。");
  }
  throw new Error(`未知平台：${platform}，无 system provider。`);
}

// ---------- 写侧：provider 自治写入（配置即能力，DESIGN §3） ----------
// 写与读同构：provider 依赖的凭据一律经 resolveValue 链式解析（跨 provider 互调），
// 不关心第一级落在哪个 scheme——BW_SESSION 自举即此规则的既有实例。
// bw create/edit 的 encodedJson = base64(JSON)（等价 `| bw encode`），值经 stdin 不落 argv
const encodeBwJson = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");

async function bwSessionOpts(config) {
  const sess = config?.get("BW_SESSION");
  if (!sess) return {};
  if (sess.uri.startsWith("bitwarden://"))
    throw new Error("BW_SESSION 记录的 uri 不能是 bitwarden://（需要 vault 先解锁才能解锁，死循环）");
  return { env: { ...process.env, BW_SESSION: await resolveValue(sess.uri, config) } };
}

// spec: {provider:"system", service, user?} | {provider:"bitwarden", item, field?, user?}
//     | {provider:"viking", parts:[category, target, field?]}. value 为明文，只经 stdin/临时文件。
export async function writeValue(spec, value, config = null) {
  if (spec.provider === "system") {
    const backend = systemBackend();
    await backend.write(spec.service, value, spec.user);
    return;
  }
  if (spec.provider === "bitwarden") {
    const opts = await bwSessionOpts(config);
    if (spec.field) {
      // 二级写 = 已存在条目上 upsert 自定义字段（不隐式建条目）
      const r = runBin("bw", ["get", "item", spec.item, "--raw"], opts);
      if (!r.ok) throw new Error(`条目 ${spec.item} 不存在或不可读（${r.stderr}）——--field 不隐式建条目，请先在 vault 建条目或去掉 --field`);
      const item = JSON.parse(r.stdout);
      const fields = (item.fields ?? []).filter((f) => f.name !== spec.field);
      fields.push({ name: spec.field, value, type: 1 });
      const out = runBin("bw", ["edit", "item", item.id], { ...opts, input: encodeBwJson({ ...item, fields }) });
      if (!out.ok) throw new Error(`bw edit 失败（exit=${out.exitCode} err=${out.stderr}）`);
      return;
    }
    // 一级写 = password 位：条目存在则改，不存在则新建 login 条目（--user 顺路写 username 位）
    const r = runBin("bw", ["get", "item", spec.item, "--raw"], opts);
    if (r.ok) {
      const item = JSON.parse(r.stdout);
      const merged = { ...item, login: { ...item.login, password: value, ...(spec.user ? { username: spec.user } : {}) } };
      const out = runBin("bw", ["edit", "item", item.id], { ...opts, input: encodeBwJson(merged) });
      if (!out.ok) throw new Error(`bw edit 失败（exit=${out.exitCode} err=${out.stderr}）`);
    } else {
      const obj = { type: 1, name: spec.item, notes: null, favorite: false, reprompt: 0, fields: [], login: { username: spec.user ?? null, password: value, totp: null } };
      const out = runBin("bw", ["create", "item"], { ...opts, input: encodeBwJson(obj) });
      if (!out.ok) throw new Error(`bw create 失败（exit=${out.exitCode} err=${out.stderr}）`);
    }
    return;
  }
  if (spec.provider === "viking") {
    // 值经 0600 临时文件（--values-file），不落 argv；path 无 field 段时主值写进 value 字段
    const [cat, target, field] = spec.parts;
    if (spec.parts.length < 2) throw new Error(`viking 写入需 <category>/<target>[/<field>]`);
    const tmp = join(tmpdir(), `secret-env-upsert-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(tmp, JSON.stringify({ [field ?? "value"]: value }), { mode: 0o600 });
    try {
      const r = runBin("ov", ["privacy", "upsert", cat, target, "--values-file", tmp]);
      if (!r.ok) throw new Error(`ov privacy upsert 失败（exit=${r.exitCode} err=${r.stderr}）`);
    } finally {
      unlinkSync(tmp);
    }
    return;
  }
  throw new Error(`未知写入 provider：${spec.provider}`);
}

// bitwarden item JSON → 自定义字段值（保留键分流在 resolveValue，不进这里）
export function pickBwField(item, field) {
  const f = (item?.fields ?? []).find((x) => x.name === field);
  if (f === undefined) {
    const names = (item?.fields ?? []).map((x) => x.name).join("、");
    throw new Error(`bitwarden 条目 ${item?.id ?? "?"} 无字段「${field}」${names ? `（现有：${names}）` : "（无自定义字段）"}`);
  }
  return f.value ?? "";
}

export async function resolveValue(uri, config = null) {
  const scheme = uri.split("://")[0];
  const rest = uri.slice(scheme.length + 3);
  if (scheme === "keychain") {
    // 一般化寻址：keychain://<service>[/<field>]。一级 = 主密钥（password），二级当前只支持 account。
    const parts = rest.split("/");
    if (parts.length > 2) throw new Error(`keychain:// URI 需为 <service>[/<account>]：${uri}`);
    const backend = systemBackend(); // 探测失败 → 人话错误，而非命令跑失败
    const out = await backend.read(parts[0], parts[1]);
    if (!out) throw new Error(`系统密钥库未取到 ${rest}`);
    return out;
  }
  if (scheme === "viking") {
    // viking://<category>/<target>[/<field>] → ov privacy resolve
    // （privacy 条目按 category/target/field 三段寻址，非 viking:// 资源树 URI；scheme 复用同一标识避免双轨命名）
    // resolve 输出是多行元数据表，真值在 value 行：`value<空白>真值`；只截该行，绝不整表返回
    const parts = rest.split("/");
    if (parts.length < 2) throw new Error(`viking:// URI 需为 <category>/<target>[/<field>]：${uri}`);
    const r = runBin("ov", ["privacy", "resolve", ...parts]);
    const out = r.ok ? r.stdout : "";
    if (!out.trim()) throw new Error(`ov privacy resolve 未取到 ${rest}（exit=${r.exitCode} err=${r.stderr}）`);
    const valueLine = out.split("\n").find((l) => l.startsWith("value"));
    if (!valueLine) throw new Error(`ov privacy resolve 输出无 value 行（${rest}），输出形状疑似变更`);
    const value = valueLine.slice("value".length).trim();
    if (!value) throw new Error(`ov privacy resolve 的 value 为空（${rest}）`);
    return value;
  }
  if (scheme === "bitwarden") {
    // 一般化寻址：bitwarden://<item>[/<field>]。一级 = password（主密钥）；
    // 二级保留键 password/username/totp 走 bw get 现成子命令，其余按自定义字段在 fields[] 里按 name 匹配。
    // bw 需要解锁态：若配置里存在 BW_SESSION 记录（如 keychain://bw-session），先解析并注入子进程环境；
    // 无此记录则依赖宿主环境已带 BW_SESSION。session key 本身不允许 bitwarden://（自举死循环）。
    const opts = await bwSessionOpts(config);
    const parts = rest.split("/");
    if (parts.length > 2) throw new Error(`bitwarden:// URI 需为 <item>[/<field>]：${uri}`);
    const [item, field] = parts;
    const sub = field ?? "password";
    if (["password", "username", "totp"].includes(sub)) {
      // 保留键优先：字段名撞保留键时按保留键语义取（撞名场景改字段名消歧）
      const r = runBin("bw", ["get", sub, item], opts);
      const out = r.ok ? r.stdout.trim() : "";
      if (!out) throw new Error(`bw 未取到 ${item}/${sub}（exit=${r.exitCode} err=${r.stderr}）`);
      return out;
    }
    const r = runBin("bw", ["get", "item", item, "--raw"], opts);
    if (!r.ok) throw new Error(`bw 未取到条目 ${item}（exit=${r.exitCode} err=${r.stderr}）`);
    return pickBwField(JSON.parse(r.stdout), sub);
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
