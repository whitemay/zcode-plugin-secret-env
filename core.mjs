// secret-env 核心层：与宿主无关的引用扫描 / provider / env 文件 / dump 黑名单。
// 宿主适配层（ZCode 钩子 / opencode 插件 / DSH Cordis 插件）引用本模块，
// 只各自实现「拦截点 + 把 source 前缀写进命令」的壳。deny 为宿主注入的拒绝回调。
import { mkdirSync, writeFileSync, readFileSync, unlinkSync, readdirSync, statSync, existsSync, appendFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { connect as netConnect } from "node:net";

export const ENV_DIR = join(tmpdir(), "secret-env-injections");
export const STALE_MS = 15 * 60 * 1000;
const HERE = dirname(fileURLToPath(import.meta.url));

// ---------- 配置（secrets.json：周知名 → {uri, aliases?}） ----------
// 加载顺序：~/.config/secret-env/secrets.json（稳定路径，marketplace refresh 不覆盖）→ 插件根（兼容旧位）。
// 两处合并（稳定路径优先，同名后者不覆盖前者）：凭据映射不随插件版本走——安装缓存是快照，refresh 即覆盖。
// "$" 开头的顶层键是保留键（后端配置），不进凭据映射；当前保留键："$keychain"。
export function loadConfig() {
  const candidates = [join(process.env.HOME ?? "~", ".config", "secret-env", "secrets.json"), join(HERE, "secret-env", "secrets.json")];
  const map = new Map(); // 别名/主键 → {canonical, uri}
  for (const path of candidates) {
    try {
      const raw = JSON.parse(readFileSync(path, "utf8"));
      for (const [name, def] of Object.entries(raw)) {
        if (map.has(name) || name.startsWith("$")) continue;
        map.set(name, { canonical: name, uri: def.uri, description: def.description });
        for (const a of def.aliases ?? []) if (!map.has(a)) map.set(a, { canonical: name, uri: def.uri });
      }
      // keychain 后端配置（稳定路径优先，只取第一处出现的）
      if (!map.keychainBackend && raw.$keychain) {
        map.keychainBackend = raw.$keychain; // {backend:"kdbx", path, password} — kdbx 后端；缺省走系统密钥库
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
    throw new Error("Windows 暂无 system provider 实现（Credential Manager 需 PowerShell 模块）。请改用 bitwarden provider 或配置 kdbx 后端（$keychain）。");
  }
  throw new Error(`未知平台：${platform}，无 system provider。`);
}

// ---------- kdbx 后端（keychain:// 换引擎，DESIGN §3 2026-11-05 定案） ----------
// keychain:// 对外 URI 不变；secrets.json 配置 "$keychain": {backend:"kdbx", path, password} 时
// 解析后端从系统 security 命令换成 kdbxweb 直读 .kdbx 库（路径 ~/ 展开，口令明文入配置是
// 已拍板的威胁模型口径：防线=防上下文泄漏，非磁盘绝对安全）。未配置则回退 systemBackend（过渡兼容）。
// 寻址映射：keychain://<svc> → 标题 <svc> 条目的 Password 位；/<field> → UserName（account/username）
// 或 URL/Notes/自定义字段名。同名条目 >1 拒绝（与 macos-keychain 防歧义同规）。读写同构（写语义镜像 bw）。
let _kdbxState = null; // {path, password, promise} — 进程内缓存（钩子进程单命令生命周期）
let _kdbxweb = null; // UMD 归一化后的命名空间，写侧建 ProtectedValue 用

async function kdbxLoad(path, password, useCache = true) {
  if (useCache && _kdbxState && _kdbxState.path === path && _kdbxState.password === password) return _kdbxState.promise;
  const promise = (async () => {
    const ns = await import("kdbxweb");
    const kdbxweb = ns.Kdbx ? ns : ns.default; // UMD：Bun 命名空间可用，Node 只在 default（PoC 实证）
    _kdbxweb = kdbxweb;
    if (!globalThis.__secretEnvArgon2) {
      const hw = await import("hash-wasm");
      kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
        const fn = type === 0 ? hw.argon2d : hw.argon2id;
        return fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: "binary" });
      });
      globalThis.__secretEnvArgon2 = true;
    }
    const expanded = path.startsWith("~") ? join(process.env.HOME ?? "~", path.slice(1)) : path;
    const data = readFileSync(expanded);
    return kdbxweb.Kdbx.load(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength), new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password)));
  })();
  if (useCache) _kdbxState = { path, password, promise };
  return promise;
}

// ---------- senv agent（可选 daemon：口令只驻 daemon 内存，库每次现场加载，DESIGN §3 2026-11-05） ----------
// 启用判据 = secrets.json $keychain 无 password 字段：有明文口令 → 内联直读（daemon 不启用）；
// 无口令且 token 文件存在 → 全部读写经 unix socket 走 daemon（协议 newline-JSON，功能独立、可被
// 任意语言平替实现）。token 是调用指纹：login 时构造、请求时携带、daemon 判定 + 全量审计。
export function agentDir() { return process.env.SENV_AGENT_DIR ?? join(process.env.HOME ?? "~", ".config", "secret-env"); }
export const agentSocketPath = () => join(agentDir(), "agent.sock");
export const agentTokenPath = () => join(agentDir(), "agent.token");
export const agentAuditPath = () => join(agentDir(), "audit.jsonl");
// 库路径是约定不是配置：恒为 agentDir()/vault.kdbx。$keychain 只剩一个可选项 password
// （有=内联直读、daemon 不启用；无/缺整个键=daemon 模式）。遗留配置里的 path 仍被尊重（过渡）。
export const vaultPath = () => process.env.SENV_VAULT_PATH ?? join(agentDir(), "vault.kdbx");

// newline-JSON 请求。返回 daemon 的应答对象；socket 不存在/超时/应答 ok:false → 抛人话错误。
export function agentRequest(msg, timeoutMs = 15000) {
  msg._pid = process.pid;
  msg._exe = process.argv[1] ?? "";
  return new Promise((resolve, reject) => {
    const sock = netConnect(agentSocketPath());
    let buf = "";
    const done = (err, data) => { try { sock.destroy(); } catch {} err ? reject(err) : resolve(data); };
    sock.setTimeout(timeoutMs, () => done(new Error("agent socket 超时")));
    sock.on("connect", () => sock.write(JSON.stringify(msg) + "\n"));
    sock.on("data", (d) => {
      buf += d.toString();
      if (!buf.endsWith("\n")) return;
      try { const r = JSON.parse(buf); r.ok ? done(null, r) : done(new Error(r.error ?? "agent 请求失败")); }
      catch { done(new Error(`agent 应答非法：${buf.slice(0, 120)}`)); }
    });
    sock.on("error", (e) => {
      if (e.code === "ENOENT" || e.code === "ECONNREFUSED") done(new Error("agent 未运行——先执行 senv login"));
      else done(new Error(`agent 连接失败：${e.message}`));
    });
  });
}

export async function kdbxBackend(cfg, { cache = true } = {}) {
  if (!cfg?.path || !cfg?.password) throw new Error('$keychain 配置需含 path 与 password（kdbx 后端）');
  const kdbxProtected = (v) => _kdbxweb.ProtectedValue.fromString(v);
  const getText = (v) => (v instanceof Object && typeof v.getText === "function" ? v.getText() : String(v ?? ""));
  const db = await kdbxLoad(cfg.path, cfg.password, cache);
  // 活条目视图：排除回收站子树（db.remove 是软删除，条目进 Recycle Bin 组，
  // 而 allEntries() 遍历子组——不过滤的话已删条目仍可被寻址命中）
  const liveEntries = () => {
    const bin = db.meta.recycleBinUuid ? db.getGroup(db.meta.recycleBinUuid) : null;
    const out = [];
    const walk = (g) => {
      if (bin && g.uuid.id === bin.uuid.id) return;
      for (const sub of g.groups) walk(sub);
      for (const e of g.entries) out.push(e);
    };
    walk(db.getDefaultGroup());
    return out;
  };
  return {
    backend: "kdbx",
    read: async (service, field) => {
      const hits = liveEntries().filter((e) => e.fields.get("Title") === service);
      if (hits.length === 0) throw new Error(`kdbx 库无标题为「${service}」的条目（${cfg.path}）`);
      if (hits.length > 1) throw new Error(`kdbx 库存在 ${hits.length} 条同名条目「${service}」，寻址歧义——请消歧（改标题）`);
      const e = hits[0];
      if (!field) {
        const pw = e.fields.get("Password");
        if (!(pw instanceof Object && typeof pw.getText === "function")) throw new Error(`条目 ${service} 无 Password 位`);
        return pw.getText();
      }
      const key = { account: "UserName", username: "UserName", url: "URL", notes: "Notes" }[field] ?? field;
      const v = e.fields.get(key);
      if (v === undefined) {
        const names = [...e.fields.keys()].filter((k) => !["Title", "UserName", "Password", "URL", "Notes"].includes(k)).join("、");
        throw new Error(`条目 ${service} 无字段「${field}」${names ? `（现有自定义字段：${names}）` : ""}`);
      }
      return getText(v);
    },
    // 写语义镜像 bitwarden：同名条目存在 → 改 Password 位（--user 顺路写 UserName 位）；
    // 不存在 → 新建条目（Title=service）；同名 >1 → 歧义拒绝。改后即落盘（0600 保持）。
    write: async (service, value, user) => {
      const hits = liveEntries().filter((e) => e.fields.get("Title") === service);
      if (hits.length > 1) throw new Error(`kdbx 库存在 ${hits.length} 条同名条目「${service}」，写入歧义——请消歧`);
      const e = hits[0] ?? db.createEntry(db.getDefaultGroup());
      if (!hits[0]) e.fields.set("Title", service);
      e.fields.set("Password", kdbxProtected(value));
      if (user) e.fields.set("UserName", user);
      e.times.update();
      const data = Buffer.from(await db.save());
      writeFileSync(cfg.path, data, { mode: 0o600 });
    },
    remove: async (service) => {
      const hits = liveEntries().filter((e) => e.fields.get("Title") === service);
      if (hits.length > 1) throw new Error(`kdbx 库存在 ${hits.length} 条同名条目「${service}」，删除歧义——请消歧`);
      if (hits.length === 0) return false;
      db.remove(hits[0]);
      const data = Buffer.from(await db.save());
      writeFileSync(cfg.path, data, { mode: 0o600 });
      return true;
    },
  };
}

// ---------- 文件守卫（PreToolUse 前置，与 dump 黑名单同级） ----------
// secrets.json 有 master 口令明文与全部映射，vault.kdbx 是整库密文——两者对 agent 一律只读不可触。
// 判定=哑文本片段匹配（宁可失败）：返回受保护路径片段列表；命中即拒绝，Agent 不碰这两个文件，
// 配置维护走 secret-env add/remove（用户终端）或用户亲手编辑。
export function guardPaths(config) {
  const fragments = [".config/secret-env", join(HERE, "secret-env", "secrets.json")];
  const vault = config?.keychainBackend?.path;
  if (vault) {
    const expanded = vault.startsWith("~") ? join(process.env.HOME ?? "~", vault.slice(1)) : vault;
    fragments.push(expanded, vault); // ~/ 形态与展开形态都拦
  }
  return fragments;
}

// keychain:// 后端选择（三态分流，读写同构共用）：$keychain 有明文口令 → 内联直读（daemon 不启用）；
// 无口令且 token 文件在 → daemon 路径（口令驻 agent 内存，库每次现场加载，请求携 token 指纹）；
// 都不是 → 人话报错提示 login 或补写 password。未配置 kdbx → 按平台回退系统密钥库（过渡兼容）。
export async function keychainBackend(config) {
  const cfg = config?.keychainBackend;
  if (!cfg) return systemBackend(); // 配置无 $keychain → 回退系统密钥库（过渡兼容）
  const path = cfg.path ?? vaultPath(); // 约定路径优先；遗留 path 字段仍尊重（过渡）
  if (cfg.password) return kdbxBackend({ path, password: cfg.password });
  if (existsSync(agentTokenPath())) {
    const token = readFileSync(agentTokenPath(), "utf8").trim();
    const call = (cmd, extra = {}) => agentRequest({ cmd, token, ...extra });
    return {
      backend: "kdbx-agent",
      read: (service, field) => call("resolve", { name: service, field }).then((r) => r.value),
      write: (service, value, user) => call("write", { service, value, user }).then(() => {}),
      remove: (service) => call("remove", { service }).then((r) => r.hit ?? false),
    };
  }
  throw new Error("kdbx 库已配置但口令不可得（配置无明文 password 且未登录 agent）——先执行 senv login，或在 $keychain 写明文 password（daemon 模式不启用）");
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
  if (spec.provider === "system" || spec.provider === "keychain") {
    // 主名 keychain（与 scheme 对齐）；system 为弃用别名。经 keychain 后端分流：
    // 配置 kdbx → 写库；未配置 → 系统密钥库（DESIGN §3 keychain:// 换引擎）
    const backend = await keychainBackend(config);
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
  if (spec.provider === "onepassword") {
    // 写与读同构，落位与 bw 镜像。⚠️ 全线待真机验证（2026-11-05 实现，本机暂无 op CLI）：
    // - create 用 stdin 模板 JSON（op item create 接受 "-" 读 stdin，待验证）；edit 值落 argv——
    //   op 无已知 stdin 编辑通道，暴露面妥协，真机验证时复核。
    const sess = await opSessionArgs(config);
    if (spec.field) {
      const out = runBin("op", [...sess, "item", "edit", spec.item, `${spec.field}=${value}`]);
      if (!out.ok) throw new Error(`op item edit 失败（exit=${out.exitCode} err=${out.stderr}）`);
      return;
    }
    const probe = runBin("op", [...sess, "item", "get", spec.item], {});
    if (probe.ok) {
      const out = runBin("op", [...sess, "item", "edit", spec.item, `password=${value}`, ...(spec.user ? [`username=${spec.user}`] : [])]);
      if (!out.ok) throw new Error(`op item edit 失败（exit=${out.exitCode} err=${out.stderr}）`);
    } else {
      const tmpl = { category: "LOGIN", title: spec.item, fields: [
        { id: "username", type: "STRING", value: spec.user ?? null, label: "username" },
        { id: "password", type: "CONCEALED", value, label: "password" },
      ] };
      const out = runBin("op", [...sess, "item", "create", "--category", "login", "-"], { input: JSON.stringify(tmpl) });
      if (!out.ok) throw new Error(`op item create 失败（exit=${out.exitCode} err=${out.stderr}）`);
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

// onepassword session 注入：配置里存在 OP_SESSION 记录（如 keychain://op-session）→ 解析后经 --session 传给 op。
// ⚠️ --session 走 argv 有进程表暴露面——op 的 session env 变量名带账号 shorthand（OP_SESSION_<xxx>），
// 无法不验真机就确定；真机验证时若 shorthand 可探测，改为 env 注入。无 OP_SESSION 记录时依赖 biometric/宿主环境。
async function opSessionArgs(config) {
  const sess = config?.get("OP_SESSION");
  if (!sess) return [];
  if (sess.uri.startsWith("onepassword://"))
    throw new Error("OP_SESSION 记录的 uri 不能是 onepassword://（需要解锁 1Password 才能解锁，死循环）");
  return ["--session", await resolveValue(sess.uri, config)];
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
    // 一般化寻址：keychain://<service>[/<field>]。一级 = 主密钥（password）；
    // 二级语义随后端：系统密钥库 = account 属性；kdbx 后端 = username/url/notes/自定义字段。
    const parts = rest.split("/");
    if (parts.length > 2) throw new Error(`keychain:// URI 需为 <service>[/<field>]：${uri}`);
    const backend = await keychainBackend(config); // kdbx 未配置时回退 systemBackend（探测失败 → 人话错误）
    const out = await backend.read(parts[0], parts[1]);
    if (!out) throw new Error(`密钥库未取到 ${rest}`);
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
  if (scheme === "onepassword") {
    // 一般化寻址：onepassword://<item>[/<field>]。一级 = password，二级 = username/自定义字段 label。
    // 无 OP_SESSION 记录时依赖 biometric（1Password 桌面 App 集成）或宿主环境会话。
    const sess = await opSessionArgs(config);
    const parts = rest.split("/");
    if (parts.length > 2) throw new Error(`onepassword:// URI 需为 <item>[/<field>]：${uri}`);
    const [item, field] = parts;
    const f = field ?? "password";
    if (f === "totp") throw new Error("onepassword provider 暂不支持 totp 字段（op 的 TOTP 寻址待真机验证后补）");
    const r = runBin("op", [...sess, "item", "get", item, "--fields", f]);
    const out = r.ok ? r.stdout.replace(/\n$/, "") : "";
    if (!out) throw new Error(`op 未取到 ${item}/${f}（exit=${r.exitCode} err=${r.stderr}）`);
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
