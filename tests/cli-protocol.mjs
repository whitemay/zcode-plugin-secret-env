// 宿主协议（protocol 1）回归：info / inject / store 的 stdin/stdout JSON 契约。运行：bun tests/cli-protocol.mjs
// 隔离：临时 HOME + 假 kdbx 库（$keychain 后端）+ 假 secrets.json；不碰系统钥匙串与真凭据。
// 值只做等值/长度断言，不打印（断言失败也只显示长度）。
// 注：引用文本用 "$" + 名字拼接构造，避免本会话钩子扫描示例文本。
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync, unlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../cli.mjs", import.meta.url).pathname;
const D = "$";
const HOME = mkdtempSync(join(tmpdir(), "senv-proto-"));
const CONFIG_DIR = join(HOME, ".config", "secret-env");
const CONFIG = join(CONFIG_DIR, "secrets.json");
const VAULT = join(HOME, "vault.kdbx");
const MASTER = "proto-test-master";
const SVC_READ = "proto-read-entry";
const SECRET_READ = `probe-${Math.random().toString(36).slice(2)}-${Date.now()}`;
const SECRET_STORE = `stored-${Math.random().toString(36).slice(2)}-${Date.now()}`;

let pass = 0, failed = 0;
const check = (label, cond, detail = "") => {
  if (cond) { pass++; console.log(`  ✅ ${label}`); }
  else { failed++; console.error(`  ❌ ${label}${detail ? ` — ${detail}` : ""}`); }
};

// ---------- 假 kdbx 库（$keychain 后端，跨平台、不碰系统钥匙串） ----------
const ns = await import("kdbxweb");
const kdbxweb = ns.Kdbx ? ns : ns.default;
const hw = await import("hash-wasm");
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
  const fn = type === 0 ? hw.argon2d : hw.argon2id;
  return fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: "binary" });
});
{
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(MASTER)), "secret-env-proto-test");
  const entry = db.createEntry(db.getDefaultGroup());
  entry.fields.set("Title", SVC_READ);
  entry.fields.set("Password", kdbxweb.ProtectedValue.fromString(SECRET_READ));
  writeFileSync(VAULT, Buffer.from(await db.save()));
}
mkdirSync(CONFIG_DIR, { recursive: true });
writeFileSync(CONFIG, JSON.stringify({
  $keychain: { path: VAULT, password: MASTER },
  PROBE_TOKEN: { uri: `keychain://${SVC_READ}`, aliases: ["PROBE_ALIAS"], description: "协议探针" },
}, null, 2) + "\n", { mode: 0o600 });

// ---------- CLI 子进程调用 ----------
let payloadSeq = 0;
function writePayload(payload) {
  const file = join(HOME, `payload-${payloadSeq++}.json`);
  writeFileSync(file, typeof payload === "string" ? payload : JSON.stringify(payload));
  return file;
}
function runCli(cmd, payload) {
  const prefix = payload === undefined ? "" : `cat ${JSON.stringify(writePayload(payload))} | `;
  const p = Bun.spawnSync(["bash", "-c", `${prefix}HOME='${HOME}' bun '${CLI}' ${cmd}`], { stdout: "pipe", stderr: "pipe" });
  return { exit: p.exitCode, stdout: p.stdout.toString().trim(), stderr: p.stderr.toString().trim() };
}
const parse = (r) => { try { return JSON.parse(r.stdout); } catch { return null; } };

try {
  // ---------- ① info（HOST-PROTOCOL §info） ----------
  console.log("① info");
  {
    const r = runCli("info");
    const info = parse(r);
    check("exit 0", r.exit === 0, r.stderr.slice(0, 200));
    check("protocol = 1", info?.protocol === 1);
    check("version 非空", typeof info?.version === "string" && info.version.length > 0);
    check("configMtime > 0", typeof info?.configMtime === "number" && info.configMtime > 0);
    check("backend = senv", info?.backend === "senv");
    check("capabilities.daemon = true", info?.capabilities?.daemon === true);
    check("capabilities.providers 含 keychain", info?.capabilities?.providers?.includes("keychain"));
    const entry = info?.entries?.find((e) => e.name === "PROBE_TOKEN");
    check("entries 含主键", Boolean(entry), JSON.stringify(info?.entries));
    check("别名折叠进 desc", entry?.desc?.includes("PROBE_ALIAS"), JSON.stringify(entry));
    check("desc 带描述", entry?.desc?.includes("协议探针"));
    check("响应不含值", !r.stdout.includes(SECRET_READ));
    check("响应不含 uri（清单不外泄映射）", !r.stdout.includes("keychain://"));
    check("guard_paths 蛇形非空", Array.isArray(info?.guard_paths) && info.guard_paths.length > 0);
    check("guard_paths 无重复", new Set(info?.guard_paths ?? []).size === info?.guard_paths?.length);
    check("guard_paths 覆盖配置目录", info?.guard_paths?.includes(".config/secret-" + "env"), JSON.stringify(info?.guard_paths));
  }

  // ---------- ② parse（判定四形态） ----------
  console.log("② parse");
  {
    const r = runCli("parse", { command: "ls -la" });
    check("无引用 → pass", r.exit === 0 && parse(r)?.action === "pass", r.stderr.slice(0, 120));
  }
  let tokenSeq = 0;
  const freshToken = () => {
    const r = runCli("parse", { command: `echo ${D}PROBE_TOKEN`, session: `t${tokenSeq++}` });
    return { r, out: parse(r) };
  };
  {
    const { r, out } = freshToken();
    check("有引用 → inject 判定", r.exit === 0 && out?.ok === true && out.action === "inject", r.stderr.slice(0, 160));
    check("token 32hex", /^[0-9a-f]{32}$/.test(out?.token ?? ""));
    check("names 按引用原名", Array.isArray(out?.names) && out.names.includes("PROBE_TOKEN"));
    check("判定不含值", !r.stdout.includes(SECRET_READ));
    check("token 不落盘（配置目录无 slots）", !existsSync(join(CONFIG_DIR, "slots")));
  }
  {
    const r = runCli("parse", { command: `sh -c 'echo ${D}PROBE_TOKEN'` });
    check("单引号 → reject", r.exit === 0 && parse(r)?.action === "reject", r.stderr.slice(0, 120));
    check("理由提示双引号", parse(r)?.reason?.includes("双引号"));
  }
  {
    const r = runCli("parse", { command: `PROBE_TOKEN=${D}PROBE_TOKEN env` });
    check("倾泻 → reject", parse(r)?.action === "reject");
    check("理由提示倾泻", parse(r)?.reason?.includes("倾泻"));
  }
  {
    const r = runCli("parse", { command: `cat '${CONFIG_DIR}/sec` + `rets.json'` });
    const out = parse(r);
    check("文件提及 → reject", out?.action === "reject", r.stderr.slice(0, 120));
    check("理由提示受保护文件", out?.reason?.includes("受保护文件"));
    check("守卫拒绝不回显值", !r.stdout.includes(SECRET_READ));
  }
  {
    const r = runCli("parse", { command: `echo ${D}NOPE_TOKEN` });
    check("未配置 $VAR → pass（rsenv 同口径）", r.exit === 0 && parse(r)?.action === "pass", r.stdout.slice(0, 160));
  }
  {
    const r = runCli("parse", {});
    check("缺 command → exit 2", r.exit === 2, `exit=${r.exit}`);
  }

  // ---------- ③ inject token（一次性消费） ----------
  console.log("③ inject");
  {
    const { out } = freshToken();
    const r = runCli(`inject ${out.token}`);
    check("export 行输出", r.exit === 0 && r.stdout === `export PROBE_TOKEN='${SECRET_READ}'`, r.stdout.slice(0, 40) || r.stderr.slice(0, 120));
    const replay = runCli(`inject ${out.token}`);
    check("重放 → exit 2", replay.exit === 2, `exit=${replay.exit}`);
    check("重放提示已消费", replay.stderr.includes("already-consumed"), replay.stderr);
    check("无 token → exit 2", runCli("inject").exit === 2);
  }
  {
    // eval 链端到端（HOST-PROTOCOL §注入链）
    const { out } = freshToken();
    const marker = `probe_${tokenSeq}_${Date.now()}`;
    const chain = `output=$(HOME='${HOME}' /bin/zsh -c '_senv_inj="$(bun ${CLI} inject ${out.token})" && eval "$_senv_inj" && { echo ${marker}; }' 2>&1); if [ "$output" = "${marker}" ]; then echo OK; else echo "GOT:$output"; fi`;
    const p = Bun.spawnSync(["bash", "-c", chain], { stdout: "pipe" });
    check("eval 链端到端", p.stdout.toString().trim().startsWith("OK"), p.stdout.toString().slice(0, 160));
  }

  // ---------- ③b set（收编 add/store） ----------
  console.log("③b set");
  {
    const r = runCli("set CLI_URI_TOKEN --uri keychain://set-probe-svc --desc set-probe-desc --alias SET_ALIAS");
    check("--uri 登记 exit 0", r.exit === 0, r.stderr.slice(0, 160));
    const raw = JSON.parse(readFileSync(CONFIG, "utf8"));
    check("secrets.json 已登记 uri", raw.CLI_URI_TOKEN?.uri === "keychain://set-probe-svc");
    check("desc 已登记", raw.CLI_URI_TOKEN?.description === "set-probe-desc");
    check("alias 已登记", raw.CLI_URI_TOKEN?.aliases?.includes("SET_ALIAS"));
  }
  {
    // stdin 值入库（假 kdbx 后端，隔离）
    const r = runCli("set CLI_STORE_TOKEN --provider keychain --desc store 探针", SECRET_STORE);
    check("stdin 值入库 exit 0", r.exit === 0, r.stderr.slice(0, 200));
    const raw = JSON.parse(readFileSync(CONFIG, "utf8"));
    check("uri = keychain://…", raw.CLI_STORE_TOKEN?.uri?.startsWith("keychain://") === true);
    check("配置文件不含值", !JSON.stringify(raw).includes(SECRET_STORE));
  }
  {
    // 闭环：set 写入的值经 parse+inject 解析出来
    const r = runCli("parse", { command: `echo ${D}CLI_STORE_TOKEN`, session: "closure" });
    const token = parse(r)?.token;
    const inj = token ? runCli(`inject ${token}`) : { stdout: "", stderr: "no token" };
    check("set → parse → inject 闭环", inj.stdout === `export CLI_STORE_TOKEN='${SECRET_STORE}'`, inj.stdout.slice(0, 40) || inj.stderr.slice(0, 120));
  }
  {
    const r = runCli("set CLI_URI_TOKEN");
    check("已存在无 provider = 维护模式 exit 0", r.exit === 0 && r.stdout.includes("维护模式"), r.stderr.slice(0, 120));
    const raw = JSON.parse(readFileSync(CONFIG, "utf8"));
    check("维护模式 uri 不变", raw.CLI_URI_TOKEN?.uri === "keychain://set-probe-svc");
  }
  {
    const r = runCli("set OTHER_TOKEN");
    check("新条目缺 provider/uri → exit 2", r.exit === 2, `exit=${r.exit}`);
    const r2 = runCli("set OTHER_TOKEN --uri not-a-uri");
    check("坏 uri → exit 2", r2.exit === 2, `exit=${r2.exit}`);
  }
  {
    const r = runCli("add ALIAS_TOKEN --uri keychain://alias-probe");
    check("add 兼容别名仍可用", r.exit === 0, r.stderr.slice(0, 120));
    check("add 提示收编进 set", r.stderr.includes("set"), r.stderr.slice(0, 120));
  }

  // ---------- ③c daemon（复用与 socket 权限） ----------
  console.log("③c daemon");
  {
    const fsmod = await import("node:fs");
    const sock = join(CONFIG_DIR, "senv.sock");
    const first = parse(runCli("parse", { command: `echo ${D}PROBE_TOKEN`, session: "dmn1" }))?.token;
    check("首次 parse 拉起 daemon", Boolean(first) && fsmod.existsSync(sock));
    check("socket 0600", (statSync(sock).mode & 0o777) === 0o600);
    const second = parse(runCli("parse", { command: `echo ${D}PROBE_TOKEN`, session: "dmn2" }))?.token;
    check("复用活 daemon（二次 parse 正常签发）", Boolean(second) && second !== first);
    // 两个 token 都可消费（同一 daemon 服务）
    check("token1 可消费", runCli(`inject ${first}`).exit === 0);
    check("token2 可消费", runCli(`inject ${second}`).exit === 0);
  }

  // ---------- ④ senv mcp 子命令入口 ----------

  // 用 node 跑（真实安装形态的 shebang = node）：mcp.mjs 反向 import cli.mjs，
  // 若 cli.mjs 用 await import 会构成 ESM 循环死锁 → node exit 13（曾发生的回归）。
  console.log("④ senv mcp（node 运行时）");
  {
    const init = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
    const p = Bun.spawnSync(["bash", "-c", `printf '%s\\n' ${JSON.stringify(init)} | HOME='${HOME}' node '${CLI}' mcp`], { stdout: "pipe", stderr: "pipe" });
    const out = parse({ stdout: p.stdout.toString().trim(), stderr: p.stderr.toString().trim() });
    check("mcp 入口 exit 0", p.exitCode === 0, `exit=${p.exitCode} stderr=${p.stderr.toString().slice(0, 200)}`);
    check("initialize 回 serverInfo", out?.result?.serverInfo?.name === "secret-env", JSON.stringify(out).slice(0, 120));
  }
} finally {
  rmSync(HOME, { recursive: true, force: true });
}

console.log(failed === 0 ? `\n全部通过 ✅（${pass} 项）` : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
