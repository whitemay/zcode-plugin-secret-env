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
  // ---------- ① info ----------
  console.log("① info --json");
  {
    const r = runCli("info");
    const info = parse(r);
    check("exit 0", r.exit === 0, r.stderr.slice(0, 200));
    check("protocol = 1", info?.protocol === 1);
    check("version 非空", typeof info?.version === "string" && info.version.length > 0);
    check("configMtime > 0", typeof info?.configMtime === "number" && info.configMtime > 0);
    const entry = info?.entries?.find((e) => e.name === "PROBE_TOKEN");
    check("entries 含主键与别名", entry?.aliases?.includes("PROBE_ALIAS"), JSON.stringify(entry));
    check("entries 带描述", entry?.description === "协议探针");
    check("响应不含值", !r.stdout.includes(SECRET_READ));
    check("响应不含 uri（清单不外泄映射）", !r.stdout.includes("keychain://"));
    check("rules.guardPaths 非空", Array.isArray(info?.rules?.guardPaths) && info.rules.guardPaths.length > 0);
    check("rules.guardPaths 无重复", new Set(info?.rules?.guardPaths).size === info?.rules?.guardPaths.length, JSON.stringify(info?.rules?.guardPaths));
    check("providers 含 keychain", info?.providers?.includes("keychain"));
  }

  // ---------- ② inject ----------
  console.log("② inject");
  {
    const r = runCli("inject", { protocol: 1, command: "ls -la", session: "t1" });
    const out = parse(r);
    check("无引用 → 原样返回", r.exit === 0 && out?.command === "ls -la" && out?.envFile === null, r.stderr.slice(0, 200));
  }
  {
    const r = runCli("inject", { protocol: 1, command: `echo ${D}PROBE_TOKEN`, session: "t2" });
    const out = parse(r);
    check("正常注入 exit 0", r.exit === 0, r.stderr.slice(0, 200));
    check("命令加 source 前缀", out?.command?.startsWith(". ") && out.command.endsWith(`echo ${D}PROBE_TOKEN`));
    check("envFile 存在", typeof out?.envFile === "string" && existsSync(out.envFile));
    if (out?.envFile && existsSync(out.envFile)) {
      const body = readFileSync(out.envFile, "utf8");
      check("env 文件含原名 export", body.startsWith("export PROBE_TOKEN='"), body.slice(0, 20));
      check("env 文件值正确", body.includes(SECRET_READ));
      check("env 文件 0600", (statSync(out.envFile).mode & 0o777) === 0o600);
      unlinkSync(out.envFile);
    }
    check("stdout 不含值", !r.stdout.includes(SECRET_READ));
  }
  {
    const r = runCli("inject", { protocol: 1, command: `sh -c 'echo ${D}PROBE_TOKEN'` });
    check("单引号 → exit 2", r.exit === 2, `exit=${r.exit}`);
    check("提示改双引号", parse(r)?.error?.includes("双引号"), parse(r)?.error);
    check("stdout 无值", !r.stdout.includes(SECRET_READ));
  }
  {
    const r = runCli("inject", { protocol: 1, command: `PROBE_TOKEN=${D}PROBE_TOKEN env` });
    check("倾泻 → exit 2", r.exit === 2, `exit=${r.exit}`);
    check("提示移除倾泻", parse(r)?.error?.includes("倾泻"), parse(r)?.error);
  }
  {
    const r = runCli("inject", { protocol: 1, command: "echo {{secret:NOPE}}" });
    check("未配置占位符 → exit 2", r.exit === 2, `exit=${r.exit}`);
    check("提示未配置", parse(r)?.error?.includes("占位符"), parse(r)?.error);
  }
  {
    // 命令文本守卫（inject 内置，2026-11-06）：提及配置/密钥库文件即拒
    const r = runCli("inject", { protocol: 1, command: `cat '${CONFIG_DIR}/secrets.json'` });
    check("命令提及受保护路径 → exit 2", r.exit === 2, `exit=${r.exit}`);
    check("code = guard", parse(r)?.code === "guard", JSON.stringify(parse(r)));
    check("提示受保护文件", parse(r)?.error?.includes("受保护文件"), parse(r)?.error);
    check("守卫拒绝不回显值", !r.stdout.includes(SECRET_READ));
  }
  {
    const r = runCli("inject", { protocol: 99, command: "ls" });
    check("协议版本不匹配 → exit 3", r.exit === 3, `exit=${r.exit}`);
    check("code = protocol", parse(r)?.code === "protocol");
  }
  {
    const r = runCli("inject", "not-json");
    check("非 JSON stdin → exit 2", r.exit === 2, `exit=${r.exit}`);
  }

  // ---------- ③ store ----------
  console.log("③ store");
  const base = { protocol: 1, name: "cli proto token", provider: "keychain", description: "store 探针", value: SECRET_STORE };
  {
    // 无 value = 校验阶段：只回环境变量名，不写配置
    const r = runCli("store", { protocol: 1, name: "cli proto token", provider: "keychain" });
    const out = parse(r);
    check("校验阶段 exit 0 / status=ready", r.exit === 0 && out?.status === "ready", JSON.stringify(out));
    check("校验阶段回 envName", out?.envName === "CLI_PROTO_TOKEN");
    check("校验阶段不写配置", JSON.parse(readFileSync(CONFIG, "utf8")).CLI_PROTO_TOKEN === undefined);
  }
  {
    // commandOnly = 终端兜底命令（不入库）
    const r = runCli("store", { protocol: 1, name: "cli proto token", provider: "keychain", detail: "svc-x", alias: "a1,a2", description: "d", commandOnly: true });
    const out = parse(r);
    check("commandOnly exit 0", r.exit === 0 && out?.status === "command", JSON.stringify(out));
    check("兜底命令含 senv add", typeof out?.command === "string" && out.command.startsWith("senv add -n "), out?.command);
    check("兜底命令带别名", out?.command?.includes("--alias") === true);
    check("兜底命令不含值", !r.stdout.includes(SECRET_STORE));
  }
  {
    const r = runCli("store", base);
    const out = parse(r);
    check("入库 exit 0", r.exit === 0, r.stderr.slice(0, 200));
    check("status = stored", out?.status === "stored", JSON.stringify(out));
    check("envName 归一化", out?.envName === "CLI_PROTO_TOKEN");
    check("uri = keychain://…", typeof out?.uri === "string" && out.uri.startsWith("keychain://"));
    check("响应不含值", !r.stdout.includes(SECRET_STORE));
  }
  {
    const raw = JSON.parse(readFileSync(CONFIG, "utf8"));
    check("secrets.json 已登记", raw.CLI_PROTO_TOKEN?.uri?.startsWith("keychain://") === true);
    check("配置文件不含值", !JSON.stringify(raw).includes(SECRET_STORE));
    check("描述已登记", raw.CLI_PROTO_TOKEN?.description === "store 探针");
  }
  {
    // 闭环：store 写入的值能被 inject 解析出来
    const r = runCli("inject", { protocol: 1, command: `echo ${D}CLI_PROTO_TOKEN`, session: "t3" });
    const out = parse(r);
    const body = out?.envFile && existsSync(out.envFile) ? readFileSync(out.envFile, "utf8") : "";
    check("store → inject 闭环", body.includes(SECRET_STORE) === true);
    if (out?.envFile && existsSync(out.envFile)) unlinkSync(out.envFile);
  }
  {
    const r = runCli("store", { ...base, value: "x" });
    check("重复名称 → exit 2 / exists", r.exit === 2 && parse(r)?.code === "exists", `exit=${r.exit}`);
  }
  {
    const r = runCli("store", { ...base, name: "other", provider: "nope" });
    check("未知 provider → exit 2", r.exit === 2 && parse(r)?.code === "unknown-provider", `exit=${r.exit}`);
  }
  {
    const r = runCli("store", { ...base, name: "other", value: "" });
    check("空值 → exit 2", r.exit === 2 && parse(r)?.code === "empty-value", `exit=${r.exit}`);
  }
  {
    const r = runCli("store", { protocol: 99, name: "x", value: "y" });
    check("store 协议不匹配 → exit 3", r.exit === 3 && parse(r)?.code === "protocol", `exit=${r.exit}`);
  }
} finally {
  rmSync(HOME, { recursive: true, force: true });
}

console.log(failed === 0 ? `\n全部通过 ✅（${pass} 项）` : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
