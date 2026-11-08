// DSH 适配器的 secret-env CLI 协议客户端（protocol 1）：只经子进程与 CLI 交互，不 import 主包代码。
// 契约：stdin 一行 JSON，stdout 一行 JSON；rsenv 侧退出码 0 成功 / 2 业务拒绝。
// 值不经过本插件：parse 只回 {action, token?}，消费由改写命令里的 rsenv inject 完成（eval 链）。
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const PROTOCOL = 1;

export class CliError extends Error {
  constructor(message, { code = "cli", exit } = {}) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.exit = exit;
  }
}

const MAX_STDERR = 200;

// 统一解析：非 JSON / 非零退出都转成 CliError（宁可失败，不静默放行）
function toJson(out, err, code, cmd) {
  const text = (out ?? "").trim();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  if (json === null) {
    throw new CliError(`rsenv ${cmd} 返回非 JSON（exit=${code}）${err ? `：${err.trim().slice(0, MAX_STDERR)}` : ""}`, { code: "bad-output", exit: code });
  }
  if (code !== 0) throw new CliError(json.error ?? `rsenv ${cmd} 失败（exit=${code}）`, { code: json.code ?? "cli", exit: code });
  return json;
}

// 二进制解析链（HOST-PROTOCOL §解析）：SENV_BIN 显式指定 > secrets.json $backend 键 > 默认 senv。
function configuredBackend() {
  try {
    const cfg = JSON.parse(readFileSync(join(process.env.HOME ?? "", ".config/secret-env", "secrets.json"), "utf8"));
    return cfg?.$backend === "rsenv" ? "rsenv" : null; // 其余值一律视为未配置（senv 是缺省）
  } catch { return null; }
}

export function resolveBin() {
  if (process.env.SENV_BIN) return process.env.SENV_BIN;
  const order = configuredBackend() === "rsenv" ? ["rsenv", "secret-env"] : ["secret-env", "rsenv"];
  for (const name of order) {
    for (const dir of (process.env.PATH ?? "").split(":")) {
      if (!dir) continue;
      try { if (existsSync(`${dir}/${name}`)) return `${dir}/${name}`; } catch {}
    }
  }
  return order[0]; // 双缺省兜底：后续 spawn ENOENT 走报错路径
}

export function createClient({ bin = resolveBin(), timeoutMs = 8000 } = {}) {
  const hint = `请安装 secret-env CLI（senv 或 rsenv）并确认 ${bin} 在 PATH 上；rsenv 后端还需在其终端运行 rsenv login 解锁密钥库`;

  function run(cmd, payload, { timeout = timeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(bin, [cmd], { stdio: ["pipe", "pipe", "pipe"] });
      } catch (e) {
        reject(new CliError(`无法启动 ${bin}：${e.message}——${hint}`, { code: "spawn" }));
        return;
      }
      let out = "", err = "", done = false;
      const timer = setTimeout(() => {
        done = true;
        child.kill("SIGKILL");
        reject(new CliError(`rsenv ${cmd} 超时（${timeout}ms）`, { code: "timeout" }));
      }, timeout);
      const finish = (fn, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        fn(value);
      };
      child.on("error", (e) => finish(reject, new CliError(`无法启动 ${bin}（${e.code ?? e.message}）——${hint}`, { code: "spawn" })));
      child.stdout.on("data", (d) => { out += d; });
      child.stderr.on("data", (d) => { err += d; });
      child.on("close", (code) => {
        try { finish(resolve, toJson(out, err, code, cmd)); }
        catch (e) { finish(reject, e); }
      });
      child.stdin.end(payload === null ? undefined : JSON.stringify(payload));
    });
  }

  // 同步版只给 info 用：DSH 的 guard 是同步回调，插件启动时必须有快照才能判定。
  function runSync(cmd) {
    const r = spawnSync(bin, [cmd], { encoding: "utf8", timeout: timeoutMs });
    if (r.error) throw new CliError(`无法启动 ${bin}（${r.error.code ?? r.error.message}）——${hint}`, { code: "spawn" });
    return toJson(r.stdout ?? "", r.stderr ?? "", r.status ?? -1, cmd);
  }

  return {
    bin,
    info: () => run("info", null),
    infoSync: () => runSync("info"),
    // 命令门（钩子时刻）：stdin {command} → {action: pass|inject|reject, token?, names?, reason?}
    // 注意：parse 的 reject 以 JSON action 表达（退出码仍 0），业务拒绝在 index.js 判定。
    parse: (payload) => run("parse", payload),
  };
}

// 版本握手：插件只认自己实现的协议版本（rsenv info 的 protocol 字段）
export function requireProtocol(info) {
  const got = info?.protocol;
  if (got !== PROTOCOL) {
    throw new CliError(`rsenv 协议版本不匹配：插件需要 ${PROTOCOL}，CLI 返回 ${got ?? "无"}（请把 rsenv 与插件升到匹配版本）`, { code: "protocol" });
  }
  return info;
}
