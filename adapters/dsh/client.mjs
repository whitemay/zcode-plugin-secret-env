// DSH 适配器的 CLI 协议客户端（protocol 1）：只经子进程与主包交互，不 import 主包代码。
// 契约：stdin 一行 JSON，stdout 一行 JSON；退出码 0 成功 / 2 业务拒绝（JSON 带 code）/ 3 协议不匹配。
// 值只经 stdin 进入，响应不含值。协议见 docs/PLAN-DSH-DECOUPLING.md。
import { spawn, spawnSync } from "node:child_process";

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
    throw new CliError(`secret-env ${cmd} 返回非 JSON（exit=${code}）${err ? `：${err.trim().slice(0, MAX_STDERR)}` : ""}`, { code: "bad-output", exit: code });
  }
  if (code !== 0) throw new CliError(json.error ?? `secret-env ${cmd} 失败（exit=${code}）`, { code: json.code ?? "cli", exit: code });
  return json;
}

export function createClient({ bin = process.env.SENV_BIN || "secret-env", timeoutMs = 8000 } = {}) {
  const hint = `请全局安装 @foperate/secret-env（bun add -g · npm i -g）并确认 ${bin} 在 PATH 上`;

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
        reject(new CliError(`secret-env ${cmd} 超时（${timeout}ms）`, { code: "timeout" }));
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
      child.stdin.end(payload === null ? undefined : JSON.stringify({ protocol: PROTOCOL, ...payload }));
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
    inject: (payload) => run("inject", payload),
    store: (payload) => run("store", payload),
  };
}

// 版本握手：插件只认自己实现的协议版本
export function requireProtocol(info) {
  const got = info?.protocol;
  if (got !== PROTOCOL) {
    throw new CliError(`secret-env 协议版本不匹配：插件需要 ${PROTOCOL}，CLI 返回 ${got ?? "无"}（请把主包与插件升到匹配版本）`, { code: "protocol" });
  }
  return info;
}
