// senv 轻量 daemon 回归：拉起/消费/重放/复用、崩后重拉（死 socket 清理）、TTL 过期。运行：bun tests/senv-daemon.mjs
// 隔离：每场景独立临时 HOME + 假 security shim（HOME 变更会带偏 security 的钥匙串域，shim 兜底）。
// TTL 场景靠 SENV_TTL_MS env——daemon 继承首次拉起者环境，故 TTL 场景用独立 HOME 从头拉。
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const CLI = new URL("../cli.mjs", import.meta.url).pathname;

const mkEnv = (extra = {}) => {
  const home = mkdtempSync(join(tmpdir(), "senv-daemon-test-"));
  const cfgDir = join(home, ".config", "secret-env");
  mkdirSync(cfgDir, { recursive: true });
  writeFileSync(join(cfgDir, "secrets.json"), JSON.stringify({ GH_TEST: { uri: "keychain://daemon-test-svc" } }));
  const fakeBin = join(home, "bin");
  mkdirSync(fakeBin);
  writeFileSync(join(fakeBin, "security"), `#!/bin/bash
case "$1" in
  dump-keychain) echo '"svce"<blob>="daemon-test-svc"' ;;
  find-generic-password) if [[ "$*" == *"-w"* ]]; then echo fakeval123; else echo '"acct"<blob>="smoke"'; fi ;;
  *) exit 1 ;;
esac`);
  chmodSync(join(fakeBin, "security"), 0o755);
  return { home, cfgDir, env: { ...process.env, HOME: home, PATH: fakeBin + ":" + process.env.PATH, ...extra } };
};
const runWith = (env, args, input) => {
  const r = spawnSync("node", [CLI, ...args], { input: input ?? "", encoding: "utf8", env });
  return { code: r.status, out: r.stdout.trim(), err: r.stderr.trim() };
};

let failed = 0;
const check = (name, cond, detail = "") => { cond ? console.log(`  ✅ ${name}`) : (failed++, console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ""}`)); };

try {
  console.log("① 拉起 / 消费 / 重放 / 复用 / socket 权限");
  {
    const { env, cfgDir } = mkEnv();
    const run = (...a) => runWith(env, ...a);
    const token = JSON.parse(run(["parse"], JSON.stringify({ command: "echo $GH_TEST" })).out).token;
    check("parse 签发 token", token?.length === 32);
    check("inject export 行", run(["inject", token]).out === "export GH_TEST='fakeval123'");
    check("重放拒", run(["inject", token]).err.includes("already-consumed"));
    const t2 = JSON.parse(run(["parse"], JSON.stringify({ command: "echo $GH_TEST" })).out).token;
    check("复用活 daemon（二次 parse 正常）", t2?.length === 32);
    const mode = spawnSync("stat", ["-f", "%Lp", join(cfgDir, "senv.sock")], { encoding: "utf8" }).stdout.trim();
    check("unix socket 0600", mode === "600", mode);
    spawnSync("bash", ["-c", `lsof -t '${cfgDir}/senv.sock' | xargs kill`]);
  }

  console.log("② 崩后重拉（死 socket 清理）");
  {
    const { env, cfgDir } = mkEnv();
    const run = (...a) => runWith(env, ...a);
    run(["parse"], JSON.stringify({ command: "echo $GH_TEST" }));
    const kill = spawnSync("bash", ["-c", `lsof -t '${cfgDir}/senv.sock' | xargs kill`]);
    check("daemon 已杀", kill.status === 0);
    check("死 socket 文件残留", existsSync(join(cfgDir, "senv.sock")));
    const t3 = JSON.parse(run(["parse"], JSON.stringify({ command: "echo $GH_TEST" })).out).token;
    check("重拉成功", t3?.length === 32);
    check("重拉后可消费", run(["inject", t3]).out.includes("fakeval123"));
    spawnSync("bash", ["-c", `lsof -t '${cfgDir}/senv.sock' | xargs kill`]);
  }

  console.log("③ TTL 过期（独立 HOME，daemon 从头带 SENV_TTL_MS）");
  {
    const { env } = mkEnv({ SENV_TTL_MS: "300" });
    const run = (...a) => runWith(env, ...a);
    const t4 = JSON.parse(run(["parse"], JSON.stringify({ command: "echo $GH_TEST" })).out).token;
    await new Promise((r) => setTimeout(r, 1600));
    check("过期 token 拒", run(["inject", t4]).err.includes("already-consumed"));
  }
} finally {
  // 清理本次测试拉起的全部 daemon（按 cli.mjs daemon 子命令特征）
  spawnSync("pkill", ["-f", "senv-daemon-test"]);
}

console.log(failed === 0 ? "\n全部通过 ✅" : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
