// secret-env DSH 真身适配器：tools/execute waterfall 里对 bash 工具做引用扫描 + source 前缀改写。
// 探针已验证 exec.arguments.command 的 mutate 会传导到 tool body（2026-11-04 真机确认）。
// 与 ZCode 钩子 / opencode 适配器共用 core.mjs（经 HOME 仓库路径直连，改源码即生效）。
// 拒绝语义：throw Error → registry 装箱为 error tool result 回给模型（宁可失败，不做魔法）。
import { appendFileSync } from "node:fs";

const LOG = "/tmp/secret-env-dsh.log";
const log = (msg) => { try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {} };

const core = await import(`file://${process.env.HOME}/github/zcode-plugin-secret-env/core.mjs`);

export function apply(ctx) {
  const unwrap = ctx.on("tools/execute", async function (exec, next) {
    if (exec?.name !== "bash") return next();
    const command = exec?.arguments?.command;
    if (typeof command !== "string" || !command) return next();

    const deny = (reason) => { throw new Error(`secret-env：${reason}`); };

    const config = core.loadConfig();
    if (config.size === 0) return next(); // 未配置 = 纯旁路

    core.cleanStale();

    const tokens = core.scanRefs(command, config, deny);
    if (tokens.length === 0) return next(); // 无引用 = 零注入

    const bad = tokens.filter((t) => t.inSingle);
    if (bad.length) {
      deny(`引用位于单引号内不会被展开（${[...new Set(bad.map((t) => t.token))].join("、")}）。请改用双引号包裹，例如 "$GH_TOKEN"。`);
    }
    if (core.isDumpCommand(command)) {
      deny("命令同时含密钥引用与环境倾泻命令（env/printenv/set/export），会打印注入值。请把倾泻意图从命令中移除。");
    }

    const values = new Map();
    for (const name of [...new Set(tokens.map((t) => t.name))]) {
      const info = config.get(name);
      try {
        values.set(name, await core.resolveValue(info.uri));
      } catch (e) {
        deny(`解析 ${name}（${info.uri}）失败：${e.message}`);
      }
    }

    const exportNames = new Map();
    for (const t of tokens) {
      exportNames.set(t.token.replace(/^\$\{?/, "").replace(/\}$/, ""), t.name);
    }

    const sessionKey = String(exec.callId ?? exec.id ?? exec.agent ?? "dsh");
    const envFile = core.writeEnvFile(sessionKey, exportNames, values);
    exec.arguments = { ...exec.arguments, command: `. ${core.shellSingleQuote(envFile)}; ${command}` };
    log(`inject key=${sessionKey} names=${[...exportNames.keys()].join(",")} file=${envFile}`);
    return next();
  });
  return () => unwrap();
}
