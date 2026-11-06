// secret-env DSH 真身适配器：
//   1) tools/execute 包装 bash：引用扫描 → 解析 → 命令前加 source 前缀（值直达子进程，不进上下文）；
//   2) tools.guard 同步守卫：文件工具（read/write/edit/apply_patch）与命令通道（terminal_send/pwsh）
//      触碰受保护文件、或在无注入通道里引用密钥时拒绝；
//   3) systemPrompt 注入已配置密钥清单与用法约定（等价 ZCode SessionStart 的 list --inject）；
//   4) add_secret 工具：元数据由模型传入，密钥值由 ctx.userQuestions 卡片收集并程序化入库（值不入上下文）。
// 运行时中立：与 core.mjs 同规，不用 Bun 专属 API。
// 注：插件经 pnpm link 从仓库路径加载，无法从仓库解析 profile 的 @deepseek-ai/dsh-tools（Node 按真实路径
// 解析依赖），因此这里直接向 ctx.tools.register 提交 JSON Schema 定义，不 import defineTool。
import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { envNameFromHuman, storeEntry } from "../../../cli.mjs";
import { T, PROVIDERS, buildEntryOpts, entryCommandText, interpretAnswer } from "./entry.mjs";
import { evaluateCall, promptText } from "./guards.mjs";

const core = await import(new URL("../../../core.mjs", import.meta.url).href);

const LOG = join(tmpdir(), "secret-env-dsh.log");
const log = (msg) => { try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {} };

export const inject = ["tools", "systemPrompt", "userQuestions"];

export function apply(ctx) {
  const disposers = [];

  // 守卫在 pre-execute / approval 之后、dispatch 之前同步执行；返回理由即拒绝。
  disposers.push(ctx.tools.guard((exec) => {
    const reason = evaluateCall(exec, core.loadConfig());
    if (reason !== undefined) log(`deny tool=${exec?.name} reason=${reason.slice(0, 160)}`);
    return reason;
  }));

  // 清单 + 约定：等价 ZCode SessionStart 注入；配置变化在下次 assembly 反映。
  disposers.push(ctx.systemPrompt.section({
    name: "secret-env",
    order: 900,
    interpolate: false,
    text: () => promptText(core.loadConfig()),
  }));

  // bash 注入：exec.arguments 的替换依赖 dispatchToolBody 现场读取同一 exec 对象。
  // DSH 官方契约只承诺 wrappers 可改 exec.signal；这是既有探针验证过的实现细节，DSH 收紧时需改显式 srun/senv。
  disposers.push(ctx.on("tools/execute", async function (exec, next) {
    if (exec?.name !== "bash") return next();
    const command = exec?.arguments?.command;
    if (typeof command !== "string" || !command) return next();

    const config = core.loadConfig();
    if (config.size === 0) return next(); // 未配置 = 纯旁路

    core.cleanStale();

    const deny = (reason) => { throw new Error(`secret-env：${reason}`); };

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
        values.set(name, await core.resolveValue(info.uri, config));
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
  }));

  disposers.push(ctx.tools.register({
    name: "add_secret",
    description: T.toolDescription,
    parameters: {
      type: "object",
      additionalProperties: false,
      properties: {
        name: { type: "string", description: T.paramName },
        provider: { type: "string", enum: PROVIDERS, description: T.paramProvider },
        detail: { type: "string", description: T.paramDetail },
        alias: { type: "string", description: T.paramAlias },
        description: { type: "string", description: T.paramDescription },
      },
      required: ["name"],
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          status: { type: "string", enum: ["stored", "command-issued", "declined", "invalid", "error"] },
          envName: { type: "string" },
          uri: { type: "string" },
          command: { type: "string" },
          message: { type: "string" },
        },
        required: ["status"],
      },
      render: (_args, value) => [{ type: "text", text: JSON.stringify(value) }],
    },
    async execute(args, exec) {
      if (exec.agent === undefined) return { status: "error", message: T.noAgent };

      const name = String(args.name ?? "").trim();
      const envName = envNameFromHuman(name);
      if (!envName) return { status: "invalid", message: T.missingName };

      const provider = args.provider === undefined || args.provider === "" ? "keychain" : args.provider;
      if (!PROVIDERS.includes(provider)) return { status: "invalid", message: T.badProvider };
      if (core.loadConfig().has(envName)) return { status: "invalid", message: T.exists };

      const picked = {
        name,
        provider,
        detail: String(args.detail ?? "").trim(),
        alias: String(args.alias ?? "").trim(),
        description: String(args.description ?? "").trim(),
      };

      let item;
      try {
        const answer = await ctx.userQuestions.ask({
          agent: exec.agent,
          signal: exec.signal,
          wait: { callId: exec.callId },
          questions: [{
            id: "value",
            header: T.cardHeader,
            question: T.cardQuestion,
            options: [{ label: T.commandLabel, description: T.commandDescription }],
          }],
        });
        item = answer?.answers?.[0];
      } catch (error) {
        const code = error?.code;
        if (code === "ASK_CANCELLED" || code === "ASK_ABORTED" || code === "ASK_TIMED_OUT" || code === "NO_PROVIDER") {
          return { status: "declined" };
        }
        return { status: "error", message: error?.message ?? String(error) };
      }

      const decision = interpretAnswer(item, T.commandLabel);
      if (decision.kind === "declined") return { status: "declined" };
      if (decision.kind === "command") return { status: "command-issued", command: entryCommandText(picked) };

      try {
        const stored = await storeEntry(buildEntryOpts(picked), decision.value);
        log(`add_secret stored env=${stored.envName} uri=${stored.uri}`);
        return { status: "stored", envName: stored.envName, uri: stored.uri };
      } catch (error) {
        return { status: "error", message: error?.message ?? String(error) };
      }
    },
  }));

  return () => {
    for (const dispose of disposers) dispose?.();
  };
}
