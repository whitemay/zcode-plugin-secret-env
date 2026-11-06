// secret-env DSH 真身适配器（协议客户端形态，2026-11-06 起）：
//   1) tools/execute 包装 bash：调 CLI `inject`（命令文本守卫 + 注入后的命令；值只在子进程里写 env 文件，不进上下文）；
//   2) tools.guard 同步守卫：本地规则副本 + info 快照（受保护路径、名字清单），不 spawn 子进程；
//   3) systemPrompt 注入已配置名字清单与用法约定（来自 info 快照）；
//   4) add_secret 工具：元数据由模型传，ctx.userQuestions 卡片收值后经 CLI `store` 入库（值走 stdin）。
// 不 import 主包代码：只经 CLI 协议（client.mjs，见 docs/PLAN-DSH-DECOUPLING.md）。
// 运行时中立：与 core.mjs 同规，不用 Bun 专属 API。
// 注：工具定义直接构造 JSON Schema 交给 ctx.tools.register，不 import defineTool（插件经 pnpm link
// 从仓库/包路径加载时，Node 按真实路径解析不到 profile 的 @deepseek-ai/dsh-tools）。
import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { T, PROVIDERS, interpretAnswer } from "./entry.mjs";
import { evaluateCall, promptText } from "./guards.mjs";
import { PROTOCOL, createClient, requireProtocol } from "./client.mjs";

const LOG = join(tmpdir(), "secret-env-dsh.log");
const log = (msg) => { try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {} };

const REFRESH_MS = 30 * 1000; // 快照过期时间：guard 每次调用顺手触发后台刷新（非阻塞）

// info（协议）→ 本地快照：config 供同步 scanRefs 用，entries 供清单文案，guardPaths 供文件守卫
export function buildSnapshot(info) {
  const config = new Map();
  for (const entry of info?.entries ?? []) {
    config.set(entry.name, { canonical: entry.name, description: entry.description });
    for (const alias of entry.aliases ?? []) config.set(alias, { canonical: entry.name });
  }
  return { entries: info?.entries ?? [], guardPaths: info?.rules?.guardPaths ?? [], config };
}

// CLI 的 store 错误码 → 宿主文案
function storeError(error) {
  if (error?.code === "exists") return { status: "invalid", message: T.exists };
  if (error?.code === "unknown-provider") return { status: "invalid", message: T.badProvider };
  if (error?.code === "missing-name") return { status: "invalid", message: T.missingName };
  return { status: "error", message: error?.message ?? String(error) };
}

export const inject = ["tools", "systemPrompt", "userQuestions"];

// options.client 仅供离线测试注入假客户端；生产不传，走 createClient()（$SENV_BIN → PATH secret-env）
export function apply(ctx, options = {}) {
  const client = options.client ?? createClient();
  const disposers = [];

  // 启动即同步拉快照：guard 是同步回调，没有快照就无法判定。失败 = 插件不加载（宁可失败，不静默放行）。
  let info;
  try {
    info = requireProtocol(client.infoSync());
  } catch (error) {
    throw new Error(`secret-env 无法初始化：${error.message}`);
  }
  let snapshot = buildSnapshot(info);
  let lastRefresh = Date.now();
  let refreshing = false;

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const next = requireProtocol(await client.info());
      info = next;
      snapshot = buildSnapshot(next);
      lastRefresh = Date.now();
      log(`snapshot refresh entries=${snapshot.entries.length}`);
    } catch (error) {
      log(`snapshot refresh failed: ${error.message}`);
    } finally {
      refreshing = false;
    }
  }
  const maybeRefresh = () => { if (Date.now() - lastRefresh > REFRESH_MS) void refresh(); };

  // 守卫在 pre-execute / approval 之后、dispatch 之前同步执行；返回理由即拒绝。
  disposers.push(ctx.tools.guard((exec) => {
    maybeRefresh();
    const reason = evaluateCall(exec, snapshot);
    if (reason !== undefined) log(`deny tool=${exec?.name} reason=${reason.slice(0, 160)}`);
    return reason;
  }));

  // 清单 + 约定：等价 ZCode SessionStart 注入；配置变化在下次 assembly 反映。
  disposers.push(ctx.systemPrompt.section({
    name: "secret-env",
    order: 900,
    interpolate: false,
    text: () => promptText(snapshot),
  }));

  // bash 注入 + 命令文本守卫：一律经 CLI 的 inject（三端同语义，2026-11-06）——
  // 未配置条目也要走一次，否则受保护路径的命令会漏拦。
  // exec.arguments 的替换依赖 dispatchToolBody 现场读取同一 exec 对象。
  // DSH 官方契约只承诺 wrappers 可改 exec.signal；这是既有探针验证过的实现细节，DSH 收紧时需改显式 srun/senv。
  disposers.push(ctx.on("tools/execute", async function (exec, next) {
    if (exec?.name !== "bash") return next();
    const command = exec?.arguments?.command;
    if (typeof command !== "string" || !command) return next();

    const session = String(exec.callId ?? exec.id ?? "dsh");
    let result;
    try {
      result = await client.inject({ command, session });
    } catch (error) {
      throw new Error(`secret-env：${error.message}`); // 业务拒绝与 CLI 故障都报错（宁可失败）
    }
    if (!result?.envFile) return next(); // 无引用 = 零注入

    exec.arguments = { ...exec.arguments, command: result.command };
    log(`inject via cli key=${session} file=${result.envFile}`);
    void refresh(); // 解析成功可能伴随配置变化（极少），顺手刷新
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
      if (!name) return { status: "invalid", message: T.missingName };

      const provider = args.provider === undefined || args.provider === "" ? "keychain" : args.provider;
      if (!PROVIDERS.includes(provider)) return { status: "invalid", message: T.badProvider };

      const picked = {
        name,
        provider,
        detail: String(args.detail ?? "").trim(),
        alias: String(args.alias ?? "").trim(),
        description: String(args.description ?? "").trim(),
      };

      // 校验阶段（不入库）：判重与命名归一化由 CLI 回答，宿主不重复实现
      try {
        await client.store(picked);
      } catch (error) {
        return storeError(error);
      }

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
      if (decision.kind === "command") {
        try {
          const fallback = await client.store({ ...picked, commandOnly: true });
          return { status: "command-issued", command: fallback.command };
        } catch (error) {
          return storeError(error);
        }
      }

      try {
        const stored = await client.store({ ...picked, value: decision.value });
        log(`add_secret stored env=${stored.envName}`);
        void refresh();
        return { status: "stored", envName: stored.envName, uri: stored.uri };
      } catch (error) {
        return storeError(error);
      }
    },
  }));

  log(`applied protocol=${PROTOCOL} version=${info.version} entries=${snapshot.entries.length}`);
  return () => {
    for (const dispose of disposers) dispose?.();
  };
}
