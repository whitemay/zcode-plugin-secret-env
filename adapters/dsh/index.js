// rsenv DSH 真身适配器（协议客户端形态，2026-11-07 接 rsenv 三分法）：
//   1) tools/execute 包装 bash：调 CLI `parse`（命令文本守卫 + 取值 + 签发一次性 token），
//      inject 回复 → 改写为 eval 链 `_senv_inj="$(<bin> inject <token>)" && eval ... && { 原命令; }`（HOST-PROTOCOL §注入链）；
//      值不出 daemon（token 一次性消费），不进上下文；
//   2) tools.guard 同步守卫：本地规则副本 + info 快照（受保护路径、名字清单），不 spawn 子进程；
//   3) systemPrompt 注入已配置名字清单与用法约定（来自 info 快照）。
// 挂账：add_secret 工具未迁移——rsenv 尚无元数据入库子命令（set 只收名字+值），等 add 流程成型。
// 不 import 主包代码：只经 CLI 协议（client.mjs）。
// 运行时中立：node only，不用 Bun 专属 API。
// 注：工具定义直接构造 JSON Schema 交给 ctx.tools.register，不 import defineTool（插件经 pnpm link
// 从仓库/包路径加载时，Node 按真实路径解析不到 profile 的 @deepseek-ai/dsh-tools）。
import { appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateCall, promptText } from "./guards.mjs";
import { PROTOCOL, createClient, requireProtocol } from "./client.mjs";

const LOG = join(tmpdir(), "rsenv-dsh.log");
const log = (msg) => { try { appendFileSync(LOG, `[${new Date().toISOString()}] ${msg}\n`); } catch {} };

const REFRESH_MS = 30 * 1000; // 快照过期时间：guard 每次调用顺手触发后台刷新（非阻塞）

// rsenv info（协议）→ 本地快照：config 供同步 scanRefs 用，entries 供清单文案，guardPaths 供文件守卫
export function buildSnapshot(info) {
  const config = new Map();
  for (const entry of info?.entries ?? []) {
    config.set(entry.name, { canonical: entry.name, description: entry.desc });
  }
  return { entries: info?.entries ?? [], guardPaths: info?.guard_paths ?? [], config };
}

export const inject = ["tools", "systemPrompt"];

// options.client 仅供离线测试注入假客户端；生产不传，走 createClient()（$SENV_BIN → PATH rsenv）
export function apply(ctx, options = {}) {
  const client = options.client ?? createClient();
  const disposers = [];

  // 启动即同步拉快照：guard 是同步回调，没有快照就无法判定。失败 = 插件不加载（宁可失败，不静默放行）。
  let info;
  try {
    info = requireProtocol(client.infoSync());
  } catch (error) {
    throw new Error(`rsenv 无法初始化：${error.message}`);
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
    name: "rsenv",
    order: 900,
    interpolate: false,
    text: () => promptText(snapshot),
  }));

  // bash 命令门：一律经 CLI 的 parse（三端同语义，2026-11-07）——
  // 未配置条目也要走一次，否则受保护路径的命令会漏拦。
  // exec.arguments 的替换依赖 dispatchToolBody 现场读取同一 exec 对象。
  // DSH 官方契约只承诺 wrappers 可改 exec.signal；这是既有探针验证过的实现细节，DSH 收紧时需改显式 srun/rsenv run。
  disposers.push(ctx.on("tools/execute", async function (exec, next) {
    if (exec?.name !== "bash") return next();
    const command = exec?.arguments?.command;
    if (typeof command !== "string" || !command) return next();

    let result;
    try {
      result = await client.parse({ command });
    } catch (error) {
      throw new Error(`rsenv：${error.message}`); // 业务拒绝与 CLI 故障都报错（宁可失败）
    }
    if (result?.action === "reject") {
      throw new Error(`rsenv：${result.reason ?? "command rejected by guard"}`);
    }
    if (result?.action !== "inject" || !result.token) return next(); // pass / 空判定 = 零注入

    // 一次性 token 经 eval 链消费；&& 短路保 fail-closed（token 已消费/GC/daemon 重启 → 原命令不执行）
    const rewritten = `_senv_inj="$(${client.bin} inject ${result.token})" && eval "$_senv_inj" && { ${command}; }`;
    exec.arguments = { ...exec.arguments, command: rewritten };
    log(`parse → token injection names=${(result.names ?? []).join(",")}`);
    void refresh(); // 解析成功可能伴随配置变化（极少），顺手刷新
    return next();
  }));

  log(`applied protocol=${PROTOCOL} entries=${snapshot.entries.length}`);
  return () => {
    for (const dispose of disposers) dispose?.();
  };
}
