// DSH 守卫判定（纯函数，供单测直接调用）：文件通道 + 无注入通道的拒绝；不做密钥解析。
// 规则数据来自 CLI 的 info 快照（guardPaths）+ 本地 scanRefs 副本（同步判定，不 spawn 子进程）。
// bash 的命令文本守卫由 CLI 的 parse 统一执行（三端同语义，2026-11-07）——这里只管
// 文件工具（同步）与 pwsh/terminal_send（没有注入通道，必须在本地拦）。
// 与 ZCode 的 guardPaths 同源：配置/密钥库文件对 agent 一律只读不可触（具体清单来自 info 快照，按后端而异）。
import { matchGuardPaths, scanRefs } from "./rules.mjs";

const FILE_TOOLS = ["read", "read_image", "write", "edit"];
const COMMAND_CHANNELS = new Map([
  ["pwsh", "command"],
  ["terminal_send", "text"],
]);

const protectedReason = (fragment) =>
  `secret-env：操作涉及受保护文件（片段「${fragment}」）——密钥库/审计/daemon 文件含全部凭据映射与审计记录，禁止 Agent 读写。配置维护请在你的终端用 CLI 的 set/remove，或亲手操作。`;

// 返回拒绝理由（字符串）或 undefined（放行）。exec 形态见 DSH ToolDispatchExecution：{ name, arguments, callId, agent, signal }。
// snapshot = { entries, guardPaths, config }，由 info 协议构建（见 index.js buildSnapshot）。
export function evaluateCall(exec, snapshot) {
  if (exec === null || typeof exec !== "object") return;
  const name = exec.name;
  if (typeof name !== "string" || name.length === 0) return;
  const args = exec.arguments !== null && typeof exec.arguments === "object" ? exec.arguments : {};
  const fragments = (snapshot?.guardPaths ?? []).filter((f) => typeof f === "string" && f.length > 0);

  if (FILE_TOOLS.includes(name)) {
    for (const key of ["file_path", "path"]) {
      const fragment = matchGuardPaths(args[key], fragments);
      if (fragment !== undefined) return protectedReason(fragment);
    }
    return;
  }
  if (name === "apply_patch") {
    const fragment = matchGuardPaths(args.patch, fragments);
    return fragment === undefined ? undefined : protectedReason(fragment);
  }

  const commandKey = COMMAND_CHANNELS.get(name);
  if (commandKey === undefined) return;
  const command = args[commandKey];
  if (typeof command !== "string" || command.length === 0) return;

  const fragment = matchGuardPaths(command, fragments);
  if (fragment !== undefined) return protectedReason(fragment);

  // pwsh / terminal_send 没有注入通道——引用已配置密钥时直接拒绝，避免变量为空静默执行（宁可失败）。
  let tokens = [];
  try {
    tokens = scanRefs(command, snapshot.config, (reason) => { throw new Error(reason); });
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  if (name === "pwsh") {
    // PowerShell 的读法 $env:NAME（大小写不敏感）不被 scanRefs 的 $NAME 覆盖。
    for (const [alias, info] of snapshot.config) {
      if (new RegExp(`\\$env:${alias}(?![A-Za-z0-9_])`, "i").test(command)) {
        tokens = [{ token: `$env:${alias}`, name: info.canonical }];
        break;
      }
    }
  }
  if (tokens.length > 0) {
    return `secret-env：${name} 通道不注入密钥（只支持 bash 工具）。需要凭据请改用 bash；宿主外执行可用可选 rsenv 后端的 run 命令。`;
  }
}

// 等价 ZCode SessionStart 的清单注入：已配置名字与用法约定（无真值）。
export function promptText(snapshot) {
  const entries = snapshot?.entries ?? [];
  if (entries.length === 0) {
    return "secret-env：当前没有已配置的密钥条目。命令中不要写密钥明文；需要时请用户在终端用 CLI 的 set 命令配置。";
  }
  return [
    "secret-env：已配置的密钥（值永远不会出现在上下文；在 bash 命令文本里显式引用即可注入子进程环境）：",
    ...entries.map(
      ({ name, desc }) => `- ${name}${desc ? `：${desc}` : ""}`,
    ),
    '用法：写 $NAME 或 ${NAME}（双引号内），例如 curl -H "Authorization: Bearer $GH_TOKEN" ...；隐式读取环境变量的工具写成 NAME=$NAME cmd。',
    "禁止：单引号包引用（拒绝）、echo/打印凭据、同一命令里出现 env/printenv/裸 set/export。",
    "terminal_send 与 pwsh 通道不注入密钥，需要凭据请用 bash。禁止读写受保护文件（清单见 info 守卫快照：配置/密钥库/审计/套接字）。",
  ].join("\n");
}
