// secret-env 的 opencode 宿主插件（V2 插件 API，Plugin.define 默认导出）。
// 分发：独立包 @foperate/secret-env-opencode。opencode.json 的 plugin 数组只写包名——宿主不接受
// "@scope/pkg/subpath" 形式（npa 解析出子路径后判为非法 spec，转去打 npm 装假路径并报 NpmInstallFailedError）。
// 与 ZCode 同构（2026-11-06 收口）：插件不含注入代码，execute.before 经 PATH 起子进程调全局 CLI 的
// `secret-env inject`（宿主协议，stdin/stdout JSON，带协议版本握手）。前置条件 = 主包全局安装
// （README 安装约定），CLI 不在 PATH 时宁可失败直接报错，不做静默旁路。
// skill 用包内自带副本（adapters/opencode/skills/secret-env/，与权威位逐字节一致，tests/skill-sync.mjs
// 校验）——宿主没有"插件包内 skills/ 自动发现"，必须程序化注册。
// 不注册 MCP server（2026-11-06 收口；0.3.3 起 MCP 入口=主包 `senv mcp` 子命令，仅 ZCode 壳注册）：opencode 宿主 elicitation 支持未验证，入库统一走
// SKILL.md 的终端兜底（senv add 命令）。
import { Plugin } from "@opencode/plugin";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PROTOCOL_VERSION = 1; // 与主包 core.mjs 的 PROTOCOL_VERSION 对齐

// 本插件包根目录（index.ts 就在包根）。
const PLUGIN_ROOT = dirname(fileURLToPath(import.meta.url));

// skill 用本包内的副本，不跨包解析主包路径。
export function skillAssetPath(): string {
  return join(PLUGIN_ROOT, "skills", "secret-env", "SKILL.md");
}

// 调全局 CLI 的宿主协议 inject。退出码：0 成功（stdout {command, envFile}）；
// 2 业务拒绝（stdout {error}）→ 抛错；3 协议不匹配 / CLI 不存在 → 抛错（宁可失败，不静默放行）。
function cliInject(command: string, session: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("secret-env", ["inject"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.on("error", (e) => reject(new Error(
      `secret-env CLI 不在 PATH 上（${e.message}）——插件只做拦截转发，注入真身在全局 CLI；请先全局安装 @foperate/secret-env。`,
    )));
    child.on("close", (code) => {
      let payload: { command?: string; error?: string } | null = null;
      try { payload = JSON.parse(out.trim()); } catch {}
      if (code === 0) {
        if (payload?.command) resolve(payload.command);
        else reject(new Error("secret-env inject 输出异常（exit 0 但无 command）"));
      } else {
        reject(new Error(payload?.error ?? `secret-env inject 退出码 ${code}`));
      }
    });
    child.stdin.end(JSON.stringify({ protocol: PROTOCOL_VERSION, command, session }));
  });
}

export default Plugin.define({
  id: "secret-env",
  async setup(ctx) {
    // ---- Skill：读包内 SKILL.md 注册；找不到 = 跳过（不注册半死技能） ----
    try {
      const path = skillAssetPath();
      const content = readFileSync(path, "utf8");
      const name = /^name:\s*(.+)$/m.exec(content)![1].trim();
      const description = /^description:\s*([\s\S]+?)(?=\n[a-z-]+:|\n---)/m.exec(content)![1].trim();
      await ctx.skill.transform((skills) => {
        if (skills.get("secret-env")) return;
        skills.add({
          id: "secret-env" as never,
          name: name as never,
          description,
          path: path as never,
          content,
        });
      });
    } catch (e) {
      console.warn(`secret-env skill registration skipped: ${(e as Error).message}`);
    }

    await ctx.tool.hook("execute.before", async (event) => {
      // opencode 内置 shell 工具名（bash 为当前名，shell 并列防御）
      if (event.tool !== "bash" && event.tool !== "shell") return;
      const input = event.input as { command?: string } | undefined;
      if (!input?.command) return;
      input.command = await cliInject(input.command, event.sessionID);
    });
  },
});
