// secret-env 的 opencode 宿主插件（V2 插件 API，Plugin.define 默认导出）。
// 分发：独立包 @foperate/secret-env-opencode（workspaces 成员，目录即 adapters/opencode）。
// opencode.json 的 plugin 数组只写包名——宿主不接受 "@scope/pkg/subpath" 形式（npa 解析出子路径后
// 判为非法 spec，转去打 npm 装假路径 /Users/<user>/@scope/pkg/subpath/package.json 并报 NpmInstallFailedError）。
// 主包 @foperate/secret-env 是依赖：装插件包会连带装上，但其 bin 不保证进全局 PATH（作为传递依赖时不会），
// 因此本文件对主包的一切引用都走 createRequire 解析绝对路径，不依赖 PATH。
// 机制：① ctx.tool.hook("execute.before") 拦截 bash/shell，扫描命令文本中的密钥引用，
// 解值写入 0600 env 文件，event.input.command 加 source 前缀——与 ZCode/DSH 同一核心（core.mjs）；
// ② ctx.mcp.transform 注册 senv-mcp（stdio，对齐 ZCode plugin.json 的 mcpServers）；
// ③ ctx.skill.transform 注册 skill——宿主没有"插件包内 skills/ 自动发现"，必须程序化注册，
// path 指向主包内的 secret-env/skills/secret-env/SKILL.md（references/ 兄弟文件被一并收载）。
import { Plugin } from "@opencode/plugin";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

type Core = typeof import("@foperate/secret-env/core.mjs");

const require = createRequire(import.meta.url);

// 主包根目录：从依赖解析出的 package.json 反推，不依赖插件包与主包的目录相对位置。
function mainPackageRoot(): string {
  return dirname(require.resolve("@foperate/secret-env/package.json"));
}

async function loadCore(): Promise<Core> {
  return (await import(pathToFileURL(require.resolve("@foperate/secret-env/core.mjs")).href)) as Core;
}

// skill 资产在主包内，与插件包不同层；路径锚定主包根而非 import.meta.url 的相对层级。
export function skillAssetPath(): string {
  return join(mainPackageRoot(), "secret-env", "skills", "secret-env", "SKILL.md");
}

export default Plugin.define({
  id: "secret-env",
  async setup(ctx) {
    const core = await loadCore();

    // ---- MCP：senv-mcp（会话内收值登记；值经 elicitation/Product，不进模型上下文） ----
    // 只传单个可执行路径：mcp.mjs 带 shebang 且运行时中立，opencode 会把多元素 command 的
    // 首个参数当 cwd 去 chdir（报 ENOTDIR），因此不写 [解释器, 脚本] 形式。
    // 绝对路径保证不依赖 PATH——主包作为传递依赖安装时 bin 不会链进 ~/.bun/bin。
    await ctx.mcp.transform((mcp) => {
      if (!mcp.get("secret-env")) {
        mcp.set("secret-env", {
          type: "local",
          command: [require.resolve("@foperate/secret-env/mcp.mjs")],
        });
      }
    });

    // ---- Skill：读主包内 SKILL.md 注册；找不到 = 跳过（不注册半死技能） ----
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
      const command = input.command;

      const deny = (reason: string): never => {
        throw new Error(`secret-env：${reason}`);
      };

      const config = core.loadConfig();
      if (config.size === 0) return; // 未配置 = 纯旁路

      core.cleanStale();

      const tokens = core.scanRefs(command, config, deny);
      if (tokens.length === 0) return; // 无引用 = 零注入

      const bad = tokens.filter((t) => t.inSingle);
      if (bad.length) {
        deny(`引用位于单引号内不会被展开（${[...new Set(bad.map((t) => t.token))].join("、")}）。请改用双引号包裹，例如 "$GH_TOKEN"。`);
      }
      if (core.isDumpCommand(command)) {
        deny("命令同时含密钥引用与环境倾泻命令（env/printenv/set/export），会打印注入值。请把倾泻意图从命令中移除。");
      }

      const values = new Map<string, string>();
      for (const name of [...new Set(tokens.map((t) => t.name))]) {
        const info = config.get(name)!;
        try {
          values.set(name, await core.resolveValue(info.uri, config));
        } catch (e) {
          deny(`解析 ${name}（${info.uri}）失败：${(e as Error).message}`);
        }
      }

      const exportNames = new Map<string, string>();
      for (const t of tokens) {
        exportNames.set(t.token.replace(/^\$\{?/, "").replace(/\}$/, ""), t.name);
      }

      const envFile = core.writeEnvFile(event.sessionID, exportNames, values);
      input.command = `. ${core.shellSingleQuote(envFile)}; ${command}`;
    });
  },
});
