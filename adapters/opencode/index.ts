// secret-env opencode 适配器（V2 插件 API，Plugin.define 默认导出）。
// 分发：随主包（package.json exports "./opencode"），opencode.json 的 plugin 数组引用
// "@foperate/secret-env/opencode"；不再用 cp 到 plugins/ 目录（V1 形态在 opencode ≥ 2 不加载）。
// 机制：① ctx.tool.hook("execute.before") 拦截 bash/shell，扫描命令文本中的密钥引用，
// 解值写入 0600 env 文件，event.input.command 加 source 前缀——与 ZCode/DSH 同一核心（core.mjs）；
// ② ctx.mcp.transform 注册 senv-mcp（stdio，对齐 ZCode plugin.json 的 mcpServers）；
// ③ ctx.skill.transform 注册 skill——宿主没有"插件包内 skills/ 自动发现"，必须程序化注册，
// path 指向包内 secret-env/skills/secret-env/SKILL.md（references/ 兄弟文件被一并收载）。
import { Plugin } from "@opencode/plugin";

type Core = typeof import("./../../core.mjs");

async function loadCore(): Promise<Core> {
  try {
    return (await import("@foperate/secret-env/core.mjs")) as Core;
  } catch {
    return (await import(process.env.HOME + "/github/zcode-plugin-secret-env/core.mjs")) as Core;
  }
}

// skill 资产在包内相对本文件定位：本文件 <包>/adapters/opencode/index.ts → <包>/secret-env/skills/secret-env
export function skillAssetUrl(): string {
  return new URL("./../../secret-env/skills/secret-env/SKILL.md", import.meta.url).href;
}

export default Plugin.define({
  id: "secret-env",
  async setup(ctx) {
    const core = await loadCore();

    // ---- MCP：senv-mcp（会话内收值登记；值经 elicitation/Product，不进模型上下文） ----
    await ctx.mcp.transform((mcp) => {
      if (!mcp.get("secret-env")) {
        mcp.set("secret-env", { type: "local", command: ["senv-mcp"] });
      }
    });

    // ---- Skill：读包内 SKILL.md 注册；找不到 = 跳过（不注册半死技能） ----
    try {
      const { readFileSync, realpathSync } = await import("node:fs");
      const { fileURLToPath } = await import("node:url");
      const path = fileURLToPath(skillAssetUrl());
      const content = readFileSync(path, "utf8");
      const name = /^name:\s*(.+)$/m.exec(content)![1].trim();
      const description = /^description:\s*([\s\S]+?)(?=\n[a-z-]+:|\n---)/m.exec(content)![1].trim();
      await ctx.skill.transform((skills) => {
        if (skills.get("secret-env")) return;
        skills.add({
          id: "secret-env" as never,
          name: name as never,
          description,
          path: realpathSync(path) as never,
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
