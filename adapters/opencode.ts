// secret-env opencode 适配器（V2 插件 API）。
// 安装：复制本文件到 ~/.config/opencode/plugins/secret-env.ts（或项目 .opencode/plugins/）。
// 机制：tool.execute.before 拦截 bash 工具，扫描命令文本中的密钥引用，
// 解值写入 0600 env 文件，output.args.command 加 source 前缀——与 ZCode 钩子同一核心（core.mjs）。
// core.mjs 定位：bun link 注册的 npm 包优先（随仓库源码生效），仓库直落路径兜底。
import type { Plugin } from "@opencode-ai/plugin";

type Core = typeof import("./../core.mjs");

async function loadCore(): Promise<Core> {
  try {
    return (await import("secret-env/core.mjs")) as Core;
  } catch {
    return (await import(process.env.HOME + "/github/zcode-plugin-secret-env/core.mjs")) as Core;
  }
}

export const SecretEnvPlugin: Plugin = async () => {
  const core = await loadCore();

  return {
    "tool.execute.before": async (input, output) => {
      // opencode 内置 shell 工具名为 bash（小写）
      if (input.tool !== "bash") return;
      const command: string = output.args?.command ?? "";
      if (!command) return;

      const deny = (reason: string): never => {
        throw new Error(`secret-env：${reason}`);
      };

      const config = core.loadConfig();
      if (config.size === 0) return; // 未配置 = 纯旁路

      core.cleanStale();

      const sessionId = (input as { sessionID?: string }).sessionID ?? "opencode";
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
          values.set(name, await core.resolveValue(info.uri));
        } catch (e) {
          deny(`解析 ${name}（${info.uri}）失败：${(e as Error).message}`);
        }
      }

      const exportNames = new Map<string, string>();
      for (const t of tokens) {
        exportNames.set(t.token.replace(/^\$\{?/, "").replace(/\}$/, ""), t.name);
      }

      const envFile = core.writeEnvFile(sessionId, exportNames, values);
      output.args.command = `. ${core.shellSingleQuote(envFile)}; ${command}`;
    },
  };
};
