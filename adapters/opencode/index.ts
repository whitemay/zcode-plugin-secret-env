// secret-env 的 opencode 宿主插件（V2 插件 API，Plugin.define 默认导出）。
// 分发：独立包 @foperate/secret-env-opencode。opencode.json 的 plugin 数组只写包名——宿主不接受
// "@scope/pkg/subpath" 形式（npa 解析出子路径后判为非法 spec，转去打 npm 装假路径并报 NpmInstallFailedError）。
// 与 ZCode 同构（2026-11-07 切换 rsenv 三分法）：插件不含注入代码，execute.before 经 PATH 起子进程
// 调 `rsenv parse`（钩子时刻守卫 + 取值 + 签发一次性 token）；token → 改写为 eval 链
// `_rse_inj="$(rsenv inject <token>)" && eval "$_rse_inj" && { 原命令; }`，&& 链保 fail-closed。
// CLI 不在 PATH / 门报错 → 抛错（宁可失败，不静默旁路）。
// skill 用包内自带副本（adapters/opencode/skills/secret-env/，与权威位逐字节一致，tests/skill-sync.mjs
// 校验）——宿主没有"插件包内 skills/ 自动发现"，必须程序化注册。
// 不注册 MCP server（rsenv mcp 仅管理面，ZCode 壳注册）：opencode 宿主 elicitation 支持未验证，入库统一走
// SKILL.md 的终端兜底（senv add 命令）。
import { Plugin } from "@opencode/plugin";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = process.env.SENV_BIN ?? "rsenv";

// ---- 文件守卫（挂账清偿，2026-11-08）：保护对象=静态文件，零 daemon 依赖 ----
// 规则数据=rsenv info 快照（CLI daemon-free 常给）；语义与 DSH guards.mjs 同构。
// opencode 读写工具入参字段名未官方核实——已知路径键优先，其余**路径尺度**字符串值
// （≤1024 字符）兜底匹配，规避「写文件内容含受保护路径字面量」的误伤；宁可失败口径。
const PATH_KEYS = ["file_path", "filepath", "path", "file", "filename"];

// 降级守卫（2026-11-08 用户定调）：rsenv 不可用时保护缺省工作目录——约定路径（声明不可配），
// 与 rsenv guard_fragments 同源，约定变更须双侧同步。
const FALLBACK_FRAGMENTS = (() => {
  const dir = `${process.env.HOME ?? ""}/.config/secret-env`;
  return [
    ".config/secret-env",
    ...["vault.db", "vault.db-wal", "vault.db-shm", ".vault.salt", "audit.jsonl", "daemon.sock"].map((f) => `${dir}/${f}`),
  ];
})();

let guardPaths: string[] | null = null; // null = 快照不可用（CLI 缺失/报错）→ 降级用 FALLBACK_FRAGMENTS

async function refreshGuardPaths(): Promise<void> {
  // info daemon-free 原则上不应失败——失败即环境异常，降级前必须留痕
  guardPaths = await new Promise<string[] | null>((resolve) => {
    const child = spawn(BIN, ["info"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", (e) => {
      console.warn(`rsenv: info degraded (spawn failed): ${e.message} — falling back to convention guard`);
      resolve(null);
    });
    child.on("close", (code) => {
      if (code !== 0) {
        console.warn(`rsenv: info degraded (exit=${code}): ${err.trim().slice(0, 160)} — falling back to convention guard`);
        resolve(null);
        return;
      }
      try { resolve((JSON.parse(out).guard_paths ?? []) as string[]); }
      catch (e) {
        console.warn(`rsenv: info degraded (unparseable output): ${String(e).slice(0, 120)} — falling back to convention guard`);
        resolve(null);
      }
    });
  });
}

// 返回拒绝理由或 undefined（放行）。导出仅供离线回归测试。
export function evaluateFileGuard(tool: string, input: unknown, fragments: string[] | null): string | undefined {
  // 降级判定：快照不可用 → 保护缺省工作目录（约定片段），而非瘫痪或裸奔
  const frags = fragments ?? FALLBACK_FRAGMENTS;
  if (!input || typeof input !== "object" || frags.length === 0) return undefined;
  const obj = input as Record<string, unknown>;
  const hit = (v: string) => frags.find((f) => f.length > 0 && v.includes(f));
  for (const k of PATH_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.length > 0) {
      const f = hit(v);
      if (f) return `rsenv：操作涉及受保护文件（片段「${f}」）——密钥库/审计/daemon 文件禁止 Agent 读写。配置维护请在你的终端用 rsenv set，或亲手操作。`;
    }
  }
  for (const [k, v] of Object.entries(obj)) {
    if (PATH_KEYS.includes(k)) continue;
    if (typeof v === "string" && v.length > 0 && v.length <= 1024) {
      const f = hit(v);
      if (f) return `rsenv：操作涉及受保护文件（片段「${f}」）——密钥库/审计/daemon 文件禁止 Agent 读写。配置维护请在你的终端用 rsenv set，或亲手操作。`;
    }
  }
  return undefined;
}

// 本插件包根目录（index.ts 就在包根）。
const PLUGIN_ROOT = dirname(fileURLToPath(import.meta.url));

// skill 用本包内的副本，不跨包解析主包路径。
export function skillAssetPath(): string {
  return join(PLUGIN_ROOT, "skills", "secret-env", "SKILL.md");
}

// 调 rsenv 的 parse 门。stdin {command}；stdout {action, token?, names?, reason?}；exit 2 = 拒绝。
// 返回改写后的命令（inject）或 null（pass 旁路）。CLI 不在 PATH / 退出非零且无判定 → 抛错（宁可失败）。
// （导出仅供离线回归测试；SENV_BIN 覆盖仅测试用）
export function cliParse(command: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const child = spawn(BIN, ["parse"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("error", (e) => reject(new Error(
      `${BIN} CLI 不在 PATH 上（${e.message}）——插件只做拦截翻译，守卫与取值真身是 rsenv；请先安装 rsenv 并在其终端 rsenv login 解锁密钥库。`,
    )));
    child.on("close", (code) => {
      let payload: {
        action?: "pass" | "inject" | "reject";
        token?: string;
        reason?: string;
      } | null = null;
      try { payload = JSON.parse(out.trim()); } catch {}
      if (payload?.action === "inject" && payload.token) {
        // 一次性 token 经 eval 链消费；&& 短路保 fail-closed（token 已消费/GC/daemon 重启 → 原命令不执行）
        resolve(`_rse_inj="$(${BIN} inject ${payload.token})" && eval "$_rse_inj" && { ${command}; }`);
        return;
      }
      if (payload?.action === "pass") { resolve(null); return; }
      if (payload?.action === "reject") {
        reject(new Error(payload.reason ?? "command rejected by rsenv guard"));
        return;
      }
      // 无判定输出：vault locked / daemon 缺失等 CLI 报错——透传给 agent
      reject(new Error(err.trim() || `${BIN} parse failed (exit=${code})`));
    });
    child.stdin.end(JSON.stringify({ command }));
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

    await refreshGuardPaths();

    await ctx.tool.hook("execute.before", async (event) => {
      // opencode 内置 shell 工具名（bash 为当前名，shell 并列防御）
      if (event.tool === "bash" || event.tool === "shell") {
        const input = event.input as { command?: string } | undefined;
        if (!input?.command) return;
        const rewritten = await cliParse(input.command);
        if (rewritten) {
          input.command = rewritten;
          void refreshGuardPaths(); // 解析成功可能伴随配置变化（极少），顺手刷新
        }
        return;
      }
      // 文件守卫（挂账清偿）：非 bash 工具一律过 info 快照本地匹配（与 ZCode Write|Edit|Read、DSH ctx.tools.guard 同构）
      const reason = evaluateFileGuard(event.tool, event.input, guardPaths);
      if (reason) throw new Error(reason);
    });
  },
});
