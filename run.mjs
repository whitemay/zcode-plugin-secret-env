#!/usr/bin/env node
// srun：带着密钥跑命令（裸终端/脚本/cron 场景的注入通道，与 senv 同库不同门）。
// 用法：srun NAME [NAME...] -- cmd [args...]   或   srun --all -- cmd [args...]
// `--` 前的裸词是周知环境变量名（字面量传给 srun，不经 shell 展开——$VAR 显式引用在终端会被
// shell 先展开成空串，所以这里反着来：名字裸写，值由本工具注入子进程环境）。--all 为显式
// opt-in 全量注入。名字未配置 → 报错并列出现有清单（宁可失败，不做魔法）。
import { loadConfig, resolveValue } from "./core.mjs";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
if (sep === -1) {
  console.error('用法：srun NAME [NAME...] -- cmd [args...]\n       srun --all -- cmd [args...]\n  例：srun GH_TOKEN DEEPSEEK_API_KEY -- gh pr list\n  `--` 前是周知变量名（无 $ 前缀，字面量），值由 srun 从密钥库解析注入子进程环境；--all 注入全部已配置条目。');
  process.exit(2);
}
const spec = argv.slice(0, sep);
const cmd = argv.slice(sep + 1);
if (cmd.length === 0) { console.error("`--` 后缺少要执行的命令"); process.exit(2); }
const all = spec.includes("--all");
if (all && spec.length > 1) { console.error("--all 不能与具体名字混用"); process.exit(2); }

const config = loadConfig();
const names = all ? [...new Set(config.keys())] : spec;
if (names.length === 0) { console.error("没有可注入的名字（清单为空）——先 senv add"); process.exit(2); }
const unknown = names.filter((n) => !config.has(n));
if (unknown.length) {
  console.error(`未配置：${unknown.join("、")}（现有：${[...config.keys()].join("、") || "无"}）——先 senv add`);
  process.exit(2);
}

const env = { ...process.env };
for (const name of names) {
  try {
    env[name] = await resolveValue(config.get(name).uri, config);
  } catch (e) {
    console.error(`srun：解析 ${name}（${config.get(name).uri}）失败：${e.message}`);
    process.exit(2);
  }
}

// stdio 继承：交互式命令（pi 等）照常工作；退出码透传
const { spawnSync } = await import("node:child_process");
const r = spawnSync(cmd[0], cmd.slice(1), { env, stdio: "inherit" });
if (r.error) { console.error(`srun：执行 ${cmd[0]} 失败：${r.error.message}`); process.exit(127); }
process.exit(r.status ?? 1);
