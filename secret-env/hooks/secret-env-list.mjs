// SessionStart 注入：把已配置密钥的「名字清单」（无真值）注进模型上下文。
// 名字本身可安全进上下文——真值只存在于 provider 与子进程环境。
// 输出：additionalContext（SessionStart 合法字段）。配置为空则静默不注。
import { loadConfig } from "../core.mjs";

const config = loadConfig();
if (config.size === 0) process.exit(0);

// 按主键聚合：名字 → {aliases}
const entries = new Map();
for (const [name, info] of config) {
  if (info.canonical === name) entries.set(name, []);
  else entries.get(info.canonical)?.push(name);
}

const lines = [
  "已配置密钥（secret-env，值永不出现在上下文，命令中显式引用即可注入子进程环境）：",
  ...[...entries].map(([name, aliases]) =>
    `- ${name}${aliases.length ? `（别名：${aliases.join("、")}）` : ""}`),
  "用法：命令文本写 $NAME 或 ${NAME}（双引号内），隐式读取的工具写成 NAME=$NAME cmd；禁止单引号包引用、禁止命令含 env/printenv/裸 set/export。",
  "详见 secret-env skill。",
];
console.log(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "SessionStart",
    additionalContext: lines.join("\n"),
  },
}));
