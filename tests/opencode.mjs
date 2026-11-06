// opencode 适配器冒烟测试：假 ctx 捕获 execute.before 钩子，构造假 event。
// 覆盖：旁路、改名注入、braced、别名、dump 拒绝、单引号拒绝、env 文件原名 export。
// 注意值断言只查 export 行的存在与名字，不打印真值。
import { readFileSync, existsSync } from "node:fs";
import plugin, { skillAssetPath } from "../adapters/opencode/index.ts";

let pass = 0, fail = 0;
const ok = (cond, label) => { cond ? pass++ : (fail++, console.error(`✗ ${label}`)); };

// Skill 假域：捕获 transform 内容（注册表断言在下方）
const skills = new Map();
let before;
await plugin.setup({
  skill: { transform: async (cb) => { cb({ get: (k) => skills.get(k), add: (s) => skills.set(s.id, s) }); return { dispose: async () => {} }; } },
  tool: { hook: async (name, cb) => { before = cb; return { dispose: async () => {} }; } },
});
const run = (tool, sessionID, input) => before({ tool, sessionID, input });

const D = "$" + "GH_TOKEN"; // 拼接构造，避免本文件被真钩子拦截

// 1. 无引用旁路
{
  const input = { command: `echo hello` };
  await run("bash", "test-oc", input);
  ok(input.command === "echo hello", "无引用零改写");
}
// 2. 原名引用 → 前缀 + 命令零改写
{
  const input = { command: `echo ${D}` };
  await run("bash", "test-oc", input);
  ok(input.command.includes("; echo " + D), "命令文本零改写");
  ok(input.command.startsWith(". '"), "带 source 前缀");
}
// 3/4. braced 与别名：export 行落在 env 文件里，不在命令文本中
const readEnvFile = (command) => {
  const m = command.match(/\. '([^']+)'/);
  return m ? readFileSync(m[1], "utf8") : "";
};
{
  const input = { command: "echo " + "$" + "{GH_TOKEN}" };
  await run("bash", "test-oc", input);
  ok(readEnvFile(input.command).includes("export GH_TOKEN="), "braced 导出原名");
}
{
  const input = { command: "echo " + "$" + "{GITHUB_TOKEN}" };
  await run("bash", "test-oc", input);
  ok(readEnvFile(input.command).includes("export GITHUB_TOKEN="), "别名按引用名导出");
}
// 5. dump 拒绝
{
  let threw = false;
  try { await run("bash", "test-oc", { command: `GH_TOKEN=${D} env` }); } catch { threw = true; }
  ok(threw, "dump 命令抛错拒绝");
}
// 6. 单引号拒绝
{
  let threw = false;
  try { await run("bash", "test-oc", { command: `echo '${D}'` }); } catch { threw = true; }
  ok(threw, "单引号内引用抛错拒绝");
}
// 7. 非 bash 工具旁路
{
  const input = { file: "/tmp/x" };
  await run("read", "t", input);
  ok(input.file === "/tmp/x", "非 bash 工具不动");
}
// 8. env 文件内容核对（读最后一个 env 文件，只验 export 名，不回显值）
{
  const input = { command: `echo ${D} ${"$"}{GITHUB_TOKEN}` };
  await run("bash", "test-oc", input);
  const m = input.command.match(/\. '([^']+)'/);
  ok(!!m, "env 文件路径可解析");
  if (m) {
    const content = readFileSync(m[1], "utf8");
    ok(content.includes("export GH_TOKEN="), "env 文件含 GH_TOKEN export");
    ok(content.includes("export GITHUB_TOKEN="), "env 文件含别名 export");
  }
}

// 9. Skill 注册断言：frontmatter 字段与主包内文件真实存在
{
  const s = skills.get("secret-env");
  const path = skillAssetPath();
  const file = readFileSync(path, "utf8");
  ok(!!s, "skill 已注册");
  if (s) {
    ok(s.name === "secret-env", "skill name 正确");
    ok(s.description.includes("密钥"), "skill description 非空");
    ok(existsSync(s.path), "skill path 指向真实 SKILL.md");
    ok(s.content === file, "content 与主包文件一致");
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
