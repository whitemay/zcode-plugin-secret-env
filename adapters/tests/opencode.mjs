// opencode 适配器冒烟测试：直接调 tool.execute.before 处理器，构造假 input/output。
// 覆盖：旁路、改名注入、braced、别名、dump 拒绝、单引号拒绝、env 文件原名 export。
// 注意值断言只查 export 行的存在与名字，不打印真值。
import { readFileSync } from "node:fs";
import { SecretEnvPlugin } from "../opencode.ts";

let pass = 0, fail = 0;
const ok = (cond, label) => { cond ? pass++ : (fail++, console.error(`✗ ${label}`)); };

const plugin = await SecretEnvPlugin();
const before = (cmd) => {
  const output = { args: { command: cmd } };
  return { output, run: () => plugin["tool.execute.before"]({ tool: "bash", sessionID: "test-oc" }, output) };
};

const D = "$" + "GH_TOKEN"; // 拼接构造，避免本文件被真钩子拦截

// 1. 无引用旁路
{
  const { output, run } = before(`echo hello`);
  await run();
  ok(output.args.command === "echo hello", "无引用零改写");
}
// 2. 原名引用 → 前缀 + 命令零改写
{
  const { output, run } = before(`echo ${D}`);
  await run();
  ok(output.args.command.includes("; echo " + D), "命令文本零改写");
  ok(output.args.command.startsWith(". '"), "带 source 前缀");
}
// 3/4. braced 与别名：export 行落在 env 文件里，不在命令文本中
const readEnvFile = (command) => {
  const m = command.match(/\. '([^']+)'/);
  return m ? readFileSync(m[1], "utf8") : "";
};
{
  const { output, run } = before("echo " + "$" + "{GH_TOKEN}");
  await run();
  ok(readEnvFile(output.args.command).includes("export GH_TOKEN="), "braced 导出原名");
}
{
  const { output, run } = before("echo " + "$" + "{GITHUB_TOKEN}");
  await run();
  ok(readEnvFile(output.args.command).includes("export GITHUB_TOKEN="), "别名按引用名导出");
}
// 5. dump 拒绝
{
  const { run } = before(`GH_TOKEN=${D} env`);
  let threw = false;
  try { await run(); } catch { threw = true; }
  ok(threw, "dump 命令抛错拒绝");
}
// 6. 单引号拒绝
{
  const { run } = before(`echo '${D}'`);
  let threw = false;
  try { await run(); } catch { threw = true; }
  ok(threw, "单引号内引用抛错拒绝");
}
// 7. 非 bash 工具旁路
{
  const output = { args: { file: "/tmp/x" } };
  await plugin["tool.execute.before"]({ tool: "read", sessionID: "t" }, output);
  ok(output.args.file === "/tmp/x", "非 bash 工具不动");
}
// 8. env 文件内容核对（读最后一个 env 文件，只验 export 名，不回显值）
{
  const { output, run } = before(`echo ${D} ${"$"}{GITHUB_TOKEN}`);
  await run();
  const m = output.args.command.match(/\. '([^']+)'/);
  ok(!!m, "env 文件路径可解析");
  if (m) {
    const content = readFileSync(m[1], "utf8");
    ok(content.includes("export GH_TOKEN="), "env 文件含 GH_TOKEN export");
    ok(content.includes("export GITHUB_TOKEN="), "env 文件含别名 export");
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
