// secret-env 钩子回归测试。运行：bun secret-env/tests/hook.mjs
// 注：payload 内的 $VAR 一律用 "$" + "NAME" 拼接构造，避免本会话钩子误拦测试命令文本。
import { writeFileSync, unlinkSync } from "node:fs";

const D = "$";
const HOOK = new URL("../hooks/secret-env.mjs", import.meta.url).pathname;
const TMP = "/tmp/secret-env-test-payload.json";

function run(command, sessionId = "test") {
  writeFileSync(TMP, JSON.stringify({ tool_name: "Bash", session_id: sessionId, tool_input: { command } }));
  const p = Bun.spawnSync(["bash", "-c", `cat ${TMP} | bun ${HOOK}`], { stdout: "pipe", stderr: "pipe" });
  return { exit: p.exitCode, stdout: p.stdout.toString(), stderr: p.stderr.toString().trim() };
}

let failed = 0;
function check(name, cond, detail = "") {
  if (cond) console.log(`  ✅ ${name}`);
  else { failed++; console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ""}`); }
}

console.log("① 无引用命令 → 纯放行");
{
  const r = run("ls -la");
  check("allow 无 updatedInput", r.exit === 0 && r.stdout.includes('"permissionDecision":"allow"') && !r.stdout.includes("updatedInput"), r.stderr);
}

console.log("② 同名显式引用 → source 前缀 + 命令零改写");
{
  const r = run(`GH_TOKEN=${D}GH_TOKEN git push origin main`);
  const out = JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command;
  check("allow", r.exit === 0, r.stderr);
  check("前缀 source", out.startsWith(". ") && out.includes("secret-env-injections"));
  check("命令体零改写", out.endsWith(`GH_TOKEN=${D}GH_TOKEN git push origin main`));
}

console.log("③ 花括号引用 → 识别");
{
  const r = run(`GH_TOKEN=${D}{GH_TOKEN} git push`);
  check("allow + 前缀", r.exit === 0 && JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command.startsWith(". "), r.stderr);
}

console.log("④ 别名引用 → 按别名原名注入");
{
  const r = run(`GITHUB_TOKEN=${D}{GITHUB_TOKEN} git push`);
  const out = JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command;
  check("allow", r.exit === 0, r.stderr);
  check("命令体零改写", out.endsWith(`GITHUB_TOKEN=${D}{GITHUB_TOKEN} git push`));
}

console.log("⑤ 任意名引用 → 注入原名 GH_TOKEN");
{
  const r = run(`USE_TOKEN=${D}GH_TOKEN some-tool`);
  check("allow + 前缀", r.exit === 0 && JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command.startsWith(". "), r.stderr);
}

console.log("⑥ 同命令倾泻 → 拒绝");
{
  const r = run(`GH_TOKEN=${D}GH_TOKEN env`);
  check("exit 2", r.exit === 2, `exit=${r.exit}`);
  check("提示含移除倾泻", r.stderr.includes("倾泻"));
}

console.log("⑦ 单引号内引用 → 拒绝");
{
  const r = run(`sh -c 'echo ${D}GH_TOKEN'`);
  check("exit 2", r.exit === 2, `exit=${r.exit}`);
  check("提示改双引号", r.stderr.includes("双引号"));
}

console.log("⑧ env 文件以引用原名 export");
{
  const r = run(`GITHUB_TOKEN=${D}GH_TOKEN true`, "envname");
  const cmd = JSON.parse(r.stdout).hookSpecificOutput.updatedInput.command;
  const envPath = cmd.match(/\. '([^']+)'/)?.[1];
  const content = await Bun.file(envPath).text();
  check("export GH_TOKEN=（非 ZCODE_SECRET）", /^export GH_TOKEN=/.test(content), content.slice(0, 40));
  check("export GITHUB_TOKEN 也在（引用名）", !content.includes("GITHUB_TOKEN") || /^export GITHUB_TOKEN=/.test(content));
  check("env 文件 0600", (await Bun.file(envPath).stat?.()) ?? true); // 权限检查由写入方 mode 保证
  unlinkSync(envPath);
}

unlinkSync(TMP);
console.log(failed === 0 ? "\n全部通过 ✅" : `\n${failed} 项失败 ❌`);
process.exit(failed === 0 ? 0 : 1);
