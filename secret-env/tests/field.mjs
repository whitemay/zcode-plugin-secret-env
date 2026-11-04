// 字段寻址测试：keychain/account 探针往返 + bitwarden 字段解析（单测 + 真机对账）。
// 运行：bun secret-env/tests/field.mjs（探针条目用后即删；bw 对账只打印长度，不打印值）
import { systemBackend, resolveValue, pickBwField, loadConfig } from "../../core.mjs";

let failed = 0;
function check(name, cond, detail = "") {
  if (cond) console.log(`  ✅ ${name}`);
  else { failed++; console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ""}`); }
}
async function expectErr(name, p, keyword) {
  try { await p; failed++; console.log(`  ❌ ${name} — 应报错却成功了`); }
  catch (e) { check(name, keyword ? e.message.includes(keyword) : true, e.message); }
}

// ---------- 1. pickBwField 纯函数单测 ----------
console.log("pickBwField 单测：");
const item = { id: "i-1", fields: [{ name: "token", value: "t".repeat(32) }, { name: "empty", value: "" }, { name: "noVal" }] };
check("命中自定义字段", pickBwField(item, "token").length === 32);
check("空值字段返回空串", pickBwField(item, "empty") === "");
check("无 value 字段返回空串", pickBwField(item, "noVal") === "");
await expectErr("缺字段报错并列出现有字段名", Promise.resolve().then(() => pickBwField(item, "token2")), "现有：token");
await expectErr("无字段条目报错", Promise.resolve().then(() => pickBwField({ id: "i-2" }, "x")), "无自定义字段");

// ---------- 2. keychain 探针往返（darwin） ----------
if (process.platform === "darwin") {
  console.log("keychain account 探针：");
  const SVC = "secret-env-field-test";
  const backend = systemBackend();
  try { await backend.remove(SVC); } catch {}
  await backend.write(SVC, "probe-pwd-" + "x".repeat(8), "probe-acct");
  check("一级寻址 = password", (await resolveValue(`keychain://${SVC}`)) === "probe-pwd-xxxxxxxx");
  check("/account 二级寻址", (await resolveValue(`keychain://${SVC}/account`)) === "probe-acct");
  await expectErr("不支持的字段报人话", resolveValue(`keychain://${SVC}/label`), "只支持 account");
  // 多 account 歧义：同 service 第二个 account 条目，password 与 account 两条路径都拒绝
  const { execFileSync } = await import("node:child_process");
  execFileSync("security", ["add-generic-password", "-a", "probe-acct-b", "-s", SVC, "-w", "p2", "-U"]);
  await expectErr("password 路径歧义拒绝", resolveValue(`keychain://${SVC}`), "歧义");
  await expectErr("account 路径歧义拒绝", resolveValue(`keychain://${SVC}/account`), "歧义");
  // 清理两条探针
  for (const acct of ["probe-acct", "probe-acct-b"]) {
    try { execFileSync("security", ["delete-generic-password", "-s", SVC, "-a", acct]); } catch {}
  }
  check("探针清理完成", !(() => {
    try { execFileSync("security", ["find-generic-password", "-s", SVC]); return true; } catch { return false; }
  })());
}

// ---------- 3. bitwarden 真机对账（只断言长度） ----------
// 条目 gitee个人：password(14ch) + 自定义字段 手机号(12ch)/邮箱(20ch)/token(32ch)（2026-11-04 探针确认）
console.log("bitwarden 真机对账：");
try {
  const config = loadConfig();
  const ID = "91cf901b-fa43-404c-90e5-f1e72f180bf9";
  const pwd = await resolveValue(`bitwarden://${ID}`, config);
  check("一级寻址仍取 password", pwd.length === 14, `len=${pwd.length}`);
  const tok = await resolveValue(`bitwarden://${ID}/token`, config);
  check("自定义字段 token 长度对账", tok.length === 32, `len=${tok.length}`);
  const mail = await resolveValue(`bitwarden://${ID}/邮箱`, config);
  check("中文字段名可寻址", mail.length === 20, `len=${mail.length}`);
  await expectErr("不存在的字段报错并列出现有字段", resolveValue(`bitwarden://${ID}/不存在`, config), "现有：");
} catch (e) {
  console.log(`  ⚠️ 跳过（bw 不可用或条目变化）：${e.message.slice(0, 80)}`);
}

console.log(failed ? `\n${failed} 项失败` : "\n全部通过");
process.exit(failed ? 1 : 0);
