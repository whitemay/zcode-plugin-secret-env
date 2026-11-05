// 写侧自治测试：viking / bitwarden 探针条目写入→读回对账，用后即删。运行：bun secret-env/tests/write.mjs
// 值只进内存/长度断言，不打印。
import { writeValue, resolveValue, loadConfig } from "../../core.mjs";
import { execFileSync } from "node:child_process";

let failed = 0;
function check(name, cond, detail = "") {
  if (cond) console.log(`  ✅ ${name}`);
  else { failed++; console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ""}`); }
}
async function expectErr(name, p, keyword) {
  try { await p; failed++; console.log(`  ❌ ${name} — 应报错却成功了`); }
  catch (e) { check(name, keyword ? e.message.includes(keyword) : true, e.message); }
}

const config = loadConfig();
const PROBE = "secret-env-write-probe";

// ---------- 1. viking：field 段与主值两种落位 ----------
console.log("viking 写入往返：");
try {
  await writeValue({ provider: "viking", parts: ["probe-cat", "probe-target", "probe_f"] }, "v".repeat(13), config);
  check("field 段写读往返", (await resolveValue("viking://probe-cat/probe-target/probe_f", config)).length === 13);
  await writeValue({ provider: "viking", parts: ["probe-cat2", "probe-target"] }, "m".repeat(7), config);
  check("主值落 value 字段", (await resolveValue("viking://probe-cat2/probe-target", config)).length === 7);
  await expectErr("两段以下拒绝", writeValue({ provider: "viking", parts: ["only-cat"] }, "x"), "写入需");
} catch (e) {
  console.log(`  ⚠️ viking 不可用：${e.message.slice(0, 60)}`);
} finally {
  for (const uri of ["viking://~/privacy/probe-cat/probe-target", "viking://~/privacy/probe-cat2/probe-target"]) {
    try { execFileSync("ov", ["rm", uri, "--recursive"]); } catch {}
  }
}

// ---------- 2. bitwarden：新建 → 更新 → 自定义字段 → username ----------
console.log("bitwarden 写入往返：");
try {
  await writeValue({ provider: "bitwarden", item: PROBE, user: "probe-usr" }, "p".repeat(11), config);
  check("新建条目 password 位", (await resolveValue(`bitwarden://${PROBE}`, config)).length === 11);
  check("--user 写 username 位", (await resolveValue(`bitwarden://${PROBE}/username`, config)) === "probe-usr");
  await writeValue({ provider: "bitwarden", item: PROBE }, "q".repeat(9), config);
  check("已存在条目更新 password", (await resolveValue(`bitwarden://${PROBE}`, config)).length === 9);
  await writeValue({ provider: "bitwarden", item: PROBE, field: "wf" }, "f".repeat(17), config);
  check("--field upsert 自定义字段", (await resolveValue(`bitwarden://${PROBE}/wf`, config)).length === 17);
  await expectErr("field 不隐式建条目", writeValue({ provider: "bitwarden", item: "secret-env-no-such-item-xyz", field: "f" }, "x", config), "不隐式建条目");
} catch (e) {
  console.log(`  ⚠️ bitwarden 不可用：${e.message.slice(0, 80)}`);
} finally {
  // 探针条目清理（bw delete item，session 经配置链解析）
  try {
    const sess = config.get("BW_SESSION") ? await resolveValue(config.get("BW_SESSION").uri, config) : process.env.BW_SESSION;
    const raw = execFileSync("bw", ["get", "item", PROBE, "--raw"], { env: { ...process.env, BW_SESSION: sess }, encoding: "utf8" });
    execFileSync("bw", ["delete", "item", JSON.parse(raw).id], { env: { ...process.env, BW_SESSION: sess } });
    console.log("  探针条目已删（trash）");
  } catch {}
}

// ---------- 3. onepassword：URI 解析守卫（不依赖 op）；读写往返仅在 op 可用时跑 ----------
console.log("onepassword：");
await expectErr("URI 三段以上拒绝", resolveValue("onepassword://a/b/c", config), "需为");
const hasOp = (() => { try { execFileSync("op", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();
if (!hasOp) {
  console.log("  ⏭️ 真机往返跳过（本机无 op CLI）——待安装后补跑 create/edit/字段往返");
} else {
  const OP = "secret-env-op-probe";
  try {
    await writeValue({ provider: "onepassword", item: OP, user: "op-usr" }, "o".repeat(10), config);
    check("新建条目 password 位", (await resolveValue(`onepassword://${OP}`, config)).length === 10);
    check("--user 写 username 位", (await resolveValue(`onepassword://${OP}/username`, config)) === "op-usr");
    await writeValue({ provider: "onepassword", item: OP }, "u".repeat(8), config);
    check("已存在条目更新 password", (await resolveValue(`onepassword://${OP}`, config)).length === 8);
    await writeValue({ provider: "onepassword", item: OP, field: "opf" }, "z".repeat(15), config);
    check("--field upsert 自定义字段", (await resolveValue(`onepassword://${OP}/opf`, config)).length === 15);
  } catch (e) {
    failed++; console.log(`  ❌ onepassword 真机往返 — ${e.message.slice(0, 100)}`);
  } finally {
    try { execFileSync("op", ["item", "delete", OP]); } catch {}
  }
}

console.log(failed ? `\n${failed} 项失败` : "\n全部通过");
process.exit(failed ? 1 : 0);
