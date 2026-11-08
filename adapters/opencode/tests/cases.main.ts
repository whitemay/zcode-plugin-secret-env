// 三态主体（由 parse.test.ts 以假 rsenv PATH 环境调起）
import { cliParse } from "../index.ts";

const rewritten = await cliParse("echo $REF_TOKEN");
if (!rewritten?.includes("rsenv inject tok123") || !rewritten.includes("eval") || !rewritten.includes("{ echo $REF_TOKEN; }")) {
  console.error("FAIL rewrite:", rewritten); process.exit(1);
}
console.log("rewrite OK:", rewritten);

const pass = await cliParse("echo hello");
if (pass !== null) { console.error("FAIL pass:", pass); process.exit(1); }
console.log("pass OK");

let threw = "";
try { await cliParse("printenv dump"); } catch (e) { threw = (e as Error).message; }
if (!threw.includes("dump intent")) { console.error("FAIL reject:", threw); process.exit(1); }
console.log("reject OK");
process.exit(0);
