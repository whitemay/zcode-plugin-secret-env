// missing-CLI 用例（由 parse.test.ts 以 SENV_BIN=/nonexistent 调起）：宁可失败抛错
process.env.SENV_BIN = "/nonexistent/rsenv";
const { cliParse } = await import("../index.ts");
try { await cliParse("echo hi"); console.error("FAIL: resolved instead of throwing"); process.exit(1); }
catch (e) {
  const s = String(e);
  if (!s.includes("ENOENT") && !s.includes("不在 PATH")) { console.error("FAIL:", s); process.exit(1); }
  console.log("missing-CLI error OK");
}
process.exit(0);
