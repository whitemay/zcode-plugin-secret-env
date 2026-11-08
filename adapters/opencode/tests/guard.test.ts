// opencode 文件守卫纯函数离线回归（bun tests/guard.test.ts）：挂账清偿 2026-11-08
import { evaluateFileGuard } from "../index.ts";

const FRAGS = [".config/secret-env", "/Users/x/.config/secret-env/vault.db"];
const reason = (r?: string) => (r ? "deny" : "pass");

// 已知路径键命中
if (reason(evaluateFileGuard("read", { file_path: "/Users/x/.config/secret-env/vault.db" }, FRAGS)) !== "deny") {
  console.error("FAIL: file_path hit"); process.exit(1);
}
// 别名键命中
if (reason(evaluateFileGuard("write", { path: "~/.config/secret-env/audit.jsonl" }, FRAGS)) !== "deny") {
  console.error("FAIL: path alias hit"); process.exit(1);
}
// 未知字段名的路径尺度值兜底命中
if (reason(evaluateFileGuard("edit", { target: "/Users/x/.config/secret-env/vault.db" }, FRAGS)) !== "deny") {
  console.error("FAIL: unknown-key fallback hit"); process.exit(1);
}
// 长内容（>1024）含片段不误伤（写文件内容场景）
const long = "x".repeat(1100) + ".config/secret-env";
if (reason(evaluateFileGuard("write", { content: long }, FRAGS)) !== "pass") {
  console.error("FAIL: long content false positive"); process.exit(1);
}
// 无片段放行
if (reason(evaluateFileGuard("read", { file_path: "/tmp/notes.md" }, FRAGS)) !== "pass") {
  console.error("FAIL: clean pass"); process.exit(1);
}
// CLI 不可用（null 快照）→ 降级保护缺省工作目录：约定路径仍拒、无关路径放行
if (reason(evaluateFileGuard("read", { file_path: `${process.env.HOME}/.config/secret-env/vault.db` }, null)) !== "deny") {
  console.error("FAIL: fallback should protect convention dir"); process.exit(1);
}
if (reason(evaluateFileGuard("read", { file_path: "/tmp/notes.md" }, null)) !== "pass") {
  console.error("FAIL: fallback should pass non-vault paths"); process.exit(1);
}
// 空输入放行
if (reason(evaluateFileGuard("read", undefined, FRAGS)) !== "pass") {
  console.error("FAIL: empty input"); process.exit(1);
}
console.log("guard.test: ALL PASS");
