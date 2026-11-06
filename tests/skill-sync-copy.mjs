// skill 副本同步：把权威位 skills/secret-env/ 同步到各宿主副本。
// 权威位改动后跑一次，再跑 bun tests/skill-sync.mjs 确认一致。
// 用法：bun tests/skill-sync-copy.mjs
import { cpSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname;
const CANON = join(ROOT, "skills", "secret-env");
const COPIES = {
  zcode: join(ROOT, "adapters", "zcode", "skills", "secret-env"),
  opencode: join(ROOT, "adapters", "opencode", "skills", "secret-env"),
  dsh: join(ROOT, "adapters", "dsh", "skills", "secret-env"),
};

if (!existsSync(CANON)) {
  console.error(`✗ 权威副本不存在：${CANON}`);
  process.exit(1);
}

for (const [host, dir] of Object.entries(COPIES)) {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dirname(dir), { recursive: true });
  cpSync(CANON, dir, { recursive: true });
  console.log(`✓ ${host} ← ${dir}`);
}

console.log("完成。跑 bun tests/skill-sync.mjs 校验。");
