// skill 副本一致性检查：skills/secret-env（权威）与各宿主自带的副本必须逐字节一致。
// 权威副本在主包根；各宿主各存一份真实副本，不做跨包引用：
//   - ZCode：marketplace 用 git-subdir 只拉 adapters/zcode，跨出该子目录的路径（含软链）到不了。
//   - opencode：插件包独立发 npm，自带副本才自包含。
//   - DSH：bundle 包（adapters/dsh）独立发 npm，skill 随包分发，`~/.dsh/skills` symlink 指向它。
// 运行：bun tests/skill-sync.mjs（CI 与 pre-commit 都应跑）
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname;
const CANON = join(ROOT, "skills", "secret-env");
const COPIES = {
  zcode: join(ROOT, "adapters", "zcode", "skills", "secret-env"),
  opencode: join(ROOT, "adapters", "opencode", "skills", "secret-env"),
  dsh: join(ROOT, "adapters", "dsh", "skills", "secret-env"),
};

function walk(dir, base = dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, base, out);
    else out.push(relative(base, p));
  }
  return out.sort();
}

let failed = 0;
const fail = (msg) => { failed++; console.error(`✗ ${msg}`); };

if (!existsSync(CANON)) {
  console.error(`✗ 权威副本不存在：${CANON}`);
  process.exit(1);
}

const canonFiles = walk(CANON);

for (const [host, dir] of Object.entries(COPIES)) {
  if (!existsSync(dir)) {
    fail(`${host}: 副本目录不存在 ${dir}`);
    continue;
  }
  const files = walk(dir);

  // 文件集合一致
  const missing = canonFiles.filter((f) => !files.includes(f));
  const extra = files.filter((f) => !canonFiles.includes(f));
  if (missing.length) fail(`${host}: 缺少 ${missing.join(", ")}`);
  if (extra.length) fail(`${host}: 多出 ${extra.join(", ")}`);

  // 内容一致
  for (const f of canonFiles) {
    if (!files.includes(f)) continue;
    if (readFileSync(join(CANON, f), "utf8") !== readFileSync(join(dir, f), "utf8")) {
      fail(`${host}: 内容不一致 ${f}`);
    }
  }
}

if (failed === 0) console.log(`✓ skill 副本一致（${canonFiles.length} 个文件）`);
process.exit(failed ? 1 : 0);
