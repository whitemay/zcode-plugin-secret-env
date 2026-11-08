// opencode 适配器 cliParse 离线回归（bun tests/parse.test.ts）：
// 假 rsenv 写进临时目录挂 PATH 前列，进程内三态断言 + 独立进程 missing-CLI 断言。
// 坑：BIN 在模块 import 时捕获 SENV_BIN，进程内改环境变量无效——missing 用例必须子进程跑。
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TD = mkdtempSync(join(tmpdir(), "oc-parse-test."));
const FAKEBIN = join(TD, "fakebin");
mkdirSync(FAKEBIN, { recursive: true });
let failed = 0;
const check = (ok: boolean, label: string) => {
  if (!ok) { console.error(`FAIL: ${label}`); failed = 1; } else console.log(`  ${label} OK`);
};

try {
  // 假 rsenv：parse 按 stdin 命令文本返回三态；inject 输出 export 行
  const fake = `#!/bin/sh
case "$1" in
  parse)
    read -r line
    case "$line" in
      *REF_TOKEN*) printf '{"action":"inject","token":"tok123","names":["REF_TOKEN"]}' ;;
      *dump*) printf '{"action":"reject","reason":"dump intent"}' ;;
      *) printf '{"action":"pass"}' ;;
    esac ;;
  inject)
    printf "export REF_TOKEN='fake_value_123'" ;;
  *) exit 1 ;;
esac
`;
  writeFileSync(join(FAKEBIN, "rsenv"), fake); chmodSync(join(FAKEBIN, "rsenv"), 0o755);

  const env = { ...process.env, PATH: `${FAKEBIN}:${process.env.PATH}`, SENV_BIN: "rsenv" };
  // 主体三态（同进程）
  const main = spawnSync("bun", [join(HERE, "cases.main.ts")], { env, encoding: "utf8" });
  process.stdout.write(main.stdout);
  if (main.status !== 0) { process.stderr.write(main.stderr); failed = 1; }
  // missing-CLI（独立进程，SENDBIN 指不存在路径）
  const missing = spawnSync("bun", [join(HERE, "cases.missing.ts")], { env: { ...env, SENV_BIN: "/nonexistent/rsenv" }, encoding: "utf8" });
  process.stdout.write(missing.stdout);
  if (missing.status !== 0) { process.stderr.write(missing.stderr); failed = 1; }
  check(main.status === 0 && missing.status === 0, "cliParse 三态 + missing-CLI");
} finally {
  rmSync(TD, { recursive: true, force: true });
}
process.exit(failed);
