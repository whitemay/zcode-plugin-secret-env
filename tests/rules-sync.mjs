// 规则副本同步：adapters/dsh/rules.mjs 的 scanRefs 必须与 core.mjs 同行为。
// guard（同步判定）与注入（CLI 子进程）判定同源，漂移会造成「守卫放行但注入拒绝」或反之。
// 运行：bun tests/rules-sync.mjs
import assert from "node:assert/strict";
import { scanRefs as coreScan } from "../core.mjs";
import { matchGuardPaths, scanRefs as dshScan } from "../adapters/dsh/rules.mjs";

const D = "$";
const config = new Map([
  ["GH_TOKEN", { canonical: "GH_TOKEN", uri: "x" }],
  ["GITHUB_TOKEN", { canonical: "GH_TOKEN", uri: "x" }],
  ["NPM_TOKEN", { canonical: "NPM_TOKEN", uri: "x" }],
]);

const fixtures = [
  "ls -la",
  `echo ${D}GH_TOKEN`,
  `curl -H "Authorization: Bearer ${D}{GH_TOKEN}" https://x`,
  `echo ${D}GITHUB_TOKEN`,
  `echo ${D}GH_TOKENX`, // 词边界：不应命中
  "echo \\" + D + "GH_TOKEN", // 反斜杠转义：跳过
  `sh -c 'echo ${D}GH_TOKEN'`, // 单引号区间
  `echo "$GH_TOKEN" ${D}NPM_TOKEN`,
  `echo {{secret:GH_TOKEN}}`,
  `echo {{secret:NOPE}}`, // deny：占位符未配置
  `${D}NPM_TOKEN && ${D}GITHUB_TOKEN`,
];

for (const command of fixtures) {
  const coreDeny = [], dshDeny = [];
  const coreTokens = coreScan(command, config, (reason) => coreDeny.push(reason));
  const dshTokens = dshScan(command, config, (reason) => dshDeny.push(reason));
  assert.deepEqual(dshTokens, coreTokens, `token 不一致：${command}`);
  assert.deepEqual(dshDeny, coreDeny, `deny 消息不一致：${command}`);
}

// 受保护片段匹配（规则数据来自 CLI info）
assert.equal(matchGuardPaths("/x/.config/secret-env/y", [".config/secret-env"]), ".config/secret-env");
assert.equal(matchGuardPaths("/tmp/ok", [".config/secret-env"]), undefined);
assert.equal(matchGuardPaths(undefined, [".config/secret-env"]), undefined);
assert.equal(matchGuardPaths(123, [".config/secret-env"]), undefined);

console.log(`OK rules sync (${fixtures.length} fixtures)`);
