// DSH bundle 包形态校验：独立发版的结构不变量。
// 运行：bun tests/dsh-package.mjs
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("../", import.meta.url).pathname;
const DIR = join(ROOT, "adapters", "dsh");
const pkg = JSON.parse(readFileSync(join(DIR, "package.json"), "utf8"));

// 包身份
assert.equal(pkg.name, "@foperate/secret-env-dsh");
assert.equal(pkg.type, "module");
assert.equal(pkg.main, "./index.js");
assert.ok(existsSync(join(DIR, pkg.main)), "main 指向的文件应存在");

// dsh bundle 声明 + patch 存在且插入行用的是本包名
assert.equal(pkg.dsh?.bundle?.patch, "./cordis.patch.yml");
const patch = readFileSync(join(DIR, pkg.dsh.bundle.patch), "utf8");
assert.match(patch, new RegExp(`name: '${pkg.name.replace(/[/.]/g, "\\$&")}'`), "patch 的 insert name 应为包名");

// 零依赖：不得声明主包依赖（否则又会在 profile 里装一份主包）
assert.equal(pkg.dependencies, undefined, "不应有 dependencies");
assert.equal(pkg.peerDependencies, undefined, "不应有 peerDependencies（peer 会被部分包管理器自动安装，导致重复副本）");

// files 覆盖全部运行时文件
const SHIPPED = ["index.js", "entry.mjs", "guards.mjs", "rules.mjs", "client.mjs", "cordis.patch.yml", "icon.svg", "locale", "skills", "README.md"];
const declared = pkg.files.map((f) => f.replace(/\/$/, ""));
for (const entry of SHIPPED) {
  assert.ok(declared.includes(entry), `files 缺少 ${entry}`);
  assert.ok(existsSync(join(DIR, entry)), `文件/目录不存在：${entry}`);
}

// 适配器源码不得跨出本包（相对 import 只能 ./）
const walk = (dir, out = []) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "node_modules") continue;
      walk(p, out);
    } else if (/\.(js|mjs|ts)$/.test(name)) out.push(p);
  }
  return out;
};
for (const file of walk(DIR)) {
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(/from\s+["']([^"']+)["']/g)) {
    const spec = m[1];
    if (spec.startsWith("node:")) continue;
    if (spec.startsWith("./") || spec.startsWith("../")) {
      assert.ok(!spec.startsWith("../"), `${relative(ROOT, file)} 跨包相对 import：${spec}`);
      continue;
    }
    assert.fail(`${relative(ROOT, file)} 引用了外部模块：${spec}`);
  }
}

// 主包不再声明 dsh bundle（避免同名 bundle 出现两个来源）
const mainPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
assert.equal(mainPkg.dsh, undefined, "主包不应再声明 dsh.bundle");
assert.equal(mainPkg.exports?.["./dsh"], undefined, "主包不应再导出 ./dsh");

console.log("OK dsh bundle package shape");
