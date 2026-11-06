// DSH 适配器内的同步判定规则：scanRefs 与 matchGuardPaths。
// 为什么复制而不是 import 主包：`ctx.tools.guard` 是同步回调（每次工具调用都跑，不能 await 子进程），
// 扫描算法必须留在插件内；规则**数据**（guardPaths）仍由 CLI 的 info 提供，不在这里硬编码。
// 同步来源：core.mjs 的 scanRefs（2026-11-06 复制）。改任一边都要同步另一边，并跑 tests/rules-sync.mjs。
// 返回每个引用 token 的 {token, start, inSingle, name}；deny 为宿主拒绝回调（占位符未配置时调用）。
export function scanRefs(command, config, deny) {
  const tokens = []; // {token, start, inSingle, name}
  const unknownPlaceholders = [];

  // 逐字符扫描建立单引号区间（shell 语义：单引号内无转义）
  const singleRanges = [];
  let inSingle = false, rangeStart = -1;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "'") {
      if (inSingle) { singleRanges.push([rangeStart, i]); inSingle = false; }
      else { inSingle = true; rangeStart = i; }
    }
  }
  const inSingleQuote = (i) => singleRanges.some(([a, b]) => i > a && i < b);

  // ① 占位符 {{secret:NAME}}
  const phRe = /\{\{secret:([A-Za-z0-9_]+)\}\}/g;
  let m;
  while ((m = phRe.exec(command))) {
    const name = m[1];
    if (!config.has(name)) { unknownPlaceholders.push(name); continue; }
    tokens.push({ token: m[0], start: m.index, name, inSingle: inSingleQuote(m.index) });
  }
  if (unknownPlaceholders.length) {
    deny(`secret-env：占位符 {{secret:${unknownPlaceholders.join("、")}}} 未在 secrets.json 配置。宁可失败：请修正名字或先配置。`);
  }

  // ② 显式 $NAME / ${NAME}（词边界；\$ 转义跳过）
  for (const [alias, info] of config) {
    const re = new RegExp(`(?<![A-Za-z0-9_\\$])\\$\{?${alias}(?![A-Za-z0-9_])`, "g");
    while ((m = re.exec(command))) {
      if (m.index > 0 && command[m.index - 1] === "\\") continue;
      tokens.push({ token: m[0], start: m.index, name: info.canonical, inSingle: inSingleQuote(m.index) });
    }
  }
  return tokens;
}

// 受保护片段匹配（规则数据来自 CLI info 的 rules.guardPaths）
export function matchGuardPaths(text, fragments) {
  return typeof text === "string" ? fragments.find((f) => text.includes(f)) : undefined;
}
