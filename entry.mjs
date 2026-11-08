// 宿主无关的条目参数与命令构造：CLI / MCP / DSH 三端共用。
// 真正的入库统一走 cli.mjs 的 storeEntry（provider 写入 + secrets.json 登记），这里只负责把
// 元数据定稿转成 storeEntry 的 opts，以及生成「终端兜底」用的 senv set 命令。
export const PROVIDERS = ["keychain", "bitwarden", "viking", "onepassword"];

export function buildEntryOpts(p) {
  const o = {
    name: p.name,
    provider: p.provider,
    aliases: p.alias ? p.alias.split(",").map((s) => s.trim()).filter(Boolean) : [],
    description: p.description || undefined,
  };
  if (p.provider === "viking") o.path = p.detail;
  else if (p.provider !== "keychain") o.item = p.detail;
  return o;
}

export function entryCommandText(p) {
  const o = buildEntryOpts(p);
  let c = `senv set ${JSON.stringify(p.name)} --provider ${o.provider}`;
  if (o.item) c += ` --item ${JSON.stringify(o.item)}`;
  if (o.path) c += ` --path ${JSON.stringify(o.path)}`;
  if (o.aliases.length) c += ` --alias ${o.aliases.map((a) => JSON.stringify(a)).join(" --alias ")}`;
  if (o.description) c += ` --desc ${JSON.stringify(o.description)}`;
  return c;
}
