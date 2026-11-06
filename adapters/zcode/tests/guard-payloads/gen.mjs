// 生成文件守卫测试 payload（含受保护路径片段，故放脚本文件里生成而非命令文本直写）
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
const dir = import.meta.dirname;
const HOME = process.env.HOME;
const payloads = {
  // Bash：cat 稳定配置文件 → deny
  "bash-cat-config.json": { tool_name: "Bash", tool_input: { command: `cat ${HOME}/.config/secret-env/secrets.json` } },
  // Bash：读 vault → deny（~/ 形态）
  "bash-cat-vault-tilde.json": { tool_name: "Bash", tool_input: { command: `cat ~/.config/secret-env/vault.kdbx | head -c 32` } },
  // Bash：无关命令但含密钥引用 → 照常注入（守卫不误伤注入链路）
  "bash-inject-ok.json": { tool_name: "Bash", tool_input: { command: `[ -n "$BW_SESSION" ] && echo inject-path-still-works` } },
  // Write：file_path 指向 vault → deny
  "write-vault.json": { tool_name: "Write", tool_input: { file_path: `${HOME}/.config/secret-env/vault.kdbx`, content: "x" } },
  // Edit：file_path 指向稳定配置 → deny
  "edit-config.json": { tool_name: "Edit", tool_input: { file_path: `${HOME}/.config/secret-env/secrets.json`, old_string: "a", new_string: "b" } },
  // Read：file_path 指向 ZCode 适配器兼容位的 secrets.json → deny
  "read-compat.json": { tool_name: "Read", tool_input: { file_path: "/Users/aston/github/zcode-plugin-secret-env/adapters/zcode/secrets.json" } },
  // Write：无关文件 → allow
  "write-unrelated.json": { tool_name: "Write", tool_input: { file_path: "/tmp/secret-env-guard-unrelated.txt", content: "x" } },
};
mkdirSync(dir, { recursive: true });
for (const [name, payload] of Object.entries(payloads)) writeFileSync(join(dir, name), JSON.stringify(payload));
console.log("payloads written:", Object.keys(payloads).join(", "));
