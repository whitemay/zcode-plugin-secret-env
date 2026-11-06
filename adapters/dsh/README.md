# @foperate/secret-env-dsh

secret-env 的 DeepSeek Harness（DSH）bundle：把密钥从私有库注入 bash 子进程环境，模型上下文永不见值。

**独立包**：本包零依赖，不 import 主包代码；运行时经 PATH 上的全局 CLI `secret-env` 走宿主协议
（`protocol 1`：`info` / `inject` / `store`，stdin/stdout JSON，值只经 stdin 且不回显）。

## 安装

```bash
# 1) 全局 CLI（真身；注入、守卫、入库都在这里）
bun add -g @foperate/secret-env        # 或 npm i -g @foperate/secret-env

# 2) DSH bundle（本包；装进当前 profile）
#    plugin_manager → action: install_bundle, target: @foperate/secret-env-dsh@<version>
```

skill 由 DSH 从 `~/.dsh/skills` 发现，指向本包的 `skills/secret-env`：

```bash
ln -sfn "$HOME/.dsh/profiles/<profile>/node_modules/@foperate/secret-env-dsh/skills/secret-env" \
  "$HOME/.dsh/skills/secret-env"
```

安装或升级后重启 DSH（插件代码在启动时加载）。

## 组成

| 文件 | 作用 |
|---|---|
| `index.js` | 装配：`tools/execute` bash 注入、`tools.guard` 同步守卫、systemPrompt 清单、`add_secret` 工具 |
| `client.mjs` | 协议客户端（`$SENV_BIN` → PATH `secret-env`），超时/退出码/非 JSON 转 `CliError` |
| `guards.mjs` | 文件工具与 pwsh/terminal_send 的同步守卫（bash 守卫在 CLI 的 `inject` 里） |
| `rules.mjs` | `scanRefs` 同步副本（与主包 `core.mjs` 同源，跨仓库测试校验） |
| `entry.mjs` | DSH 专属文案与卡片答案判定 |
| `cordis.patch.yml` | DSH bundle 补丁（插入 `@foperate/secret-env-dsh` 行） |
| `skills/secret-env/` | skill 副本（与主包 `skills/secret-env` 逐字节一致） |

## 兼容

- 需要主包 CLI 支持 `protocol 1`（`secret-env info` 可验证）；协议不匹配时插件拒绝加载（宁可失败）。
- 已知：`ctx.tools.guard` 同步回调限制决定了守卫不能走子进程；bash 守卫与注入统一在 CLI，
  GUI 内文件/通道守卫在本包，`rules-sync` 测试保证两处判定同源。
