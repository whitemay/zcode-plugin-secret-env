# 在 DSH 中安装 secret-env（agent 执行版）

面向 DSH 会话内的 agent。按顺序执行；`plugin_manager` 与写 `~/.dsh` 都会触发权限审批，等用户批准即可。

## 前置

- 在 DSH 会话中执行。
- **是两个包**：全局 CLI（真身，`@foperate/secret-env`）+ DSH bundle（`@foperate/secret-env-dsh`，零依赖薄包）。
  bundle 不 import 主包代码，运行时经 PATH 上的 `secret-env` 走宿主协议（`protocol 1`），因此
  **CLI 必须在 PATH 上且支持协议 1**，否则插件拒绝加载（宁可失败）。
- 安装顺序：先全局 CLI，再装 bundle，最后重启。

## 1. 安装全局 CLI（真身）

```bash
bun add -g @foperate/secret-env        # 或 npm i -g @foperate/secret-env
secret-env info                        # 应输出一行含 "protocol":1 的 JSON
```

`secret-env info` 不输出 JSON（只有用法）→ 说明装的是不含协议的旧版本或没进 PATH，先升级/修复再继续。

## 2. 安装 Host 插件（bundle）

调用 `plugin_manager`：

```
action: install_bundle
target: @foperate/secret-env-dsh@0.3.2        # npm 上的 bundle 包
```

要点：

- 每次调用会请求一次完整文件访问审批，等用户批准。
- 成功返回里看 `application` 与 `warnings`；`warnings` 非空时如实转述，不要重复安装制造重复条目。
- 成功后 profile 的 `package.json` 依赖与 `dsh.profile.bundles` 会记录 `@foperate/secret-env-dsh`。

## 3. 安装 skill

skill **随 bundle 包分发**（`skills/secret-env/`），DSH 只从 `~/.dsh/skills` 发现 skill，做一次指向：

```bash
mkdir -p ~/.dsh/skills
ln -sfn "$HOME/.dsh/profiles/desktop/node_modules/@foperate/secret-env-dsh/skills/secret-env" ~/.dsh/skills/secret-env
```

skill 是 symlink，DSH 的 skill-filesystem 热加载；随 bundle 升级自动指向新版本，无需重装。

## 4. 重启 DSH

Host 插件代码在 DSH 启动时加载，安装或替换后都必须重启。**告诉用户重启**，不要尝试用命令重启宿主进程。

## 验证

1. 新会话的工具列表里出现 `add_secret`。
2. 系统提示里出现「secret-env：已配置的密钥…」清单（只有名字和描述，没有值）。
3. 插件日志 `<tmpdir>/secret-env-dsh.log` 出现 `applied protocol=1 …`，不再出现 `defineTool unavailable`。

## 更新

- CLI：按全局包管理器升级（`bun add -g @foperate/secret-env@<ver>`）。
- bundle：`plugin_manager` 的 `updateBundle`，或先 `remove_bundle` 再 `install_bundle` 新版本；改代码后重启 DSH。
- 两包的协议版本必须匹配（bundle 启动时握手校验）。

## 卸载

1. `plugin_manager`：`action: remove_bundle`，`target: @foperate/secret-env-dsh`
2. 删除 skill 链接：`rm ~/.dsh/skills/secret-env`（只删链接）
3. 可选：卸载全局 CLI

## 排错

- **`add_secret` 没出现**：确认 bundle 返回 `application: applied` 且已重启；再看插件日志。
- **初始化报「无法启动 secret-env」**：CLI 不在 PATH——先做第 1 步。
- **初始化报「协议版本不匹配」**：CLI 与 bundle 版本不配套——升级其中一个到匹配版本。
- **审批被拒**：让用户批准后重试同一操作，不要改用手工写 profile 文件绕开。
- **重复安装报错**：先 `remove_bundle` 再装。
- **不要手写** profile 的 `cordis.patch.yml`、`package.json` 或手工 symlink 到 profile `node_modules`——安装与卸载统一由 `plugin_manager` 管理。
- 本适配器的工具定义直接交给 `ctx.tools.register` 的 JSON Schema，不要再改成 `import defineTool`（见 AGENTS.md 的解析坑）。
