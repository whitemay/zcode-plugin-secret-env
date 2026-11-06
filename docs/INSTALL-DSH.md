# 在 DSH 中安装 secret-env（agent 执行版）

面向 DSH 会话内的 agent。按顺序执行；`plugin_manager` 与写 `~/.dsh` 都会触发权限审批，等用户批准即可。

## 前置

- 在 DSH 会话中执行。
- **只装主包即可**：DSH 不需要独立的插件包（opencode 才需要）。
- **主包是插件本体**：`@foperate/secret-env` 的根 `package.json` 声明了 `dsh.bundle.patch`，安装主包即安装 DSH 插件（适配器在包内 `adapters/dsh/`，patch 通过 exports 的 `@foperate/secret-env/dsh` 解析）。不需要独立的 DSH 插件包。
- **装的是 npm 上的主包**，不指向任何本地目录：profile 依赖记为版本号（如 `0.3.1`），升级走 registry。

## 1. 安装 Host 插件（bundle）

调用 `plugin_manager`：

```
action: install_bundle
target: @foperate/secret-env@0.3.1        # 已发布的 npm 包
```

要点：

- 每次调用会请求一次完整文件访问审批，等用户批准。
- 成功返回里看 `application` 与 `warnings`；`warnings` 非空时如实转述，不要重复安装制造重复条目。
- 成功后 profile 的 `package.json` 依赖与 `dsh.profile.bundles` 会记录 `@foperate/secret-env`。

## 2. 安装 skill

skill 不在 bundle 里，DSH 只从 `~/.dsh/skills` 发现 skill。指向**已安装的主包**（profile 的 `node_modules`），不要指向仓库目录——升级主包后自动跟随新版本：

```bash
mkdir -p ~/.dsh/skills
ln -sfn "$HOME/.dsh/profiles/desktop/node_modules/@foperate/secret-env/skills/secret-env" ~/.dsh/skills/secret-env
```

skill 是 symlink，DSH 的 skill-filesystem 热加载，改 `SKILL.md` / `references/` 无需重装或重启。

## 3. 重启 DSH

Host 插件代码在 DSH 启动时加载，安装或替换后都必须重启。**告诉用户重启**，不要尝试用命令重启宿主进程。

## 验证

1. 新会话的工具列表里出现 `add_secret`。
2. 系统提示里出现「secret-env：已配置的密钥…」清单（只有名字和描述，没有值）。
3. 插件日志 `<tmpdir>/secret-env-dsh.log` 不再出现 `defineTool unavailable`。

## 更新

- 升级主包后重启 DSH。
- skill 是 symlink，指向已安装主包的 skill 目录，随主包升级自动指向新版本，无需重装。

## 卸载

1. `plugin_manager`：`action: remove_bundle`，`target: @foperate/secret-env`
2. 删除 skill 链接：`rm ~/.dsh/skills/secret-env`（只删链接）

## 排错

- **`add_secret` 没出现**：确认 bundle 返回 `application: applied` 且已重启；再看插件日志。
- **审批被拒**：让用户批准后重试同一操作，不要改用手工写 profile 文件绕开。
- **重复安装报错**：先 `remove_bundle` 再装。
- **不要手写** profile 的 `cordis.patch.yml`、`package.json` 或手工 symlink 到 profile `node_modules`——安装与卸载统一由 `plugin_manager` 管理。
- 本适配器依赖“插件从真实路径解析依赖”的 Node 行为：`add_secret` 的工具定义是直接交给 `ctx.tools.register` 的 JSON Schema，不要再改成 `import defineTool`（见 AGENTS.md 的解析坑）。
