# zcode-plugin-secret-env

**面向 AI 编码 agent 的本机凭据管理工具**：密钥从私有库直达 Bash 子进程环境，模型上下文只见占位符/变量名，永不见值。

> **致 npm 审核员 / 安全扫描器**：这是一个与 doppler / bitwarden-cli / 1password-cli 同品类的开源开发者工具。它管理的是用户自己机器上的自有凭据：调用本机密钥库 CLI（macOS 钥匙串的 `security`、`bw`、`op`、`ov`），将解析出的值经 0600 临时文件注入子进程环境。不外发任何数据、无网络监听，所有外部调用均指向用户自行配置的密钥库后端。实现核心 `core.mjs`（约 400 行）完全可读。

简体中文 | [English](./README.md)

## ⚠️ 版本安全声明

**截至 0.1.x 的所有版本不建议使用。** 这些版本的设计把凭据映射（以及配置 vault 时的 master 口令）存在**明文 JSON 文件**（`~/.config/secret-env/secrets.json`，0600）。防线只覆盖 *agent 上下文*——值不入模型、不入命令文本、不入审计日志——**不覆盖磁盘**：任何能读到映射文件的人即获得全部已配置 token。

**自 0.2.0 起，本工具改用 KeePassXC 兼容的加密 `.kdbx` 库**作为密钥存储。它**不使用系统 keychain、不触及系统保护的安全密钥**（OS 钥匙串条目、登录/支付类凭据完全在本工具范围之外）。映射与高价值凭据整体存于 AES 加密库；secrets.json 中只配置库路径与 master 口令。

## 缘起

OpenViking 的 privacy 区域是密钥的理想存放地，但通过 `{{ov_privacy:...}}` 占位符消费密钥时，MCP 侧（`privacy_resolve`）解析出明文后**必然回流到模型上下文与会话记录**——存储端做得再严，消费端这一步就把值泄给了模型。本项目就是为了堵上这个缺口：密钥从 privacy 区域直达 Bash 子进程环境，解析链路完全绕开模型上下文。

## 机制

PreToolUse(Bash) 钩子扫描命令文本中的**显式引用**（`{{secret:NAME}}` 占位符或已配置的周知 `$VAR`），经 provider 解出真值写入 0600 临时 env 文件（按命令中实际引用的名字 export，即周知原名），命令仅加 source 前缀后放行：`. <envfile>; <原命令>`。命令文本零改写；隐式读环境变量的场景由 skill 引导 agent 显式化引用来触发。文本与值分离——审计日志只见 env 文件路径。

- **provider**：`keychain://`（macOS 钥匙串）/ `viking://`（OpenViking privacy 层，`ov privacy resolve`）/ `bitwarden://`（Bitwarden CLI）/ `onepassword://`（1Password CLI）
- **dump 黑名单**：命令同时含密钥引用与倾泻意图（`env` / `printenv` / 裸 `set` / 裸 `export`）才拒绝
- **单引号禁忌**：引用落在单引号内不会被展开 → 整条命令拒绝（宁可失败，不做魔法）
- **显式化约定**：钩子是纯文本扫描的机械层；工具隐式消费环境变量（如裸 `gh pr list` 读 `' + 'GH_TOKEN' + '`）由模型按 skill 引导显式写成 `' + 'GH_TOKEN' + '=$' + 'GH_TOKEN' + ' gh pr list`

## 与其它 agent harness 协作

凡凭据走环境变量的工具，**零集成代码**即可接入——命令里显式写周知变量名，钩子即注入：

```bash
DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY pi        # pi coding agent（读 DeepSeek 密钥）
OPENAI_API_KEY=$OPENAI_API_KEY my-cli        # 同一句式适用于一切环境变量凭据的工具
```

由此形成两级集成光谱：

| 梯队 | 机制 | 成本 | 覆盖 |
|---|---|---|---|
| 环境变量注入 | 命令中显式 `$`VAR` 引用 → 钩子注入子进程环境 | 零代码 | 一切「凭据走环境变量」的 harness（生态惯例） |
| 拦截点适配器 | 按宿主改写工具调用（ZCode PreToolUse 钩子 / opencode 插件 / DSH cordis 包装器） | 每宿主一次适配 | harness 自己作为 agent 跑 Bash、其命令需要注入的场景 |

两级可组合：ZCode 内的 agent 以子进程调用另一 harness（凭据同样经钩子注入），在 harness 之间流转而全程不入模型上下文。完全没有适配器的宿主，也可以在 agent 的 Bash 里走 `srun`（见下节）兜底。

## srun — agent 宿主之外的注入通道

以上都发生在 agent 宿主之内。宿主之外——裸终端、临时命令、脚本、cron、launchd/systemd 服务——注入通道是 `srun` 命令。它读同一份配置，经同样的 provider 解析具名条目，带着它们 exec 目标命令：stdio 继承、退出码透传，值不出现在任何地方——不在命令行上、不在 rc 文件里、不在 shell 历史里。

```bash
srun GH_TOKEN -- gh pr list              # 解析单条并执行
srun GH_TOKEN BW_SESSION -- ./deploy.sh  # 一次注入多条
srun DEEPSEEK_API_KEY -- pi              # 带着密钥环境启动一个 agent 宿主
srun --all -- ./legacy-tool.sh           # 注入全部已配置条目（供确实需要全量的场景）
```

具名形式是默认也是推荐用法。常驻服务可用它作启动入口（如 systemd `ExecStart=/usr/local/bin/srun BW_SESSION -- my-service`），服务定义文件里同样不落明文。


## 安装

本项目是 npm 包 + 各宿主薄壳。全局命令（真身）：

```bash
bun link   # 仓库内执行，注册 secret-env 与 senv 双命令名（同一 CLI，短别名）（或 npm i -g .）
npm i -g @foperate/secret-env   # 或安装已发布的 npm 包
```

ZCode 壳：Plugin Marketplace → Add Marketplace 粘贴本仓库根 → Install **secret-env**（hooks.json 指向全局命令）。

opencode 壳：把适配器复制进插件目录（V2 API，`tool.execute.before` 改写 `output.args.command` 加同一 source 前缀）：

```bash
cp adapters/opencode.ts ~/.config/opencode/plugins/secret-env.ts   # 或项目级 .opencode/plugins/
```

DSH（DeepSeek Harness）壳：symlink cordis 插件包 + 在 profile 用户补丁层插一行（`tools/execute` waterfall 改写 `exec.arguments.command`，经探针真机验证，见 docs）：

```bash
mkdir -p ~/.dsh/profiles/node_modules/@local
ln -sfn "$PWD/adapters/dsh/secret-env" ~/.dsh/profiles/node_modules/@local/secret-env
# 然后在 ~/.dsh/profiles/<profile>/cordis.patch.yml 加：
# - insert:
#     - id: secret-env
#       name: '@local/secret-env'
#       config: {}
# 重启 DSH 加载新模块
```

凭据入库（用户终端执行，隐藏输入，值不经对话）：

```bash
secret-env add GH_TOKEN --provider keychain --desc 'GitHub 令牌' --alias GITHUB_TOKEN
secret-env list
```

## 配置

`~/.config/secret-env/secrets.json`（700 目录 / 600 文件；`secret-env add` 自动维护，也可手写）：

```json
{
  "GH_TOKEN": { "uri": "viking://credential/github-token/token" },
  "OPENAI_API_KEY": { "uri": "keychain://zcode-openai", "aliases": ["OPENAI_KEY"] }
}
```

模板见 [secret-env/secrets.example.json](./secret-env/secrets.example.json)。配置为空时钩子纯旁路。

## 已知边界（诚实声明）

- **出口无脱敏**：ZCode PostToolUse 输出无 tool_result 改写能力（harness 源码核查定案），`echo $GH_TOKEN` 这类值回流无自动防线，靠 skill 明令禁止
- **依赖 skill 引导质量**：模型没写显式引用时注入不生效——设计如此，宁可失败
- viking:// provider 依赖 `ov` CLI（≥0.5.1）与本地 OpenViking 服务

设计沿革与机制验证记录见 [docs/DESIGN.md](./docs/DESIGN.md)。

## 反馈

对本项目设计或实现方案有建议，欢迎提 [GitHub issue](https://github.com/whitemay/zcode-plugin-secret-env/issues)（Gitee 用户也可用 [Gitee issues](https://gitee.com/whitemay/zcode-plugin-secret-env/issues)，两边不互通）。
