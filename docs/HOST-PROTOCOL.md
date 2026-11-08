# HOST-PROTOCOL：senv / rsenv 宿主协议契约（protocol 1）

> 三端适配器（ZCode / opencode / DSH）唯一依赖面。两个 CLI 二进制（rsenv=Rust+turso+daemon、
> senv=bun/node+keepassxc/json，见 DESIGN.md）实现同一套协议，插件按协议匹配、**永远不按二进制名分支**。
> 硬契约 §1/§2/§3 逐字对齐，违反即协议不匹配（握手拒绝加载）；§4/§5 为软约定。

## 1. 协议入口（硬契约）

| 入口 | I/O | 语义 | 退出码 |
|---|---|---|---|
| `<bin> parse` | stdin JSON `{"command": "..."}` → stdout 一行 JSON | 钩子时刻：守卫 + 解析全部值 → 一次性槽位 + token | 判定 0；内部错误 2 |
| `<bin> inject <token>` | argv token → stdout `export K='v'` 行（sh_quote 包裹） | 消费槽位，一次性（rename 原子认领 / daemon 槽删除） | 成功 0；已消费/无效 2 |
| `<bin> info` | 无 stdin → stdout 一行 JSON | 守卫快照 + 版本握手（daemon 不在时仍可用，entries 空、guard_paths 照给） | 0 |

parse 响应形态（两端逐字一致）：

```json
{"ok": true,  "action": "pass"}
{"ok": true,  "action": "reject", "reason": "…"}
{"ok": true,  "action": "inject", "token": "<32hex>", "names": ["GH_TOKEN"]}
{"ok": false, "error": "…"}          // 内部错误（解析失败等），exit 2
```

判定顺序（两端一致）：文件提及守卫（先于一切，静态保护不依赖解锁态）→ 锁态（rsenv 有；senv 无此层）→
引用扫描（无引用=pass）→ 单引号拒 → 倾泻黑名单拒 → 解析全部值（失败当场拒，附可用清单）→ 签发 token。

info 响应形态：

```json
{
  "protocol": 1,
  "version": "<CLI 版本>",
  "backend": "rsenv" | "senv",
  "capabilities": {"daemon": true|false, "providers": [...]},
  "guard_paths": ["..."],              // 蛇形；三端守卫快照消费此字段
  "entries": [{"name": "...", "desc": "..."}]
}
```

版本握手：适配器启动时调 info，`protocol !== 1` → 抛错拒绝加载（宁可失败不静默）。

## 2. 注入链模板（硬契约）

parse 回 `inject` 后，**适配器**（非 CLI）把原命令改写为：

```
_senv_inj="$(<bin> inject <token>)" && eval "$_senv_inj" && { 原命令; }
```

- 变量名统一 `_senv_inj`（两端一致；历史上 rsenv 侧曾用 `_rse_inj`，2026-11-08 统一）。
- `<bin>` 由适配器代入解析出的二进制路径。
- `&&` 链保 fail-closed：token 已消费/失效 → inject 报错 → 原命令不执行。
- **不要手工拼这条链**（SKILL 纪律）：CLI inject 的 stdout 未被 eval 捕获属误用，parse 侧守卫会拒绝命令文本含裸 inject 调用。

## 3. 二进制解析链（硬契约）

三端适配器同一算法：

```
SENV_BIN 环境变量（显式指定）
  > secrets.json 的 "$backend" 键（"rsenv" → rsenv 优先；其余值视为未配置）
  > 默认 senv：PATH 上的 secret-env > PATH 上的 rsenv
```

- 解析点收敛于各适配器一处（ZCode 壳头部 / opencode index.ts 头部 / DSH client.mjs `resolveBin()`）。
- 未配置 = 缺省 senv（secret-env 优先）；配置 `"rsenv"` 则 rsenv 优先、secret-env 兜底。
- 双双不在 PATH：按各端口径报错/降级，不静默放行（ZCode=守卫降级+透传见 FALLBACK_FRAGMENTS；DSH/opencode=抛错）。

## 4. 槽位实现（软约定——语义必须一致，两端同为 daemon 内存）

- 语义：token→值 映射只存在于 CLI 自身 daemon 内存；插件与 shell 只经手 token（零价值句柄），值全程不落盘。
  一次性消费、fail-closed、暴露窗口有上界（10s TTL 清扫；daemon 崩 = 未消费 token 丢失 = inject 短路，即要的语义）。
- rsenv daemon：加密库守护 + login 生命周期。端点与托管按平台分流（2026-11-08 起 Windows 支持，真机实测挂账）：
  macOS=launchd submit + unix socket（0600，dead unlink 重 bind）；Linux=setsid detached spawn + 同 socket；
  Windows=DETACHED_PROCESS spawn + win32 named pipe `\\.\pipe\rsenv-<username>`（默认 ACL 限本用户）。
  连接级 peer 鉴权三平台同语义：内核实查 peer 进程 exe 与本二进制比对（macOS LOCAL_PEERPID+proc_pidpath /
  Linux SO_PEERCRED+/proc/exe / Windows GetNamedPipeClientProcessId+QueryFullProcessImageName），非本二进制一律 rejected。
- senv daemon（2026-11-08）：**纯 token 内存 map，与加密数据无关**——parse 按需拉起（detached）、有端点直接用、
  崩后下次重拉、不保活不管退出。端点分流：unix socket `~/.config/secret-env/senv.sock`（0600，死 socket 探测后
  unlink 重 bind）/ win32 named pipe `\\.\pipe\secret-env-tokens`（ACL 限本用户）。
  协议：`{op:"ping"|"put"|"redeem"}` 单行 JSON；put→`{ok,token}`，redeem 取即删→`{ok,env}`。

## 5. 人类命令面（软约定——允许不对称，SKILL 按 backend 分轨）

| 能力 | rsenv | senv |
|---|---|---|
| 入库 | `set NAME`（值 stdin；`--uri` 引用） | `set NAME`（值 stdin/TTY 隐藏输入；`--provider`/`--uri`） |
| 取值（终端） | `get NAME` | （无 get；用户经 provider 工具自查） |
| 清单 | `list` | `list` |
| 删除 | `remove NAME` | `remove NAME` |
| 生命周期 | `init`/`login`/`logout`/`passwd`（daemon） | 无 daemon；`passwd` 挂账 |
| 迁移 | `import-secrets` | `set NAME --uri` |

适配器与 SKILL 需要区分后端行为时读 `info.backend`/`info.capabilities`，不探测二进制名。
新增第三种后端 = 实现本协议 + info 声明 backend，插件零改动。
