# rsenv Windows named pipe 支持（daemon 层全平台可移植）

## Context
rsenv daemon 目前传输层 = `tokio UnixListener/UnixStream`（`rust/rsenv/src/main.rs`），peer 鉴权只有 macOS/Linux 两套实现，Windows 连编译都过不了。目标：daemon 传输/鉴权/生命周期层全平台可移植，Windows 走 named pipe（`\\.\pipe\rsenv-<username>`）+ pid→exe 路径比对鉴权；已拍板：全平台 daemon 层支持、pid+exe 比对鉴权、验证口径 = `cargo check --target x86_64-pc-windows-*` 类型级通过 + unix e2e 不回归，真机实测挂账。

## 改动文件
- `rust/rsenv/src/main.rs`（主体）
- `rust/rsenv/Cargo.toml`（依赖平台门控）
- `docs/HOST-PROTOCOL.md`（socket/0600 表述补 Windows 端点一行）
- `rust/rsenv/SKILL.md`（平台说明一行，可选）

## 实现要点（全部在 main.rs，保持单文件风格）

### 1. 连接类型统一
- 按平台定义 type alias：`#[cfg(unix)] type Conn = UnixStream;` / `#[cfg(windows)] type Conn = tokio::net::windows::named_pipe::NamedPipeClient;`
- `client_call`（L771）：`UnixStream::connect` → `daemon_connect()` 小函数按平台返回 `Conn`；读写改用 `tokio::io::split` + 泛型（`write_reply` L230 签名改 `impl AsyncWrite + Unpin`，读侧 BufReader 本就泛型）。
- `handle_conn`（L198）参数改 `Conn`；unix 分支鉴权仍取 `as_raw_fd`（cfg 门内）。

### 2. Windows 鉴权（新 cfg(windows) 分支，L65 处的「恒 false」分支替换）
- `windows-sys` 查 `GetNamedPipeClientProcessId(handle, &pid)`（features: Win32_Foundation / Win32_System_Pipes / Win32_System_Threading）。
- pid → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `QueryFullProcessImageNameW` 取 peer exe → canonicalize 与 `current_exe()` 比较。失败任何一步 = false（与 unix 口径一致，宁可拒绝）。

### 3. 管道名与 serve 循环
- `pipe_name()`：`format!(r"\\.\pipe\rsenv-{}", username)`（username 取 `USER` 或 `USERNAME`，取不到则报错——宁可失败）。
- serve（L982）：unix 分支维持现状（remove_file 陈旧 socket + chmod 0600）；windows 分支无陈旧文件清理（管道随进程退出自动消失），`ServerOptions::new().first_pipe_instance(true).create(pipe_name)` 建首个实例，accept 循环 = connect().await → 处理完（tokio::spawn）→ 立即 create 下一实例。
- `load_or_create_salt`/`audit` 的 PermissionsExt（L84/L179）cfg(unix) 门控；`which_tool`（L765）windows 分支退化为 `p.is_file()`。

### 4. daemon 生命周期三分支
- 现有 `#[cfg(not(target_os = "macos"))]`（setsid，L689）拆成 `#[cfg(all(unix, not(target_os = "macos")))]` 与 `#[cfg(windows)]`。
- Windows 分支：探活（`daemon_connect()`）→ `Command::new(exe).arg("serve")…` + `std::os::windows::process::CommandExt::creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)` → 轮询管道 100×50ms（复用现有节奏）。
- logout 的 `launchctl remove`（L1332）cfg(macos) 门控（现在无条件跑，Windows 下会起不存在的命令）。
- passwd 探活/轮询（L1354-1363）与 login 幂等探活（L1066）统一改走 `daemon_connect()`。

### 5. 平台差异杂项
- `dir()`（L18）：`HOME` 取不到回落 `USERPROFILE`。
- serve `--node-dir` PATH 拼接分隔符 `:`（L998）与默认 PATH 兜底 `/usr/bin:/bin`（L997）→ 按 `cfg!(windows)` 取 `;` 与系统默认。
- `client_call_or_no_daemon`（L789）错误映射：改按 `std::io::ErrorKind`（NotFound / ConnectionRefused）+ windows 下 raw os error 2 判断「daemon 不在」，措辞不变。

### 6. Cargo.toml
- `libc` 改 `[target.'cfg(unix)'.dependencies]`；新增 `[target.'cfg(windows)'.dependencies] windows-sys`（只开必需 features）。

### 7. 文档
- main.rs 文件头注释（L1-2）：传输层表述补「windows=named pipe」。
- `docs/HOST-PROTOCOL.md` senv 段已有双端点表述（L74-77），rsenv 段补一行 Windows 端点与鉴权口径对齐。
- SKILL.md daemon 段平台一行说明（`daemon.sock` 名字仅 unix；windows 为管道，文件守卫语义不变）。

## 不做
- e2e.sh 不加 Windows 分支（bash+launchctl+AF_UNIX 攻击者测试本就 unix 专属）；provider unix 工具链（security/bw/ov）不动。
- daemon 生命周期 Windows 无 launchd 等价托管，第一版用 detached spawn（宿主连坐风险挂账真机观察）。

## 验证
1. `rustup target list --installed` 确认/添加 x86_64-pc-windows-msvc（MSVC 目标只 check 不 link，无需 VS；若受阻改用 gnu target）。
2. `cargo check --target x86_64-pc-windows-msvc`（类型级通过）+ `cargo check`（unix 不回归）。
3. unix 回归：`bash rust/rsenv/e2e.sh`（memory 教训：BIN=target/debug 须 debug+release 双跑，e2e 前先 `cargo build --release`，跑完 `logout` 收尾清 daemon）。
4. 真机 Windows 实测：挂账记录（记入项目 memory + AGENTS 挂账节如适用）。
