//! rsenv 原型：turso 加密库 + daemon（unix socket newline-JSON）+ login/get/set/lock/status。
//! 原型边界：鉴权=连接级 peer-exe 实查（macOS LOCAL_PEERPID+proc_pidpath / Linux SO_PEERCRED+/proc/exe）+ socket 0600；inject=注入原语（env 生命周期=进程外产物，返回 JSON 由消费者负责）；run=用户态执行器（env 生命周期=子进程一次性物，退出即消失，退出码透传）
//! 并存口径：库/运行文件独立于 JS 版（vault.db，不动 vault.kdbx/secrets.json）。

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use turso::EncryptionOpts;

// ---------- 路径约定（SENV_VAULT_DIR 仅测试重定向） ----------

fn dir() -> std::path::PathBuf {
    match std::env::var("SENV_VAULT_DIR") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => {
            let mut p = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap();
            p.push(".config/secret-env");
            p
        }
    }
}

fn vault_path() -> std::path::PathBuf { dir().join("vault.db") }
fn socket_path() -> std::path::PathBuf { dir().join("daemon.sock") }
fn salt_path() -> std::path::PathBuf { dir().join(".vault.salt") }

/// 连接级鉴权：peer 进程的真身（内核实查，不可谎报）是否为本二进制。
/// macOS: LOCAL_PEERPID 拿 peer pid → proc_pidpath；Linux: SO_PEERCRED → /proc/<pid>/exe。
fn peer_exes_self(fd: std::os::fd::RawFd) -> bool {
    fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }
    #[cfg(target_os = "macos")]
    unsafe {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        if libc::getsockopt(fd, 0, libc::LOCAL_PEERPID, &mut pid as *mut _ as *mut libc::c_void, &mut len) != 0 {
            return false;
        }
        if pid <= 0 { return false; }
        let mut buf = [0i8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32);
        if n <= 0 { return false; }
        let cstr = std::ffi::CStr::from_ptr(buf.as_ptr());
        let Ok(me) = std::env::current_exe() else { return false };
        same_file(std::path::Path::new(cstr.to_str().unwrap_or("")), &me)
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) != 0 {
            return false;
        }
        if cred.pid <= 0 { return false; }
        let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", cred.pid)) else { return false };
        let Ok(me) = std::env::current_exe() else { return false };
        same_file(&exe, &me)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        false
    }
}

// ---------- KDF ----------

/// 读或创建随机 salt（hex，16 字节），0600
fn load_or_create_salt() -> Result<String, Box<dyn std::error::Error>> {
    let p = salt_path();
    if p.exists() {
        Ok(std::fs::read_to_string(&p)?.trim().to_string())
    } else {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::fs::write(&p, &s)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        Ok(s)
    }
}

fn derive_key(password: &str, salt_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(salt_hex.as_bytes()).map_err(|e| e.to_string())?;
    let params = Params::new(19456, 2, 1, None).map_err(|e| e.to_string())?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let out = a2.hash_password(password.as_bytes(), &salt).map_err(|e| e.to_string())?;
    Ok(out.hash.unwrap().as_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

/// stdio MCP server（newline-JSON JSON-RPC 2.0；管理面工具：list / status）
async fn mcp_serve() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let req: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let reply = match method {
            "initialize" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": req.pointer("/params/protocolVersion").cloned().unwrap_or(json!("2024-11-05")),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "rsenv", "version": env!("CARGO_PKG_VERSION")},
                }
            }),
            "notifications/initialized" | "notifications/cancelled" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"tools": [
                    {
                        "name": "rsenv_list",
                        "description": "列出 rsenv 已配置的密钥条目（名字与描述；值永不出现在此通道）",
                        "inputSchema": {"type": "object", "properties": {}}
                    },
                    {
                        "name": "rsenv_status",
                        "description": "查看密钥库解锁状态（locked 时提示用户在其终端 rsenv login）",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]}
            }),
            "tools/call" => {
                let name = req.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
                let result = match name {
                    "rsenv_list" => match client_call(&json!({"op": "list"})).await {
                        Ok(r) if r.get("ok").and_then(Value::as_bool).unwrap_or(false) => {
                            let entries = r.get("entries").cloned().unwrap_or(json!([]));
                            json!({"content": [{"type": "text", "text": serde_json::to_string(&entries)?}]})
                        }
                        Ok(r) => json!({"isError": true, "content": [{"type": "text", "text": r.get("error").and_then(Value::as_str).unwrap_or("vault is locked: ask the user to run `rsenv login` in their terminal").to_string()}]}),
                        Err(e) => json!({"isError": true, "content": [{"type": "text", "text": format!("rsenv daemon unreachable: {e} — ask the user to run `rsenv login` in their terminal")}]})
                    },
                    "rsenv_status" => match client_call(&json!({"op": "status"})).await {
                        Ok(r) => json!({"content": [{"type": "text", "text": serde_json::to_string(&r)?}]}),
                        Err(e) => json!({"isError": true, "content": [{"type": "text", "text": format!("rsenv daemon unreachable: {e} — ask the user to run `rsenv login` in their terminal")}]})
                    },
                    other => json!({"isError": true, "content": [{"type": "text", "text": format!("unknown tool: {other}")}]})
                };
                json!({"jsonrpc": "2.0", "id": id, "result": result})
            }
            "" => continue,
            other => json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": format!("method not found: {other}")}
            }),
        };
        println!("{}", serde_json::to_string(&reply)?);
    }
    Ok(())
}

// ---------- 审计（audit.jsonl，0600；只记事件与名字，永不记值） ----------

fn audit(event: &str, fields: &[(&str, String)]) {
    use std::io::Write;
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut obj = serde_json::Map::new();
    obj.insert("ts".into(), json!(ts));
    obj.insert("event".into(), json!(event));
    for (k, v) in fields {
        obj.insert((*k).into(), json!(v));
    }
    let line = json!(obj).to_string();
    let p = dir().join("audit.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.write_all(line.as_bytes()).and_then(|_| f.write_all(b"\n"));
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
}

// ---------- socket 协议（newline-JSON） ----------

#[derive(Clone)]
struct DaemonState {
    key: Option<String>,
    cipher: String,
    /// parse 签发的一次性注入槽位：token → (env_map, 签发时刻)。语义=消费一次（redeem 即删，无过期概念）；
    /// 10s 惰性 GC 只回收未消费残留（命令被取消等场景），等效 TTL 的作用但非访问控制；
    /// 仅存内存——daemon 退出即消失，值活不过会话由结构保证（不走 turso 表：秒级临时物不进持久层）
    slots: std::collections::HashMap<String, (serde_json::Map<String, Value>, i64)>,
}


async fn handle_conn(
    stream: UnixStream,
    state: std::sync::Arc<tokio::sync::RwLock<DaemonState>>,
) {
    // 连接级鉴权：只认本二进制发起的连接（内核实查 peer exe，不可谎报、不可转移）
    use std::os::fd::AsRawFd;
    if !peer_exes_self(stream.as_raw_fd()) {
        audit("peer-rejected", &[]);
        let (_, mut writer) = stream.into_split();
        let _ = write_reply(&mut writer, &json!({"ok": false, "error": "rejected: caller is not rsenv"})).await;
        return;
    }
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => { let _ = write_reply(&mut writer, &json!({"ok":false,"error":format!("bad json: {e}")})).await; break; }
        };
        let reply = handle_op(req, &state).await;
        let done = matches!(reply.get("op"), Some(Value::String(o)) if o == "close");
        let quit = reply.get("_quit").is_some();
        let _ = write_reply(&mut writer, &reply).await;
        if done || quit { break; }
        if reply.get("_shutdown").is_some() {
            // logout：daemon 结束会话退场（reply 已送达）
            let _ = std::fs::remove_file(socket_path());
            std::process::exit(0);
        }
    }
}

async fn write_reply(w: &mut tokio::net::unix::OwnedWriteHalf, v: &Value) -> std::io::Result<()> {
    w.write_all(format!("{v}\n").as_bytes()).await?;
    w.flush().await
}

async fn handle_op(
    req: Value,
    state: &std::sync::Arc<tokio::sync::RwLock<DaemonState>>,
) -> Value {
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    // 鉴权已在连接级完成（peer exe 实查），协议层无 token
    match op {
        "status" => {
            let s = state.read().await;
            json!({"ok": true, "unlocked": s.key.is_some(), "cipher": s.cipher})
        }
        "unlock" => {
            // launchd 托管形态的解锁门：口令验证责任在 CLI（login/init/passwd 已开库验过），
            // daemon 只收 key——daemon 侧再开库验证会撞 CLI 句柄的文件锁（turso 后台 checkpoint
            // 存活期）；错误 key 由后续 per-op open 自然 fail-closed。连接有 peer-exe 门。
            let key = req.get("key").and_then(Value::as_str).unwrap_or("").to_string();
            if key.is_empty() { return json!({"ok": false, "error": "key required"}); }
            state.write().await.key = Some(key);
            audit("unlock", &[]);
            json!({"ok": true})
        }
        "login" => {
            audit("login-op", &[]);
            let password = req.get("password").and_then(Value::as_str).unwrap_or("");
            if password.is_empty() {
                return json!({"ok": false, "error": "password required"});
            }
            let salt = match load_or_create_salt() { Ok(s) => s, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let key = match derive_key(password, &salt) { Ok(k) => k, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            // open 即口令验证：错口令在这里被拒（宁可失败）
            let cipher = state.read().await.cipher.clone();
            let db = match turso::Builder::new_local(vault_path().to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher: cipher.clone(), hexkey: key.clone() })
                .build().await {
                Ok(db) => db,
                Err(e) => return json!({"ok": false, "error": format!("wrong password: {e}")}),
            };
            let conn = match db.connect() { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            if let Err(e) = conn.execute("CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, name TEXT UNIQUE, desc TEXT, fields_json TEXT, created_at INTEGER, updated_at INTEGER)", ()).await {
                return json!({"ok": false, "error": format!("init: {e}")});
            }
            state.write().await.key = Some(key);
            json!({"ok": true, "_quit": true})
        }
        "get" => {
            let name = req.get("name").and_then(Value::as_str).unwrap_or("");
            audit("get", &[("name", name.to_string())]);
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            match resolve_entry(&conn, state, &name, 0).await {
                Ok(v) => json!({"ok": true, "value": v}),
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        "set" => {
            // 元数据入库：native 值（password）或 provider URI 引用，二选一；desc 可选。
            // 两者同给 = 配置歧义，拒绝（宁可失败）。
            let name = req.get("name").and_then(Value::as_str).unwrap_or("");
            audit("set", &[("name", name.to_string())]);
            let value = req.get("value").and_then(Value::as_str).unwrap_or("");
            let uri = req.get("uri").and_then(Value::as_str).unwrap_or("");
            let desc = req.get("desc").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() { return json!({"ok": false, "error": "missing name"}); }
            if !value.is_empty() && !uri.is_empty() {
                return json!({"ok": false, "error": "value and uri are mutually exclusive (one entry is either a native secret or a provider reference)"});
            }
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let fields = if !uri.is_empty() {
                json!({"uri": uri}).to_string()
            } else {
                json!({"password": value}).to_string()
            };
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            match conn.execute(
                "INSERT INTO entries (name, desc, fields_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4) \
                 ON CONFLICT(name) DO UPDATE SET desc = excluded.desc, fields_json = excluded.fields_json, updated_at = excluded.updated_at",
                [name, desc, &fields, &now.to_string()]).await {
                Ok(_) => json!({"ok": true}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "remove" => {
            let name = req.get("name").and_then(Value::as_str).unwrap_or("");
            audit("remove", &[("name", name.to_string())]);
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            match conn.execute("DELETE FROM entries WHERE name = ?1", [name]).await {
                Ok(n) if n > 0 => json!({"ok": true}),
                Ok(_) => json!({"ok": false, "error": format!("not configured: {name}")}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "inject" => {
            // 解析注入：daemon 取值回 client（peer-exe 门内），client 本地 spawn；值不落盘不打印
            let names: Vec<String> = req.get("names").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).map(String::from).collect()
            }).unwrap_or_default();
            if names.is_empty() { return json!({"ok": false, "error": "no names"}); }
            audit("inject", &[("names", names.join(","))]);
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let mut env_map = serde_json::Map::new();
            let mut errors: Vec<String> = Vec::new();
            for name in &names {
                match resolve_entry(&conn, state, name, 0).await {
                    Ok(v) => { env_map.insert(name.clone(), json!(v)); }
                    Err(e) => errors.push(format!("{name}: {e}")),
                }
            }
            if !errors.is_empty() {
                // 宁可失败：明确指出是哪个名字、哪种失败（missing 与 provider 错误都如实返回）
                let mut listed = Vec::new();
                let mut rows = match conn.query("SELECT name FROM entries ORDER BY name", ()).await {
                    Ok(r) => r, Err(e) => return json!({"ok": false, "error": e.to_string()}),
                };
                while let Ok(Some(row)) = rows.next().await {
                    if let Some(n) = row.get_value(0).unwrap().as_text() { listed.push(n.clone()); }
                }
                return json!({"ok": false, "error": format!("{}; available: {}", errors.join("; "), listed.join(", "))});
            }
            json!({"ok": true, "env": Value::Object(env_map)})
        }
        "list" => {
            // 管理面清单：名字+描述+字段键，永不返回值
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let mut rows = match conn.query("SELECT name, desc, fields_json, updated_at FROM entries ORDER BY name", ()).await {
                Ok(r) => r, Err(e) => return json!({"ok": false, "error": e.to_string()}),
            };
            let mut items = Vec::new();
            while let Ok(Some(row)) = rows.next().await {
                let name = row.get_value(0).unwrap().as_text().unwrap().clone();
                let desc = row.get_value(1).unwrap().as_text().unwrap().clone();
                let fj = row.get_value(2).unwrap().as_text().unwrap().clone();
                let fields: Value = serde_json::from_str(&fj).unwrap_or(json!({}));
                let keys: Vec<String> = fields.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
                let ts = row.get_value(3).unwrap().as_integer().copied().unwrap_or(0);
                items.push(json!({"name": name, "desc": desc, "fields": keys, "updated_at": ts}));
            }
            json!({"ok": true, "entries": items})
        }
        "import" => {
            // secrets.json 迁移：URI 引用条目入库（fields_json.uri，区别于原生 password）
            let entries = req.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
            if entries.is_empty() { return json!({"ok": false, "error": "no entries"}); }
            audit("import", &[("count", entries.len().to_string())]);
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let mut imported = 0usize;
            for e in &entries {
                let name = e.get("name").and_then(Value::as_str).unwrap_or("");
                let desc = e.get("desc").and_then(Value::as_str).unwrap_or("");
                let uri = e.get("uri").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() || uri.is_empty() { continue; }
                let fields = json!({"uri": uri}).to_string();
                match conn.execute(
                    "INSERT INTO entries (name, desc, fields_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4) \
                     ON CONFLICT(name) DO UPDATE SET desc = excluded.desc, fields_json = excluded.fields_json, updated_at = excluded.updated_at",
                    [name, desc, &fields, &now.to_string()]).await {
                    Ok(_) => imported += 1,
                    Err(err) => return json!({"ok": false, "error": format!("import {name}: {err}")}),
                }
            }
            json!({"ok": true, "imported": imported})
        }
        "parse" => {
            // 宿主无关命令门（daemon 内执行）：守卫判定 + 解析全部值 → 一次性槽位 + token。
            // 值不出 daemon；provider 失败/名字缺失在钩子时刻当场拒绝（宁可失败）
            let command = req.get("command").and_then(Value::as_str).unwrap_or("");
            audit("parse", &[]);
            // 文件提及守卫先于 lock 检查：保护对象=静态文件，与解锁态无关（守卫分层原则）
            if let Some(hit) = guard_fragments().iter().find(|f| command.contains(f.as_str())) {
                return json!({"ok": true, "action": "reject", "reason": format!("command touches protected files (fragment \"{hit}\") — vault/audit files are forbidden to the agent; maintain config in your own terminal")});
            }
            if state.read().await.key.is_none() { return json!({"ok": false, "error": "vault locked: ask the user to run `rsenv login` in their terminal"}); }
            let conn = match open_conn(state).await { Ok(c) => c, Err(e) => return json!({"ok": false, "error": e.to_string()}) };
            let configured: Vec<String> = {
                let mut rows = match conn.query("SELECT name FROM entries ORDER BY name", ()).await {
                    Ok(r) => r, Err(e) => return json!({"ok": false, "error": e.to_string()}),
                };
                let mut v = Vec::new();
                while let Ok(Some(row)) = rows.next().await {
                    if let Some(n) = row.get_value(0).unwrap().as_text() { v.push(n.clone()); }
                }
                v
            };
            if refs_in_single_quotes(command, &configured) {
                return json!({"ok": true, "action": "reject", "reason": "secret reference inside single quotes (integrity unguaranteed): use double quotes"});
            }
            let refs = scan_refs(command, &configured);
            if refs.is_empty() {
                return json!({"ok": true, "action": "pass"});
            }
            let ref_names: Vec<String> = refs.iter().map(|(n, _, _)| n.clone()).collect();
            if has_dump_intent(command, &ref_names) {
                return json!({"ok": true, "action": "reject", "reason": "dump intent (env/printenv/set/export) with secret references: remove the dump intent"});
            }
            // 解析全部值（provider 链在 daemon 内跑完），失败当场拒绝并附可用清单
            let mut env_map = serde_json::Map::new();
            for name in &ref_names {
                if let Err(e) = match resolve_entry(&conn, state, name, 0).await {
                    Ok(v) => { env_map.insert(name.clone(), json!(v)); Ok(()) }
                    Err(e) => Err(e),
                } {
                    let mut listed = Vec::new();
                    let mut rows = match conn.query("SELECT name FROM entries ORDER BY name", ()).await {
                        Ok(r) => r, Err(e2) => return json!({"ok": false, "error": e2.to_string()}),
                    };
                    while let Ok(Some(row)) = rows.next().await {
                        if let Some(n) = row.get_value(0).unwrap().as_text() { listed.push(n.clone()); }
                    }
                    return json!({"ok": false, "error": format!("{name}: {e}; available: {}", listed.join(", "))});
                }
            }
            // 签发一次性 token：随机 32 hex；GC 只回收 age≥10s 的未消费残留（新槽位必然存活）
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let mut s = state.write().await;
            s.slots.retain(|_, (_, t)| now - *t < 10);
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
            s.slots.insert(token.clone(), (env_map, now));
            audit("parse-inject", &[("names", ref_names.join(","))]);
            json!({"ok": true, "action": "inject", "token": token, "names": ref_names})
        }
        "redeem" => {
            // 一次性消费：token → env JSON → 槽位立即删除（无过期概念；未消费残留由 GC 回收）
            let token = req.get("token").and_then(Value::as_str).unwrap_or("");
            audit("redeem", &[]);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let mut s = state.write().await;
            s.slots.retain(|_, (_, t)| now - *t < 10); // GC：只回收未消费残留
            match s.slots.remove(token) {
                Some((env, _)) => json!({"ok": true, "env": Value::Object(env)}),
                None => json!({"ok": false, "error": "invalid or already-consumed injection token"}),
            }
        }
        "logout" => {
            audit("logout", &[]);
            let mut st = state.write().await;
            st.key = None;
            st.slots.clear(); // 待注入槽位随会话清空（值活不过会话）
            json!({"ok": true, "_shutdown": true})
        }
        other => json!({"ok": false, "error": format!("unknown op: {other}")}),
    }
}

// ---------- provider 解析层（daemon 内子进程外调；值不离开 daemon，只走注入/回包通道） ----------

/// UUID 形参判定（8-4-4-4-12）：bitwarden URI 一级为 id 时跳过精确名匹配
fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts.iter().map(|p| p.len()).eq([8usize, 4, 4, 4, 12])
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

const MAX_RESOLVE_DEPTH: usize = 4;

/// 单条目解析：native password 直取；uri 引用按 scheme 分发到 provider（递归，深度上限防环）
async fn resolve_entry(
    conn: &turso::Connection,
    state: &std::sync::Arc<tokio::sync::RwLock<DaemonState>>,
    name: &str,
    depth: usize,
) -> Result<String, String> {
    if depth >= MAX_RESOLVE_DEPTH {
        return Err(format!("resolve depth exceeded (reference cycle at {name}?)"));
    }
    let mut rows = conn
        .query("SELECT fields_json FROM entries WHERE name = ?1", [name])
        .await
        .map_err(|e| e.to_string())?;
    let row = rows
        .next()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("not configured: {name}"))?;
    let fj = row.get_value(0).map_err(|e| e.to_string())?.as_text().ok_or("bad fields_json")?.clone();
    let fields: Value = serde_json::from_str(&fj).unwrap_or(json!({}));
    if let Some(v) = fields.get("password").and_then(Value::as_str) {
        return Ok(v.to_string());
    }
    let uri = fields
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("entry {name}: no password field and no uri reference"))?;
    resolve_uri(conn, state, uri, depth + 1).await
}

/// URI 引用解析：scheme 分发；外部 provider 在 daemon 进程内子进程外调，宁可失败。
/// 递归 async（bitwarden 链回 BW_SESSION 条目）需 Box::pin 消除无限 future
fn resolve_uri<'a>(
    conn: &'a turso::Connection,
    state: &'a std::sync::Arc<tokio::sync::RwLock<DaemonState>>,
    uri: &'a str,
    depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>> {
    Box::pin(resolve_uri_inner(conn, state, uri, depth))
}

async fn resolve_uri_inner(
    conn: &turso::Connection,
    state: &std::sync::Arc<tokio::sync::RwLock<DaemonState>>,
    uri: &str,
    depth: usize,
) -> Result<String, String> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| format!("bad uri (missing scheme): {uri}"))?;
    match scheme {
        // viking://<category>/<target>[/<field>] → ov privacy resolve 分段传参
        //（与 JS 版同构；整串一个 arg 会被 ov 判 selector 非法）
        "viking" => {
            let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() < 2 {
                return Err(format!("viking:// URI needs <category>/<target>[/<field>]: {uri}"));
            }
            let mut argv = vec!["privacy", "resolve"];
            argv.extend(parts);
            let out = run_tool("ov", &argv)?;
            parse_ov_value_line(&out).ok_or_else(|| {
                format!("ov resolve: no value line in output (uri: {uri})")
            })
        }
        // bitwarden://<item>[/field]，field 默认 password；session 先解析库内 BW_SESSION 条目。
        // 精确寻址（约定：URI 的一级是条目名或 id，不是搜索关键字）：UUID 直用；
        // 名字则精确匹配（bw get 对非 id 参数是搜索语义，同名多条会串条目）——
        // 全量取回后按 name 严格相等过滤，0 条/多条都拒绝，多条附 id 清单供消歧。
        "bitwarden" => {
            let (item, field) = match rest.split_once('/') {
                Some((i, f)) => (i, f),
                None => (rest, "password"),
            };
            let session = match resolve_entry(conn, state, "BW_SESSION", depth).await {
                Ok(s) => s,
                Err(_) => std::env::var("BW_SESSION").map_err(|_| {
                    "bw: no session (BW_SESSION entry not configured and daemon env empty)".to_string()
                })?,
            };
            let bw_env = [("BW_SESSION", session.as_str())];
            let item_id = if is_uuid(item) {
                item.to_string()
            } else {
                let out = run_tool_env("bw", &["list", "items", "--search", item], &bw_env)?;
                let v: Value = serde_json::from_str(out.trim())
                    .map_err(|_| "bw list items: unexpected output".to_string())?;
                let matches: Vec<&Value> = v
                    .as_array()
                    .map(|a| a.iter().filter(|e| e.get("name").and_then(Value::as_str) == Some(item)).collect())
                    .unwrap_or_default();
                match matches.len() {
                    0 => return Err(format!("bw: no item named exactly \"{item}\" (search is not addressing; check the name or use the item id)")),
                    1 => matches[0].get("id").and_then(Value::as_str).ok_or("bw item missing id")?.to_string(),
                    n => {
                        let ids: Vec<&str> = matches.iter().filter_map(|e| e.get("id").and_then(Value::as_str)).collect();
                        return Err(format!("bw: {n} items named \"{item}\" — ambiguous, disambiguate by id in the uri: {ids:?}"));
                    }
                }
            };
            let out = run_tool_env("bw", &["get", field, &item_id], &bw_env)?;
            Ok(out)
        }
        // onepassword://<item>[/<field>]，field 默认 password；totp 显式拒绝（op TOTP 寻址待真机验证）
        // session=OP_SESSION 条目（禁指 onepassword:// 自锁死循环，深度上限兜底）。
        // 挂账（与 JS 版同等妥协）：--session 走 argv 有进程表暴露面——op 的 session env 变量名带账号
        // shorthand（OP_SESSION_<xxx>），无法静态确定；真机探测出 shorthand 后改 env 注入。
        // 无 OP_SESSION 记录时依赖 biometric / 宿主环境会话。
        "onepassword" => {
            let (item, field) = match rest.split_once('/') {
                Some((i, f)) => (i, f),
                None => (rest, "password"),
            };
            if field == "totp" {
                return Err("onepassword provider 不支持 totp 字段".into());
            }
            match resolve_entry(conn, state, "OP_SESSION", depth).await {
                Ok(sess) => run_tool("op", &["--session", &sess, "item", "get", item, "--fields", field]),
                Err(_) => run_tool("op", &["item", "get", item, "--fields", field]),
            }
        }
        other => Err(format!("unknown provider scheme: {other}://{rest}")),
    }
}

/// 同步子进程外调（继承 daemon env），宁可失败：CLI 缺失/非零退出都显式报错
fn run_tool(bin: &str, args: &[&str]) -> Result<String, String> {
    run_tool_env(bin, args, &[])
}

fn run_tool_env(bin: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<String, String> {
    // login 经 argv 下发的工具绝对路径优先（launchd 作业 PATH 残缺的根治形态）；
    // 未下发（手动 serve / e2e 假二进制走 PATH）回落裸名，行为不变
    let bin_path = std::env::var(format!("SENV_TOOL_{}", bin.to_uppercase())).unwrap_or_else(|_| bin.to_string());
    let mut cmd = std::process::Command::new(bin_path);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("{bin}: spawn failed (CLI missing?): {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!(
            "{bin} {args0} failed: {stderr}",
            args0 = args.first().unwrap_or(&"")
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// ov resolve 输出 = 9 行空格对齐元数据表，真值只在 value 行（严禁把整表当值用）
fn parse_ov_value_line(out: &str) -> Option<String> {
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("value") {
            let v = rest.trim_start();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// daemon 侧用 state 里的 key 开库连接
async fn open_conn(state: &std::sync::Arc<tokio::sync::RwLock<DaemonState>>) -> Result<turso::Connection, Box<dyn std::error::Error>> {
    let s = state.read().await;
    let key = s.key.clone().ok_or("locked")?;
    let cipher = s.cipher.clone();
    let db = turso::Builder::new_local(vault_path().to_str().unwrap())
        .experimental_encryption(true)
        .with_encryption(EncryptionOpts { cipher, hexkey: key })
        .build().await?;
    Ok(db.connect()?)
}

// ---------- 客户端 ----------

fn daemon_launchd_label() -> &'static str { "com.foperate.rsenv" }

/// 平台分流：daemon「拉起且不被宿主连坐」各接各地头蛇——
/// macOS=launchctl submit（Dock 按 GUI 应用责任进程链 SIGTERM，fork 式必死，2026-11-08 实锤）；
/// Linux/其他=setsid fork（Linux 无此连坐层，setsid 即终态）。
/// socket-unlock 解锁协议平台无关（launchctl submit 喂不了 stdin，key 统一走 socket）。
#[cfg(target_os = "macos")]
async fn ensure_daemon(exe: &std::path::Path, cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_daemon_via_launchd(exe, cipher).await
}

#[cfg(not(target_os = "macos"))]
async fn ensure_daemon(exe: &std::path::Path, _cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    if UnixStream::connect(socket_path()).await.is_ok() { return Ok(()); }
    // 真 daemon 化：只用 setsid（勿叠加 process_group(0)——setpgid 先把子进程变组长，
    // 组长调 setsid 返回 EPERM 静默失败）；失败必须报错（宁可失败）
    let child = unsafe {
        std::process::Command::new(exe)
            .arg("serve")
            .arg("--vault-dir").arg(dir())
            .arg("--cipher").arg(_cipher)
            .arg("--path").arg(std::env::var("PATH").unwrap_or_default())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .pre_exec(|| {
                if unsafe { libc::setsid() } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()?
    };
    drop(child);
    for _ in 0..100 {
        if UnixStream::connect(socket_path()).await.is_ok() { return Ok(()); }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("daemon socket not ready after spawn".into())
}

/// launchd 托管拉起 daemon（macOS 专用）：责任进程=launchd，
/// 免受 GUI 应用退出时 Dock 按责任进程链 SIGTERM 连坐（setsid 只是必要非充分）。
async fn ensure_daemon_via_launchd(exe: &std::path::Path, cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    if UnixStream::connect(socket_path()).await.is_ok() { return Ok(()); }
    // 残留作业（daemon 已退场但 label 还挂着）先清掉，submit 才不会撞名
    let _ = std::process::Command::new("launchctl").args(["remove", daemon_launchd_label()]).output();
    let mut spawn_cmd = std::process::Command::new("launchctl");
    spawn_cmd
        .args(["submit", "-l", daemon_launchd_label(), "-o", "/dev/null", "-e", "/dev/null", "--"])
        .arg(exe)
        .arg("serve")
        // launchd 作业不继承 shell env：vault 目录/cipher 走 argv（非机密，见 serve 处注释）
        .arg("--vault-dir").arg(dir())
        .arg("--cipher").arg(cipher);
        // provider 工具（ov/bw/op）绝对路径：login 进程按自身 PATH which 出来，
        // 没找到的不传（使用时宁可失败）；ps 里只见三个短路径，不再暴露整条 PATH。
        // node 解释器：ov 是 node 脚本（env node），launchd PATH 无 node 必炸——
        // which(node) 取其目录随 argv 下发（serve 侧 prepend 进 PATH）；
        // node 缺席 ⇒ 判 ov 不可用一并省略（宁可失败，使用时大声报错）
        let node_dir = which_tool("node").map(|p| p.parent().unwrap().to_path_buf());
        if node_dir.is_none() && which_tool("ov").is_some() {
            eprintln!("rsenv: node not found in PATH — ov (node script) unavailable this session; bw/op unaffected");
        }
        if let Some(d) = &node_dir {
            spawn_cmd.arg("--node-dir").arg(d);
        }
        for name in ["ov", "bw", "op"] {
            if name == "ov" && node_dir.is_none() { continue; }
            if let Some(p) = which_tool(name) {
                spawn_cmd.arg(format!("--{name}-path")).arg(p);
            }
        }
        let out = spawn_cmd.output()?;
    if !out.status.success() {
        return Err(format!("launchctl submit failed: {}", String::from_utf8_lossy(&out.stderr).trim()).into());
    }
    for _ in 0..100 {
        if UnixStream::connect(socket_path()).await.is_ok() { return Ok(()); }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("daemon socket not ready after launchctl submit".into())
}

/// 在当前进程 PATH 里找工具的绝对路径（找不到=None，调用侧不传、使用时宁可失败）
fn which_tool(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH").ok()?;
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&path).map(|d| d.join(bin)).find(|p| {
        p.is_file() && std::fs::metadata(p).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    })
}

async fn client_call(req: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let stream = UnixStream::connect(socket_path()).await?;
    let (r, mut w) = stream.into_split();
    w.write_all(format!("{req}\n").as_bytes()).await?;
    w.flush().await?;
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

/// get/set/status/lock：daemon 不在就直接报错，不自行拉起。
/// 错误信息面向 agent：区分「未 init」与「已 init 未 login」，直接给出用户可执行的恢复命令
/// （agent 看到后应指引用户在终端执行，口令不经 agent；与 SKILL.md 口径一致）
async fn client_call_or_no_daemon(req: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    client_call(req).await.map_err(|e| {
        // daemon 不在的两种形态都给 agent 可执行指引：socket 文件没建（未 init/首次）与
        // 文件在但进程死（Connection refused，如宿主退出连坐/重启后）——措辞即行动指令
        if e.to_string().contains("No such file or directory") || e.to_string().contains("Connection refused") {
            if vault_path().exists() {
                "vault is locked: ask the user to run `rsenv login` in their terminal (password never passes through the agent)".into()
            } else {
                "vault is not initialized: ask the user to run `rsenv init` in their terminal (sets vault password)".into()
            }
        } else { e }
    })
}

fn read_password_arg() -> Result<String, Box<dyn std::error::Error>> {
    // TTY → 隐藏输入；非 TTY（测试）→ 读 stdin 首行
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        Ok(rpassword::prompt_password("vault password: ")?)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim().to_string())
    }
}

fn read_value_stdin() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim_end_matches('\n').trim_end_matches('\r').to_string())
}

/// 展开 ~ 前缀（无第三方 shell 展开依赖）
fn shellexpand_home(p: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("HOME")?;
        return Ok(std::path::PathBuf::from(home).join(rest));
    }
    Ok(std::path::PathBuf::from(p))
}

/// 路径加后缀（turso 库文件组形态：vault.db / vault.db-wal / vault.db-shm）
fn with_suffix(p: &std::path::Path, s: &str) -> std::path::PathBuf {
    let mut np = p.to_path_buf().into_os_string();
    np.push(s);
    std::path::PathBuf::from(np)
}

// ---------- bash 命令守卫（CLI 侧纯函数，离线可测） ----------
// 口径（沿用 JS 版已拍板行为）：
// - 引用形态：$NAME / ${NAME}（NAME 必须在已配置清单内才命中；{{secret:X}} 挂账）
// - 单引号内引用 → 整条拒绝，不静默放行（shell 单引号内无转义，逐字符扫描区间）
// - 倾泻黑名单 = 命令含引用 且 命令位置有倾泻意图；跨调用裸 env 不拦（每次 Bash 调用全新 shell）
// - 宁可失败：守卫只在明确判定下放行/改写，判定不了就拒

/// 逐字符扫描：单引号区间 + $NAME/${NAME} token 定位（NAME ∈ configured 才算引用）
fn scan_refs(command: &str, configured: &[String]) -> Vec<(String, usize, bool)> {
    scan_refs_opts(command, configured, false)
}

/// ignore_single=true 时连单引号内的 $token 也报（供引号违规检查用）
fn scan_refs_opts(command: &str, configured: &[String], ignore_single: bool) -> Vec<(String, usize, bool)> {
    let single_ranges = {
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut in_single = false;
        let mut start = 0usize;
        for (i, c) in command.char_indices() {
            if c == '\'' {
                if in_single {
                    ranges.push((start, i));
                    in_single = false;
                } else {
                    in_single = true;
                    start = i;
                }
            }
        }
        ranges
    };
    let in_single = |idx: usize| single_ranges.iter().any(|(s, e)| idx > *s && idx < *e);
    let mut refs = Vec::new();
    let bytes = command.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'$' && (ignore_single || !in_single(i)) {
            let braced = bytes.get(i + 1) == Some(&b'{');
            let name_start = i + if braced { 2 } else { 1 };
            let mut j = name_start;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = &command[name_start..j];
            if !name.is_empty() && configured.iter().any(|c| c == name) {
                refs.push((name.to_string(), i, braced));
                i = if braced && bytes.get(j) == Some(&b'}') { j + 1 } else { j };
                continue;
            }
            i = if braced { name_start.max(j + 1) } else { j };
            continue;
        }
        i += 1;
    }
    refs
}

/// 命令位置倾泻意图：任一 && / || / ; / | 分段的第一个 token 是 env/printenv（无参数=整环境倾泻）
/// 或裸 set/export。近似判定——宁可失败口径下只拦「明确倾泻形态」，不猜语义
fn has_dump_intent(command: &str, ref_names: &[String]) -> bool {
    for seg in command.split(|c| c == ';' || c == '|' || c == '&' || c == '\n') {
        let seg = seg.trim();
        if seg.is_empty() { continue; }
        let mut toks = seg.split_whitespace();
        let first = match toks.next() {
            Some(t) => t,
            None => continue,
        };
        let rest = toks.count(); // 首个 token 之后的参数个数
        let seg_ref = !ref_names.is_empty()
            && seg.split_whitespace().any(|t| ref_names.iter().any(|r| t.contains(r)));
        match first {
            // printenv/set/export 命令位置即意图（带引用参数 = 单点窃取，更该拦）
            "printenv" | "set" | "export" => {
                if rest == 0 || seg_ref { return true; }
            }
            // env 无参数=整环境倾泻；带参数 VAR=x cmd 形态不拦
            "env" => {
                if rest == 0 { return true; }
            }
            _ => {}
        }
    }
    false
}

/// 单引号内命中引用 → 整条拒绝
fn refs_in_single_quotes(command: &str, configured: &[String]) -> bool {
    let single_ranges = { // 与 scan_refs_opts 同源的单引号区间扫描

        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut in_single = false;
        let mut start = 0usize;
        for (i, c) in command.char_indices() {
            if c == '\'' {
                if in_single {
                    ranges.push((start, i));
                    in_single = false;
                } else {
                    in_single = true;
                    start = i;
                }
            }
        }
        ranges
    };
    scan_refs_opts(command, configured, true)
        .iter()
        .any(|(_, idx, _)| single_ranges.iter().any(|(s, e)| *idx > *s && *idx < *e))
}

/// sh 单引号安全包裹（值含任意字符也不破坏命令）
fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

// ---------- 宿主无关命令门：守卫与槽位签发在 daemon parse op 内执行 ----------
// 分工定稿（用户口径）：parse=守卫判定+解析全部值+签发一次性 token（钩子时刻，值不出 daemon）；
// inject=redeem token 输出 export 行（运行时刻，同 shell eval 消费，为后续指令注入，一次性消费）；
// run=自己 spawn 子进程精确注入（用户执行器）。env 文件已废除，槽位只存 daemon 内存。

/// 内部文件守卫碎片（与 info 快照同源）：目录碎片（~ 形态连带）+ 库文件组
fn guard_fragments() -> Vec<String> {
    let vd = dir();
    let mut frags = vec![".config/secret-env".to_string()];
    for f in ["vault.db", "vault.db-wal", "vault.db-shm", ".vault.salt", "audit.jsonl", "daemon.sock"] {
        frags.push(vd.join(f).to_string_lossy().to_string());
    }
    frags
}

// ---------- main ----------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let e = run(cmd, &args).await;
    if let Err(e) = e {
        eprintln!("rsenv: {e}");
        std::process::exit(1);
    }
}


async fn run(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // run = inject 的别名（语义完全相同，肌肉记忆从 srun→run 迁移）
    let cipher = std::env::var("SENV_CIPHER").unwrap_or_else(|_| "aegis256".into());
    match cmd {
        "serve" => {
            // launchd 作业不继承 shell env：vault 目录/cipher 经 argv 显式传入并落到本进程 env，
            // 后续 dir()/vault_path()/cipher 读取逻辑不变（路径非机密，argv 可容）
            if let Some(i) = args.iter().position(|a| a == "--vault-dir") {
                if let Some(v) = args.get(i + 1) { unsafe { std::env::set_var("SENV_VAULT_DIR", v); } }
            }
            if let Some(i) = args.iter().position(|a| a == "--cipher") {
                if let Some(c) = args.get(i + 1) { unsafe { std::env::set_var("SENV_CIPHER", c); } }
            }
            if let Some(i) = args.iter().position(|a| a == "--path") {
                if let Some(p) = args.get(i + 1) { unsafe { std::env::set_var("PATH", p); } }
            }
            // node 解释器目录（ov 是 env node 脚本）：prepend 进 daemon PATH，launchd 基线兜底
            if let Some(i) = args.iter().position(|a| a == "--node-dir") {
                if let Some(d) = args.get(i + 1) {
                    let base = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
                    unsafe { std::env::set_var("PATH", format!("{}:{}", d, base)); }
                }
            }
            // 工具绝对路径（login 用自身 PATH which 出来，没找到的不传）：ov/bw/op 各一
            for name in ["ov", "bw", "op"] {
                if let Some(i) = args.iter().position(|a| a == &format!("--{name}-path")) {
                    if let Some(p) = args.get(i + 1) {
                        unsafe { std::env::set_var(format!("SENV_TOOL_{}", name.to_uppercase()), p); }
                    }
                }
            }
            std::fs::create_dir_all(dir())?;
            // launchd 托管形态：serve 恒以 locked 态启动，key 由 login 经 socket `unlock` op 传入
            // （stdin 管道通道废除——launchctl submit 无法喂 stdin；socket 0600+peer-exe 同信任域）；
            // 手动 serve 亦为 locked 态
            let preloaded: Option<String> = None;
            let sp = socket_path();
            let _ = std::fs::remove_file(&sp);
            let listener = UnixListener::bind(&sp)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sp, std::fs::Permissions::from_mode(0o600))?;
            let state = std::sync::Arc::new(tokio::sync::RwLock::new(DaemonState { key: preloaded, cipher, slots: std::collections::HashMap::new() }));
            audit("daemon-start", &[]);
            eprintln!("rsenv: listening on {}", sp.display());
            loop {
                let (stream, _) = listener.accept().await?;
                let st = state.clone();
                tokio::spawn(handle_conn(stream, st));
            }
        }
        "init" => {
            // 一次性建库设口令（用户终端，口令不经任何第三方）；库已存在则拒绝
            if vault_path().exists() {
                return Err("vault already exists (login directly; re-init = delete vault.db yourself first)".into());
            }
            let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let password = if tty {
                let p1 = rpassword::prompt_password("new vault password: ")?;
                let p2 = rpassword::prompt_password("confirm password: ")?;
                if p1 != p2 { return Err("passwords do not match".into()); }
                p1
            } else {
                read_password_arg()?
            };
            if password.is_empty() { return Err("empty password".into()); }
            let salt = load_or_create_salt()?;
            let k_login = derive_key(&password, &salt)?;
            let key = k_login; // vault 直接用口令派生密钥加密（单一加密模型，无信封）
            let cipher = std::env::var("SENV_CIPHER").unwrap_or_else(|_| "aegis256".into());
            let db = turso::Builder::new_local(vault_path().to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher: cipher.clone(), hexkey: key.clone() })
                .build().await?;
            let conn = db.connect()?;
            conn.execute("CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, name TEXT UNIQUE, desc TEXT, fields_json TEXT, created_at INTEGER, updated_at INTEGER)", ()).await?;
            drop(conn);
            audit("init", &[]);
            // launchd 托管拉起（locked）→ unlock 经 socket 送 key，同 login 口径
            let exe = std::env::current_exe()?;
            ensure_daemon(&exe, &cipher).await?;
            let reply = client_call(&json!({"op": "unlock", "key": key})).await?;
            if reply.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("unlock failed").to_string().into());
            }
            println!("vault initialized, daemon started (launchd-managed)");
        }
        "login" => {
            // 幂等：daemon 已在跑且已解锁 → 静默退出（口令都不问）；locked 态（launchd 刚拉起）继续走解锁
            if UnixStream::connect(socket_path()).await.is_ok() {
                let reply = client_call(&json!({"op": "status"})).await?;
                if reply.get("unlocked").and_then(Value::as_bool) == Some(true) {
                    return Ok(());
                }
            }
            if !vault_path().exists() {
                return Err("vault not found (run: rsenv init)".into());
            }
            let password = read_password_arg()?;
            // 口令验证 = 开库（打不开 = 口令错，fail-closed）；单一天真模型，无信封
            let salt = load_or_create_salt()?;
            let k_login = derive_key(&password, &salt)?;
            let key = k_login;
            let cipher = std::env::var("SENV_CIPHER").unwrap_or_else(|_| "aegis256".into());
            let db = turso::Builder::new_local(vault_path().to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher: cipher.clone(), hexkey: key.clone() })
                .build().await.map_err(|_| "wrong password")?;
            let conn = db.connect().map_err(|_| "wrong password")?;
            conn.query("SELECT count(*) FROM entries", ()).await.map_err(|_| "wrong password")?;
            drop(conn);
            drop(db);
            audit("login", &[]);
            // launchd 托管拉起（locked 态）→ key 经 socket unlock 送入（socket 0600+peer-exe 同信任域，
            // 值不落盘不进 argv/env；fork 式 daemon 会被宿主退出连坐清杀，launchd 是唯一幸存形态）
            let exe = std::env::current_exe()?;
            ensure_daemon(&exe, &cipher).await?;
            let reply = client_call(&json!({"op": "unlock", "key": key})).await?;
            if reply.get("ok").and_then(Value::as_bool) != Some(true) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("unlock failed").to_string().into());
            }
            println!("unlocked, daemon running (launchd-managed)");
        }
        "get" => {
            let name = args.get(2).ok_or("usage: rsenv get NAME")?.clone();
            let reply = client_call_or_no_daemon(&json!({"op": "get", "name": name})).await?;
            match (reply.get("ok").and_then(Value::as_bool), reply.get("value")) {
                (Some(true), Some(v)) => println!("{}", v.as_str().unwrap_or("")),
                _ => return Err(reply.get("error").and_then(Value::as_str).unwrap_or("get failed").into()),
            }
        }
        "set" => {
            // 元数据入库：`printf '值' | rsenv set NAME [--desc 描述]`（native 值），
            // 或 `rsenv set NAME --uri provider://路径 [--desc 描述]`（provider 引用，无需 stdin）。
            let name = args.get(2).filter(|s| !s.starts_with("--")).ok_or("usage: rsenv set NAME [--desc D | --uri U]")?.clone();
            let mut desc = String::new();
            let mut uri = String::new();
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--desc" => { desc = args.get(i + 1).ok_or("--desc needs a value")?.clone(); i += 2; }
                    "--uri" => { uri = args.get(i + 1).ok_or("--uri needs a value")?.clone(); i += 2; }
                    _ => return Err(format!("unknown set arg: {}（--desc / --uri）", args[i]).into()),
                }
            }
            let reply = if uri.is_empty() {
                let value = read_value_stdin()?;
                client_call_or_no_daemon(&json!({"op": "set", "name": name, "value": value, "desc": desc})).await?
            } else {
                // uri 模式不消费 stdin；但管道里带了值 = 配置歧义，拒绝（与 daemon 侧互斥校验同构）
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() {
                    let piped = read_value_stdin().unwrap_or_default();
                    if !piped.is_empty() {
                        return Err("value and uri are mutually exclusive (one entry is either a native secret or a provider reference)".into());
                    }
                }
                client_call_or_no_daemon(&json!({"op": "set", "name": name, "uri": uri, "desc": desc})).await?
            };
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("set failed").into());
            }
            println!("set {name} ok");
        }
        "remove" => {
            let name = args.get(2).ok_or("usage: rsenv remove NAME")?.clone();
            let reply = client_call_or_no_daemon(&json!({"op": "remove", "name": name})).await?;
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("remove failed").into());
            }
            println!("removed {name}");
        }
        "inject" => {
            // 注入消费：`rsenv inject <token>`——redeem parse 签发的一次性槽位，
            // stdout 输出 export 行（sh_quote 包裹），由同 shell 的 eval 消费为后续指令注入。
            // 无 token 直接调 = 死命令（daemon 拒绝）；stdout 未被 eval 捕获的调用属于误用，
            // 由守卫在 parse 侧拒绝（命令文本含 inject 调用 → dump 意图）
            let token = args.get(2).ok_or("usage: rsenv inject <token>")?;
            let reply = client_call_or_no_daemon(&json!({"op": "redeem", "token": token})).await?;
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("inject failed").into());
            }
            let envs = reply.get("env").and_then(Value::as_object).ok_or("bad inject reply")?;
            for (k, v) in envs {
                println!("export {}={}", k, sh_quote(v.as_str().unwrap_or("")));
            }
        }
        "run" => {
            // 用户态执行器：`rsenv run NAME... -- cmd args`——只对参数给出的命令负责，
            // 注入的 env 只活在子进程内，run 退出后续命令不可见（生命周期=子进程一次性物）
            let sep = args.iter().position(|a| a == "--").ok_or("usage: rsenv run NAME... -- cmd args")?;
            let names = args[2..sep].to_vec();
            if names.is_empty() { return Err("no names before --".into()); }
            let cmd_args = &args[sep + 1..];
            if cmd_args.is_empty() { return Err("no command after --".into()); }
            let reply = client_call_or_no_daemon(&json!({"op": "inject", "names": names})).await?;
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("run failed").into());
            }
            // 精确注入非全量环境复制：白名单基础变量 + 注入值，未注入变量不混入
            let envs = reply.get("env").and_then(Value::as_object).ok_or("bad run reply")?;
            let mut cmd = std::process::Command::new(&cmd_args[0]);
            cmd.args(&cmd_args[1..]).env_clear();
            for k in ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "TERM", "SHELL"] {
                if let Ok(v) = std::env::var(k) { cmd.env(k, v); }
            }
            for (k, v) in envs {
                cmd.env(k, v.as_str().unwrap_or(""));
            }
            // stdio 继承 + 退出码透传（交互式命令照常跑）
            let status = cmd.status()?;
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }

        "status" => {
            let reply = client_call_or_no_daemon(&json!({"op": "status"})).await?;
            println!("{}", serde_json::to_string_pretty(&reply)?);
        }
        "mcp" => {
            // stdio MCP 门（管理面专用）：newline-JSON JSON-RPC 2.0，工具只有 list/status——
            // resolve/get 类工具不开（值永不进 MCP 通道，当年 daemon 拍板口径）。
            // 宿主（ZCode/DSH/opencode）mcpServers 配置 command=rsenv args=["mcp"] 即接入。
            mcp_serve().await?
        }
        "info" => {
            // 宿主适配器守卫快照（同 DSH 蓝本）：rsenv 只提供保护目标清单（约定目录推导），
            // 拦截执行由宿主钩子完成——setup 时调一次，适配器本地保存快照并拦截。
            // daemon 不在/locked 时 info 仍可用（names 空，guard_paths 照给）
            let vd = dir();
            let guard_paths: Vec<String> = [
                "vault.db",
                "vault.db-wal",
                "vault.db-shm",
                ".vault.salt",
                "audit.jsonl",
                "daemon.sock",
            ]
            .iter()
            .map(|f| vd.join(f).to_string_lossy().to_string())
            .collect();
            let entries: Vec<Value> = match client_call(&json!({"op": "list"})).await {
                Ok(r) if r.get("ok").and_then(Value::as_bool).unwrap_or(false) => r
                    .get("entries")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|e| {
                                json!({
                                    "name": e.get("name").and_then(Value::as_str).unwrap_or(""),
                                    "desc": e.get("desc").and_then(Value::as_str).unwrap_or(""),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "protocol": 1,
                    "version": env!("CARGO_PKG_VERSION"),
                    "backend": "rsenv",
                    "capabilities": {"daemon": true},
                    "guard_paths": guard_paths,
                    "entries": entries,
                }))?
            );
        }
        "list" => {
            let reply = client_call_or_no_daemon(&json!({"op": "list"})).await?;
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("list failed").into());
            }
            for e in reply.get("entries").and_then(Value::as_array).unwrap_or(&vec![]) {
                let name = e.get("name").and_then(Value::as_str).unwrap_or("");
                let desc = e.get("desc").and_then(Value::as_str).unwrap_or("");
                let fields: Vec<&str> = e.get("fields").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                println!("{name}  ({})  [{}]", desc, fields.join(","));
            }
        }
        "import-secrets" => {
            // secrets.json 迁移（用户终端执行；URI 引用非明文凭据，无需输值）
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("~/.config/secret-env/secrets.json");
            let path = shellexpand_home(path)?;
            let raw = std::fs::read_to_string(&path)?;
            let v: Value = serde_json::from_str(&raw)?;
            let mut entries = Vec::new();
            for (name, def) in v.as_object().ok_or("bad secrets.json")? {
                if name.starts_with('$') { continue; } // 保留键（$keychain 等）废弃
                let uri = def.get("uri").and_then(Value::as_str).unwrap_or("");
                if uri.is_empty() { continue; }
                let desc = def.get("description").and_then(Value::as_str).unwrap_or("");
                entries.push(json!({"name": name, "desc": desc, "uri": uri}));
            }
            if entries.is_empty() { println!("nothing to import"); return Ok(()); }
            let reply = client_call_or_no_daemon(&json!({"op": "import", "entries": entries})).await?;
            if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return Err(reply.get("error").and_then(Value::as_str).unwrap_or("import failed").into());
            }
            println!("imported {} entries from {}", reply.get("imported").and_then(Value::as_i64).unwrap_or(0), path.display());
        }
        "parse" => {
            // 宿主无关命令门（钩子时刻）：stdin JSON {"command": ...} → stdout JSON 判定。
            // 各宿主插件壳（JS）读各自 payload、翻译各自协议后调这里；rsenv 不感知宿主方言
            let mut raw = String::new();
            use std::io::Read;
            std::io::stdin().read_to_string(&mut raw)?;
            let payload: Value = serde_json::from_str(raw.trim())
                .map_err(|e| format!("bad parse payload: {e}"))?;
            let command = payload
                .get("command")
                .and_then(Value::as_str)
                .ok_or("parse payload missing command")?;
            // 第一层（守卫分层原则，2026-11-08 用户定调）：文件提及守卫的保护对象是静态文件，
            // 零 daemon 依赖——CLI 本地判定、永远生效；daemon 侧同款判定保留作纵深。
            // daemon 不在时本层仍拦文件提及，引用/倾泻/解析层自然跳过（无保护对象）
            if let Some(hit) = guard_fragments().iter().find(|f| command.contains(f.as_str())) {
                println!("{}", serde_json::to_string(&json!({"ok": true, "action": "reject", "reason": format!("command touches protected files (fragment \"{hit}\") — vault/audit files are forbidden to the agent; maintain config in your own terminal")}))?);
                std::process::exit(2);
            }
            let reply = match client_call_or_no_daemon(&json!({"op": "parse", "command": command})).await {
                Ok(r) => r,
                Err(e) => {
                    // 用户定调（2026-11-08）：daemon 不在/未解锁 → 钩子不生效，pass 透传。
                    // 依据：vault 不可用期间无值可解析也无值可泄，全量拒绝只瘫痪 agent 不增安全；
                    // 判据 = client_call_or_no_daemon 的 agent 指引映射消息（daemon 不可达专用）
                    let msg = e.to_string();
                    if msg.contains("ask the user to run") {
                        println!("{}", serde_json::to_string(&json!({"action": "pass", "degraded": "daemon-down"}))?);
                        return Ok(());
                    }
                    return Err(e);
                }
            };
            if reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                println!("{}", serde_json::to_string(&reply)?);
                if reply.get("action").and_then(Value::as_str) == Some("reject") {
                    std::process::exit(2);
                }
                return Ok(());
            }
            // daemon 在但 locked：同口径透传（vault 不可用无值可泄；判据=daemon 侧同款指引消息）
            let err = reply.get("error").and_then(Value::as_str).unwrap_or("parse failed");
            if err.contains("ask the user to run") {
                println!("{}", serde_json::to_string(&json!({"action": "pass", "degraded": "vault-locked"}))?);
                return Ok(());
            }
            return Err(err.into());
        }
        "logout" => {
            client_call_or_no_daemon(&json!({"op": "logout"})).await?;
            // launchd 作业随 daemon 退场清掉，避免残留 label 阻塞下次 submit
            let _ = std::process::Command::new("launchctl").args(["remove", daemon_launchd_label()]).output();
            println!("logged out, daemon stopped");
        }
        "passwd" => {
            // 闲置重加密换口令（用户终端执行）。turso 后台 checkpoint 与库文件置换互斥，
            // 所以整个换装窗口内不允许任何库句柄存活：先停 daemon（进程退出，句柄必然
            // 全释放）→ CLI 行级搬库到侧路径（vault.db.passwd）→ 全部句柄关闭后换装
            // （旧三件 → .bak 三件，新三件改名就位）→ 全新子进程验证行数（失败回滚
            // .bak）→ 按需重启 daemon。旧库新库都是口令派生密钥直接加密，无信封。
            let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
            let (old_pw, new_pw) = if tty {
                let o = rpassword::prompt_password("current password: ")?;
                let n1 = rpassword::prompt_password("new password: ")?;
                let n2 = rpassword::prompt_password("confirm new password: ")?;
                if n1 != n2 { return Err("passwords do not match".into()); }
                (o, n1)
            } else {
                (read_password_arg()?, read_password_arg()?)
            };
            if new_pw.is_empty() { return Err("empty new password".into()); }

            // 1) 停 daemon（若有）
            let daemon_was_up = UnixStream::connect(socket_path()).await.is_ok();
            if daemon_was_up {
                let reply = client_call(&json!({"op": "logout"})).await?;
                if !reply.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    return Err(reply.get("error").and_then(Value::as_str).unwrap_or("logout failed").into());
                }
                for _ in 0..50 {
                    if UnixStream::connect(socket_path()).await.is_err() { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }

            // 2) 旧口令开库，行级读出全部条目（开不了库/读不了 = 口令错）
            let salt = load_or_create_salt()?;
            let k_old = derive_key(&old_pw, &salt)?;
            let cipher = std::env::var("SENV_CIPHER").unwrap_or_else(|_| "aegis256".into());
            let db = turso::Builder::new_local(vault_path().to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher: cipher.clone(), hexkey: k_old.clone() })
                .build().await.map_err(|_| "current password mismatch")?;
            let conn = db.connect().map_err(|_| "current password mismatch")?;
            let mut rows_out: Vec<(String, String, String, i64, i64)> = Vec::new();
            let mut rows = conn.query("SELECT name, desc, fields_json, created_at, updated_at FROM entries", ())
                .await.map_err(|_| "current password mismatch")?;
            while let Some(r) = rows.next().await.map_err(|_| "passwd: read rows failed")? {
                rows_out.push((
                    r.get_value(0).unwrap().as_text().unwrap().clone(),
                    r.get_value(1).unwrap().as_text().unwrap().clone(),
                    r.get_value(2).unwrap().as_text().unwrap().clone(),
                    r.get_value(3).unwrap().as_integer().copied().unwrap_or(0),
                    r.get_value(4).unwrap().as_integer().copied().unwrap_or(0),
                ));
            }
            let n_old = rows_out.len();
            drop(rows);
            drop(conn);
            drop(db);

            // 3) 新口令在侧路径建全新库写入（全句柄关闭后换装）
            let k_new = derive_key(&new_pw, &salt)?;
            let new_path = dir().join("vault.db.passwd");
            for s in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(with_suffix(&new_path, s));
            }
            let db2 = turso::Builder::new_local(new_path.to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher: cipher.clone(), hexkey: k_new.clone() })
                .build().await?;
            let conn2 = db2.connect()?;
            conn2.execute("CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, name TEXT UNIQUE, desc TEXT, fields_json TEXT, created_at INTEGER, updated_at INTEGER)", ()).await?;
            for (name, desc, fj, created, updated) in &rows_out {
                conn2.execute(
                    "INSERT INTO entries (name, desc, fields_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    [name.as_str(), desc.as_str(), fj.as_str(), &created.to_string(), &updated.to_string()],
                ).await?;
            }
            drop(conn2);
            drop(db2);

            // 4) 换装：旧三件 → .bak 三件，新三件改名就位（wal/shm 可能不存在，容忍）
            let vp = vault_path();
            let bak = with_suffix(&vp, ".bak");
            std::fs::rename(&vp, &bak)?;
            for s in ["-wal", "-shm"] {
                let o = with_suffix(&vp, s);
                if o.exists() { let _ = std::fs::rename(&o, with_suffix(&bak, s)); }
            }
            std::fs::rename(&new_path, &vp)?;
            for s in ["-wal", "-shm"] {
                let o = with_suffix(&new_path, s);
                if o.exists() { let _ = std::fs::rename(&o, with_suffix(&vp, s)); }
            }

            // 5) 全新子进程验证行数（验证窗口内无任何旧句柄存活）；失败回滚 .bak
            let exe = std::env::current_exe()?;
            let mut child = std::process::Command::new(&exe)
                .arg("_passwd-verify").arg(n_old.to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            use std::io::Write;
            child.stdin.take().unwrap().write_all(format!("{new_pw}\n").as_bytes())?;
            let ok = child.wait().map(|st| st.success()).unwrap_or(false);
            if !ok {
                let _ = std::fs::remove_file(&vp);
                for s in ["-wal", "-shm"] { let _ = std::fs::remove_file(with_suffix(&vp, s)); }
                let _ = std::fs::rename(&bak, &vp);
                for s in ["-wal", "-shm"] {
                    let b = with_suffix(&bak, s);
                    if b.exists() { let _ = std::fs::rename(&b, with_suffix(&vp, s)); }
                }
                return Err("passwd: post-swap verification failed (rolled back to previous vault)".into());
            }
            let _ = std::fs::remove_file(&bak);
            for s in ["-wal", "-shm"] { let _ = std::fs::remove_file(with_suffix(&bak, s)); }
            audit("passwd", &[]);

            // 6) 按需重启 daemon（launchd 托管拉起 locked 态 → unlock 经 socket 送新 key）
            if daemon_was_up {
                ensure_daemon(&exe, &cipher).await?;
                let reply = client_call(&json!({"op": "unlock", "key": k_new})).await?;
                if reply.get("ok").and_then(Value::as_bool) != Some(true) {
                    return Err(reply.get("error").and_then(Value::as_str).unwrap_or("unlock failed").to_string().into());
                }
                println!("password changed (vault re-encrypted), daemon restarted");
            } else {
                println!("password changed (vault re-encrypted)");
            }
        }
        "_passwd-verify" => {
            // 内部：passwd 换装后的验证子命令（全新进程内无其他库句柄存活）。
            // 参数 = 期望条目数，stdin = 新口令；不一致即退出码 1。
            let expect: i64 = args.get(2).ok_or("missing expected count")?.parse().map_err(|_| "bad count")?;
            let password = read_password_arg()?;
            let salt = load_or_create_salt()?;
            let k_login = derive_key(&password, &salt)?;
            let cipher = std::env::var("SENV_CIPHER").unwrap_or_else(|_| "aegis256".into());
            let db = turso::Builder::new_local(vault_path().to_str().unwrap())
                .experimental_encryption(true)
                .with_encryption(EncryptionOpts { cipher, hexkey: k_login })
                .build().await.map_err(|_| "verify: cannot open vault")?;
            let conn = db.connect()?;
            let mut rows = conn.query("SELECT count(*) FROM entries", ()).await?;
            let n = match rows.next().await? {
                Some(r) => r.get_value(0).unwrap().as_integer().copied().unwrap_or(-1),
                None => -1,
            };
            if n != expect { std::process::exit(1); }
            println!("verified");
        }
        other => {
            return Err(format!("unknown command: {other} (usage: login|parse|inject|run|get|set|remove|list|import-secrets|info|status|passwd|logout)").into());
        }
    }
    Ok(())
}
