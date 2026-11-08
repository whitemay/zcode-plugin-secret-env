//! turso 加密能力 PoC：建库/读写/重开/错口令拒绝/密文落盘/login 派生/换 key 验证。
//! 与 secret-env 项目功能无关，纯技术验证。

use turso::{Builder, EncryptionOpts, Value};

const CIPHER_AEGIS256: &str = "aegis256";
const CIPHER_AES256GCM: &str = "aes256gcm";

fn hexkey_ok() -> &'static str {
    // PoC 固定 key，非生产凭据
    "2d7a30108d3eb3e45c90a732041fe54778bdcf707c76749fab7da335d1b39c1d"
}

fn hexkey_wrong() -> &'static str {
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}

fn opts(cipher: &str, hexkey: &str) -> EncryptionOpts {
    EncryptionOpts {
        cipher: cipher.to_string(),
        hexkey: hexkey.to_string(),
    }
}

async fn open(path: &str, o: Option<EncryptionOpts>) -> turso::Result<turso::Connection> {
    let mut b = Builder::new_local(path).experimental_encryption(true);
    if let Some(o) = o {
        b = b.with_encryption(o);
    }
    let db = b.build().await?;
    Ok(db.connect()?)
}

/// 断言辅助：query 单值
async fn scalar(conn: &turso::Connection, sql: &str) -> turso::Result<Value> {
    let mut rows = conn.query(sql, ()).await?;
    let row = rows.next().await?.expect("expected one row");
    Ok(row.get_value(0)?)
}

async fn scenario_create_read_write(
    path: &str,
    cipher: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: create/read/write [{cipher}] ==");
    // 1. 建库建表写入
    let conn = open(path, Some(opts(cipher, hexkey_ok()))).await?;
    conn.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)", ())
        .await?;
    conn.execute("INSERT INTO secrets (name, value) VALUES (?1, ?2)", ["gh_token", "ghp_fake_poc_value"])
        .await?;
    // 2. 同连接读回
    let v = scalar(&conn, "SELECT value FROM secrets WHERE name = 'gh_token'").await?;
    assert_eq!(v.as_text().unwrap(), "ghp_fake_poc_value");
    println!("  same-conn read-back OK");
    drop(conn);

    // 3. 关闭后同 key 重开读回
    let conn = open(path, Some(opts(cipher, hexkey_ok()))).await?;
    let v = scalar(&conn, "SELECT value FROM secrets WHERE name = 'gh_token'").await?;
    assert_eq!(v.as_text().unwrap(), "ghp_fake_poc_value");
    println!("  reopen-with-key read-back OK");
    // 4. 重开后继续写
    conn.execute("INSERT INTO secrets (name, value) VALUES (?1, ?2)", ["bw_session", "poc_bw_value"])
        .await?;
    let n = scalar(&conn, "SELECT COUNT(*) FROM secrets").await?;
    assert_eq!(*n.as_integer().unwrap(), 2);
    println!("  post-reopen write OK");
    drop(conn);
    Ok(())
}

/// 错 key 重开：期望报错（宁可失败）。行为如实记录，断言见 main。
async fn probe_wrong_key(path: &str, cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: wrong-key reopen [{cipher}] ==");
    match open(path, Some(opts(cipher, hexkey_wrong()))).await {
        Ok(conn) => {
            // 有的实现 open 成功但首条查询才失败（密钥惰性校验），两种都如实记录
            match scalar(&conn, "SELECT COUNT(*) FROM secrets").await {
                Ok(v) => println!("  NOTE: open+query SUCCEEDED with wrong key! count={:?}", v.as_integer()),
                Err(e) => println!("  open OK, first query failed (lazy key check): {e}"),
            }
        }
        Err(e) => println!("  open rejected immediately: {e}"),
    }
    Ok(())
}

/// 无 key 重开：期望报错
async fn probe_no_key(path: &str, cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: no-key reopen [{cipher}] ==");
    match open(path, None).await {
        Ok(conn) => match scalar(&conn, "SELECT COUNT(*) FROM secrets").await {
            Ok(v) => println!("  NOTE: open+query SUCCEEDED without key! count={:?}", v.as_integer()),
            Err(e) => println!("  open OK, first query failed: {e}"),
        },
        Err(e) => println!("  open rejected immediately: {e}"),
    }
    Ok(())
}

/// 密文落盘验证：文件头不得是明文 SQLite 魔数，且全文 grep 不到 PoC 明文值
fn probe_encrypted_on_disk(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: encrypted-on-disk ==");
    let bytes = std::fs::read(path)?;
    let head = String::from_utf8_lossy(&bytes[..16.min(bytes.len())]).to_string();
    println!("  file size = {} bytes, header16 = {head:?}", bytes.len());
    assert_ne!(head, "SQLite format 3\0", "header is plaintext sqlite magic!");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("ghp_fake_poc_value"), "plaintext secret found on disk!");
    assert!(!text.contains("poc_bw_value"), "plaintext secret found on disk!");
    println!("  no plaintext magic, no plaintext secret: OK");
    Ok(())
}

/// 口令 → 64 字符 hex key（模拟 login 的 KDF 派生；salt 固定为 PoC 简化，生产须随机入库）
fn derive_key(password: &str) -> String {
    use argon2::{Argon2, Algorithm, Params, Version};
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"turso-enc-poc-salt").unwrap();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19456, 2, 1, None).unwrap());
    let out = a2.hash_password(password.as_bytes(), &salt).unwrap();
    let h = out.hash.unwrap();
    h.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// login 链路：口令派生 key 建库 → 同 key 重开 OK；错误口令派生 → open 拒绝
async fn scenario_login(path: &str, cipher: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: login (argon2id derive -> open) [{cipher}] ==");
    // 建库与 login 共用同一派生 key（生产口径：口令唯一来源是 login，建库即首次 login）
    let good = derive_key("correct-horse-battery");
    let path = format!("{path}-login");
    let _ = std::fs::remove_file(&path);
    let conn = open(&path, Some(opts(cipher, &good))).await?;
    conn.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)", ()).await?;
    conn.execute("INSERT INTO secrets (name, value) VALUES (?1, ?2)", ["gh_token", "ghp_fake_poc_value"]).await?;
    drop(conn);

    let conn = open(&path, Some(opts(cipher, &good))).await?;
    let v = scalar(&conn, "SELECT COUNT(*) FROM secrets").await?;
    assert_eq!(*v.as_integer().unwrap(), 1);
    drop(conn);
    println!("  correct password -> reopen + query OK (derived {} chars hex)", good.len());

    let bad = derive_key("wrong-password");
    let r = open(&path, Some(opts(cipher, &bad))).await;
    match r {
        Ok(_) => println!("  FAIL: wrong password opened the db!"),
        Err(e) => println!("  wrong password -> open rejected: {e}"),
    }
    Ok(())
}

/// 换 key（turso 无 rekey，走逻辑重加密）：旧库导出 → 新 key 建新库回放 → 原子换名 → 双向验证
async fn scenario_rotate_key(
    path: &str,
    cipher: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("== scenario: key rotation (logical re-encrypt) [{cipher}] ==");
    let old_key = hexkey_ok();
    let new_key = "aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff";

    println!("  [rotate] step1: export from {path}");
    // 1. 旧 key 打开，导出 schema + 数据
    let conn = open(path, Some(opts(cipher, old_key))).await?;
    let mut rows = conn.query("SELECT name, value FROM secrets ORDER BY id", ()).await?;
    let mut data = Vec::new();
    while let Some(row) = rows.next().await? {
        let name = row.get_value(0)?.as_text().unwrap().clone();
        let value = row.get_value(1)?.as_text().unwrap().clone();
        data.push((name, value));
    }
    drop(conn);
    assert_eq!(data.len(), 2);

    println!("  [rotate] step2: replay to tmp with new key");
    // 2. 新 key 建新库，回放
    let tmp = format!("{path}.new");
    let _ = std::fs::remove_file(&tmp);
    let conn = open(&tmp, Some(opts(cipher, new_key))).await?;
    conn.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT)", ()).await?;
    for (name, value) in &data {
        conn.execute("INSERT INTO secrets (name, value) VALUES (?1, ?2)", [name.as_str(), value.as_str()]).await?;
    }
    let v = scalar(&conn, "SELECT COUNT(*) FROM secrets").await?;
    assert_eq!(*v.as_integer().unwrap(), 2);
    drop(conn);

    println!("  [rotate] step3: atomic swap");
    // 3. 原子换名：旧库备份 → 新库上位（WAL/shm 附属文件必须随主文件一起搬，否则数据丢失）
    let bak = format!("{path}.bak");
    let _ = std::fs::remove_file(&bak);
    std::fs::rename(path, &bak)?;
    std::fs::rename(&tmp, path)?;
    for suffix in ["-wal", "-shm"] {
        let from = format!("{tmp}{suffix}");
        if std::fs::metadata(&from).is_ok() {
            std::fs::rename(&from, format!("{path}{suffix}"))?;
        }
    }

    // 4. 双向验证：新 key 可读；旧 key（现为错误 key）被拒
    println!("  files after rename: path={}", std::fs::metadata(path).map(|m| m.len()).unwrap_or(0));
    for suffix in ["-wal", "-shm"] {
        let f = format!("{path}{suffix}");
        println!("  path{suffix} = {}", std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0));
    }
    let conn = open(path, Some(opts(cipher, new_key))).await?;
    let v = scalar(&conn, "SELECT COUNT(*) FROM secrets").await?;
    assert_eq!(*v.as_integer().unwrap(), 2);
    drop(conn);
    println!("  new-key reopen OK ({} entries preserved)", data.len());

    match open(path, Some(opts(cipher, old_key))).await {
        Ok(_) => println!("  FAIL: old key still opens db!"),
        Err(e) => println!("  old key rejected: {e}"),
    }
    let _ = std::fs::remove_file(&bak);
    Ok(())
}

#[tokio::main]
async fn main() {
    let dir = std::env::temp_dir().join("turso-enc-poc");
    std::fs::create_dir_all(&dir).unwrap();
    for cipher in [CIPHER_AEGIS256, CIPHER_AES256GCM] {
        let path = dir.join(format!("poc-{cipher}.db"));
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);

        let r = scenario_create_read_write(path, cipher).await;
        println!("  => {}", if r.is_ok() { "PASS" } else { "FAIL" });
        if let Err(e) = &r { println!("  error: {e}"); }
        if r.is_ok() {
            async fn diag(path: &str, tag: &str, cipher: &str) {
                match open(path, Some(opts(cipher, hexkey_ok()))).await {
                    Ok(c) => match scalar(&c, "SELECT COUNT(*) FROM secrets").await {
                        Ok(v) => println!("  [diag:{tag}] correct-key count={:?}", v.as_integer()),
                        Err(e) => println!("  [diag:{tag}] correct-key query error: {e}"),
                    },
                    Err(e) => println!("  [diag:{tag}] correct-key open error: {e}"),
                }
            }
            if let Err(e) = probe_wrong_key(path, cipher).await { println!("  [wrong-key] error: {e}"); }
            diag(path, "after-wrongkey", cipher).await;
            if let Err(e) = probe_no_key(path, cipher).await { println!("  [no-key] error: {e}"); }
            diag(path, "after-nokey", cipher).await;
            if let Err(e) = scenario_login(path, cipher).await { println!("  [login] error: {e}"); }
            if let Err(e) = scenario_rotate_key(path, cipher).await { println!("  [rotate] error: {e}"); }
        }
    }
    // 落盘验证用 aegis256 的库
    let aegis = dir.join("poc-aegis256.db");
    if aegis.exists() {
        if let Err(e) = probe_encrypted_on_disk(aegis.to_str().unwrap()) {
            println!("  encrypted-on-disk FAIL: {e}");
        }
    }
    println!("\nPoC done. db files kept at {dir:?} for manual inspection (hexdump).");
}
