#!/bin/bash
# rsenv E2E 回归：login(自起 daemon)/set/get/peer-exe 鉴权/审计/logout(停 daemon)。用法：bash e2e.sh
set -e
TD=$(mktemp -d /tmp/rsenv-test.XXXXXX)
export SENV_VAULT_DIR=$TD
cd "$(dirname "$0")"
BIN=./target/debug/rsenv
RUN=inject
cleanup() {
  PIDS=$(pgrep -f "rsenv serve" || true)
  [ -n "$PIDS" ] && kill $PIDS 2>/dev/null
  rm -rf $TD
}
trap cleanup EXIT

echo "--- fake provider CLIs on PATH（daemon 继承 PATH，子进程外调全部落到假二进制）:"
FAKEBIN=$TD/fakebin
mkdir -p $FAKEBIN
cat > $FAKEBIN/ov <<'EOF'
#!/bin/sh
# ov privacy resolve <path> → 多行元数据表，真值在 value 行（空格对齐非冒号）
printf 'account fake\nkind privacy\nvalue    fake_ov_%s%s\nnote fake\n' "$3" "${4:+/$4}"
EOF
cat > $FAKEBIN/bw <<'EOF'
#!/bin/sh
# 665827d 两步流：list items --search <名>（JSON 数组，唯一精确同名）→ get <field> <id>（session 走 env）
if [ "$1" = "list" ]; then
  printf '[{"name":"%s","id":"fake-bw-id"}]\n' "$4"
  exit 0
fi
printf 'bwval(field=%s,item=%s)' "$2" "$3"
[ -n "$BW_SESSION" ] && printf ' sess=%s' "$BW_SESSION"
printf '\n'
EOF
cat > $FAKEBIN/op <<'EOF'
#!/bin/sh
sess=no
for a in "$@"; do [ "$a" = "--session" ] && sess=yes; done
printf 'opval sess=%s' "$sess"
[ "$sess" = "yes" ] && printf ' tok=%s' "$2"
printf '\n'
EOF
chmod +x $FAKEBIN/ov $FAKEBIN/bw $FAKEBIN/op
export PATH=$FAKEBIN:$PATH

echo "--- init (creates vault, starts daemon):"
echo "testpass" | $BIN init
pgrep -f "rsenv serve" >/dev/null && echo "daemon running OK" || { echo "FAIL: no daemon"; exit 1; }
echo "--- no token file on disk:"
[ ! -f $TD/agent.token ] && echo "tokenless OK" || { echo "FAIL: token file exists"; exit 1; }
echo "--- login again (idempotent, silent):"
echo "" | $BIN login && echo "idempotent OK" || { echo "FAIL: second login errored"; exit 1; }
echo "--- init on existing vault (expect refuse):"
echo "" | $BIN init >/dev/null 2>&1 && { echo "FAIL: re-init accepted"; exit 1; } || echo "re-init refused OK"
echo "--- import-secrets (URI refs, no plaintext):"
cat > $TD/secrets.json <<'JSON'
{
  "GH_TOKEN_REF": {"uri": "viking://resources/github-token", "description": "gh token via viking"},
  "BW_SESSION": {"uri": "viking://resources/bw-session", "description": "bw session via viking"},
  "OPS_SECRET": {"uri": "bitwarden://my-item", "description": "bw item, session chained from BW_SESSION entry"},
  "OP_SECRET": {"uri": "onepassword://my-op-item", "description": "op item, session from OP_SESSION entry"},
  "OP_SESSION": {"uri": "viking://resources/op-session", "description": "op session via viking"},
  "BAD_SCHEME": {"uri": "foo://whatever", "description": "unknown scheme, must fail loudly"},
  "$keychain": {"password": "ignored"}
}
JSON
$BIN import-secrets $TD/secrets.json
$BIN list | tee $TD/list.out
grep -q "GH_TOKEN_REF" $TD/list.out && grep -q "BW_SESSION" $TD/list.out && echo "import+list OK" || { echo "FAIL: import"; exit 1; }
grep -q "ghp_fake_value_123" $TD/list.out && { echo "FAIL: list leaked value"; exit 1; } || echo "list: no values OK"
grep -q '"$keychain"' $TD/list.out && { echo "FAIL: reserved key imported"; exit 1; } || echo "reserved key skipped OK"
echo "--- provider 解析（daemon 内子进程外调）:"
[ "$($BIN get GH_TOKEN_REF)" = "fake_ov_resources/github-token" ] && echo "viking: value line parsed OK" || { echo "FAIL: viking resolve: $($BIN get GH_TOKEN_REF)"; exit 1; }
$BIN get OPS_SECRET | grep -q 'sess=fake_ov_resources/bw-session' && echo "bitwarden: BW_SESSION entry chained to child env OK" || { echo "FAIL: bw chain: $($BIN get OPS_SECRET)"; exit 1; }
$BIN get OP_SECRET | grep -q 'opval sess=yes' && $BIN get OP_SECRET | grep -q 'tok=fake_ov_resources/op-session' && echo "onepassword: OP_SESSION entry resolved to --session OK" || { echo "FAIL: op session: $($BIN get OP_SECRET)"; exit 1; }
$BIN get BAD_SCHEME >/dev/null 2>&1 && { echo "FAIL: unknown scheme accepted"; exit 1; } || echo "unknown scheme: rejected loudly OK"
PTOK=$(/usr/bin/python3 -c 'import json;print(json.dumps({"command":"echo $OPS_SECRET"}))' | $BIN parse | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
$BIN inject $PTOK | grep -q 'bwval' && echo "parse→inject: provider-resolved value in export line OK" || { echo "FAIL: inject provider"; exit 1; }
echo "--- set:"
printf 'ghp_fake_value_123' | $BIN set GH_TOKEN
echo "--- set: 元数据入库（desc / provider uri 引用，value 与 uri 互斥）:"
printf 'ghp_fake_value_123' | $BIN set GH_TOKEN --desc "gh personal token"
$BIN list | grep -q "gh personal token" && echo "set: desc stored OK" || { echo "FAIL: desc missing"; exit 1; }
$BIN set NEW_REF --uri "viking://resources/new-token" --desc "uri ref entry" && echo "set: uri entry OK" || { echo "FAIL: uri set"; exit 1; }
[ "$($BIN get NEW_REF)" = "fake_ov_resources/new-token" ] && echo "set: uri entry resolves OK" || { echo "FAIL: uri resolve: $($BIN get NEW_REF)"; exit 1; }
RC=0; printf 'x' | $BIN set BOTH --uri "viking://x" >/dev/null 2>&1 || RC=$?
[ "$RC" != "0" ] && echo "set: value+uri mutually exclusive OK" || { echo "FAIL: both accepted"; exit 1; }
echo "--- remove:"
$BIN remove NEW_REF && echo "remove OK" || { echo "FAIL: remove"; exit 1; }
$BIN get NEW_REF >/dev/null 2>&1 && { echo "FAIL: removed entry still resolves"; exit 1; } || echo "remove: gone OK"
RC=0; $BIN remove NO_SUCH_KEY >/dev/null 2>&1 || RC=$?
[ "$RC" != "0" ] && echo "remove: nonexistent rejected OK" || { echo "FAIL: nonexistent remove accepted"; exit 1; }
echo "--- get:"
[ "$($BIN get GH_TOKEN)" = "ghp_fake_value_123" ] && echo "get roundtrip OK" || { echo "get MISMATCH"; exit 1; }
echo "--- attacker: python3 connects to socket (expect peer-exe rejection):"
"/usr/bin/python3" - "$TD/daemon.sock" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b'{"op":"get","name":"GH_TOKEN"}\n')
data = s.recv(4096).decode()
assert "not rsenv" in data or "rejected" in data, f"FAIL: attacker accepted: {data}"
print(f"attacker rejected OK: {data.strip()}")
PYEOF
AUD=$TD/audit.jsonl
AUD=$TD/audit.jsonl
echo "--- audit: events recorded, no values:"
AUD=$TD/audit.jsonl
[ -f "$AUD" ] && echo "audit.jsonl exists OK" || { echo "FAIL: no audit"; exit 1; }
for ev in daemon-start get set peer-rejected; do
  grep -q "\"event\":\"$ev\"" $AUD && echo "  event $ev OK" || { echo "FAIL: missing event $ev"; exit 1; }
done
if grep -r "ghp_fake_value_123" $AUD >/dev/null 2>&1; then echo "FAIL: value leaked into audit!"; exit 1; else echo "  no value in audit OK"; fi
echo "--- run: 用户态执行器——只对命令负责，退出码透传:"
$BIN run GH_TOKEN -- sh -c 'test -n "$GH_TOKEN"' && echo "run: value present OK" || { echo "FAIL: run missing"; exit 1; }
SECRET_CANARY=leaky $BIN run GH_TOKEN -- sh -c 'test -z "$SECRET_CANARY"' && echo "run: env precise OK" || { echo "FAIL: env leaked"; exit 1; }
RC=0; $BIN run GH_TOKEN -- sh -c 'exit 42' || RC=$?
[ "$RC" = "42" ] && echo "run: exit 42 OK" || { echo "FAIL: exit=$RC"; exit 1; }
echo "--- run: env 生命周期=子进程一次性物，后续命令不可见:"
$BIN run GH_TOKEN -- sh -c 'exit 0'
sh -c 'test -z "$GH_TOKEN"' && echo "run: no env persistence OK" || { echo "FAIL: env persisted"; exit 1; }
echo "--- run: 值不打印到 stdout/stderr:"
OUT=$($BIN run GH_TOKEN -- sh -c 'exit 0' 2>&1)
[ -z "$OUT" ] && echo "run: silent OK" || { echo "FAIL: output leaked: $OUT"; exit 1; }
grep -q '"event":"inject"' $AUD && echo "inject: audited OK" || { echo "FAIL: not audited"; exit 1; }
echo "--- parse/inject: 守卫门 + 一次性 token 槽位（daemon 内存，值不出 daemon）:"
OUT=$(printf '{"command":"echo hello"}' | $BIN parse)
echo "$OUT" | grep -q '"action":"pass"' && echo "parse: no refs pass-through OK" || { echo "FAIL: $OUT"; exit 1; }
OUT=$(printf '{"command":"echo $GH_TOKEN"}' | $BIN parse)
echo "$OUT" | grep -q '"action":"inject"' && echo "$OUT" | grep -q '"token"' && echo "parse: token minted OK" || { echo "FAIL: $OUT"; exit 1; }
TOKEN=$(echo "$OUT" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
# 消费形态（JS 壳同款改写）：eval 链注入 + 原命令执行
sh -c "_senv_inj=\"\$($BIN inject $TOKEN)\" && eval \"\$_senv_inj\" && { echo \$GH_TOKEN; }" | grep -q 'ghp_fake_value_123' && echo "inject: eval chain injects value OK" || { echo "FAIL: eval chain"; exit 1; }
# 一次性：同 token 二次消费 → 死命令
$BIN inject $TOKEN >/dev/null 2>&1 && { echo "FAIL: token reusable"; exit 1; } || echo "inject: token consumed once OK"
# 裸调（无 token）= 死命令
$BIN inject >/dev/null 2>&1 && { echo "FAIL: bare inject accepted"; exit 1; } || echo "inject: bare call rejected OK"
# GC：未消费 token 超 10s 被 GC 回收（redeem 报失效，语义=消费一次 + GC 兜底）
OUT=$(printf '{"command":"echo $GH_TOKEN"}' | $BIN parse)
TOKEN2=$(echo "$OUT" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
sleep 11
$BIN inject $TOKEN2 >/dev/null 2>&1 && { echo "FAIL: GC'd token still redeemable"; exit 1; } || echo "inject: unconsumed token GC'd after 10s OK"
# 重新签发即恢复（GC 不影响新槽位）
OUT=$(printf '{"command":"echo $GH_TOKEN"}' | $BIN parse)
TOKEN3=$(echo "$OUT" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
sh -c "_senv_inj=\"\$($BIN inject $TOKEN3)\" && eval \"\$_senv_inj\" && { echo \$GH_TOKEN; }" | grep -q 'ghp_fake_value_123' && echo "inject: post-GC fresh token OK" || { echo "FAIL: post-GC"; exit 1; }
RC=0; /usr/bin/python3 -c 'import json;print(json.dumps({"command":"echo \x27$GH_TOKEN\x27"}))' | $BIN parse >/dev/null 2>&1 || RC=$?
[ "$RC" = "2" ] && echo "parse: single-quote ref rejected OK" || { echo "FAIL: single-quote not rejected rc=$RC"; exit 1; }
OUT=$(/usr/bin/python3 -c 'import json;print(json.dumps({"command":"echo $GH_TOKEN; printenv GH_TOKEN"}))' | $BIN parse 2>&1 || true)
echo "$OUT" | grep -q 'dump intent' && echo "parse: dump intent (printenv with ref) rejected OK" || { echo "FAIL: dump not rejected: $OUT"; exit 1; }
OUT=$(printf '{"command":"echo $UNRELATED_VAR"}' | $BIN parse)
echo "$OUT" | grep -q '"action":"pass"' && echo "parse: non-configured var pass-through OK" || { echo "FAIL: $OUT"; exit 1; }
echo "--- info: 宿主守卫快照（保护目标清单，拦截由宿主钩子执行）:"
$BIN info > $TD/info.json
grep -q "vault.db-wal" $TD/info.json && grep -q ".vault.salt" $TD/info.json && grep -q "audit.jsonl" $TD/info.json && grep -q "daemon.sock" $TD/info.json && echo "info: guard paths OK" || { echo "FAIL: guard paths: $(cat $TD/info.json)"; exit 1; }
grep -q '"GH_TOKEN"' $TD/info.json && echo "info: entries included (daemon up) OK" || { echo "FAIL: entries missing: $(cat $TD/info.json)"; exit 1; }
echo "--- parse: 文件提及守卫（命令文本涉及库文件即拒）:"
RC=0; /usr/bin/python3 -c "import json;print(json.dumps({'command':'cat $TD/vault.db'}))" | $BIN parse >/dev/null 2>&1 || RC=$?
[ "$RC" = "2" ] && echo "parse: file-mention rejected OK" || { echo "FAIL: file mention not rejected rc=$RC"; exit 1; }
echo "--- ZCode 插件壳（JS 翻译层，harness 逻辑在插件侧）:"
export SENV_BIN=$PWD/target/debug/rsenv
OUT=$(cd ../../adapters/zcode && printf '{"tool_name":"Bash","tool_input":{"command":"echo $GH_TOKEN"},"hook_event_name":"PreToolUse"}' | node hooks/secret-env-zcode.mjs pretooluse)
echo "$OUT" | grep -q '"permissionDecision":"allow"' && echo "$OUT" | grep -q 'rsenv inject' && echo "zcode shell: token rewrite allow OK" || { echo "FAIL: zcode bash: $OUT"; exit 1; }
RC=0; (cd ../../adapters/zcode && printf '{"tool_name":"Write","tool_input":{"file_path":"'"$TD"'/vault.db"},"hook_event_name":"PreToolUse"}' | node hooks/secret-env-zcode.mjs pretooluse >/dev/null 2>&1) || RC=$?
[ "$RC" = "2" ] && echo "zcode shell: file guard deny OK" || { echo "FAIL: zcode file guard not denied rc=$RC"; exit 1; }
(cd ../../adapters/zcode && printf '{"tool_name":"Write","tool_input":{"file_path":"/tmp/normal.txt"},"hook_event_name":"PreToolUse"}' | node hooks/secret-env-zcode.mjs pretooluse) | grep -q '"permissionDecision":"allow"' && echo "zcode shell: normal file allow OK" || { echo "FAIL: normal file denied"; exit 1; }
OUT=$(cd ../../adapters/zcode && printf '{"hook_event_name":"SessionStart"}' | node hooks/secret-env-zcode.mjs session-start)
echo "$OUT" | grep -q '"additionalContext"' && echo "$OUT" | grep -q 'GH_TOKEN' && echo "zcode shell: session-start list OK" || { echo "FAIL: session-start: $OUT"; exit 1; }
unset SENV_BIN
echo "--- passwd: 换口令 = 闲置重加密（停 daemon→侧路径建库→换装→子进程验证）："
printf 'testpass\nnewpass\n' | $BIN passwd
[ -f $TD/vault.db.bak ] && { echo "FAIL: .bak not cleaned"; exit 1; }
[ -f $TD/vault.db.passwd ] && { echo "FAIL: side-path db not cleaned"; exit 1; }
[ "$($BIN get GH_TOKEN)" = "ghp_fake_value_123" ] && echo "passwd: data intact OK" || { echo "FAIL: data lost after passwd"; exit 1; }
$BIN get OPS_SECRET | grep -q 'bwval' && echo "passwd: provider entries intact OK" || { echo "FAIL: provider entries lost"; exit 1; }
grep -q '"event":"passwd"' $AUD && echo "passwd: audited OK" || { echo "FAIL: passwd not audited"; exit 1; }
echo "--- wrong old password rejected (logout, wrong login, relogin):"
$BIN logout >/dev/null
for i in 1 2 3 4 5; do pgrep -f "rsenv serve" >/dev/null || break; sleep 0.5; done
printf 'testpass\n' | $BIN login >/dev/null 2>&1 && { echo "FAIL: old pw accepted after passwd"; exit 1; } || echo "passwd: old pw rejected OK"
printf 'newpass\n' | $BIN login >/dev/null
[ "$($BIN get GH_TOKEN)" = "ghp_fake_value_123" ] && echo "passwd: relogin with new pw OK" || { echo "FAIL: new pw login"; exit 1; }
echo "--- mcp: stdio 管理面（list/status 有响应，无 get 工具）:"
MCPIN='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rsenv_list","arguments":{}}}'
printf '%s\n' "$MCPIN" | $BIN mcp > $TD/mcp.out
grep -q '"serverInfo"' $TD/mcp.out && grep -q '"rsenv_list"' $TD/mcp.out && echo "mcp: initialize + tools/list OK" || { echo "FAIL: mcp handshake: $(cat $TD/mcp.out)"; exit 1; }
grep -q 'GH_TOKEN' $TD/mcp.out && echo "mcp: list returns entries OK" || { echo "FAIL: mcp list: $(cat $TD/mcp.out)"; exit 1; }
grep -q 'ghp_fake_value_123' $TD/mcp.out && { echo "FAIL: mcp leaked value"; exit 1; } || echo "mcp: no values OK"
grep -q '"rsenv_get"' $TD/mcp.out && { echo "FAIL: get tool exposed"; exit 1; } || echo "mcp: no get/resolve tool OK"
echo "--- logout (stops daemon):"
$BIN logout
for i in 1 2 3 4 5; do pgrep -f "rsenv serve" >/dev/null || break; sleep 0.5; done
pgrep -f "rsenv serve" >/dev/null && { echo "FAIL: daemon still running"; exit 1; } || echo "daemon stopped OK"
grep -q '"event":"logout"' $AUD && echo "  logout audit OK" || { echo "FAIL: logout not audited"; exit 1; }
$BIN get GH_TOKEN && { echo "FAIL: get after logout"; exit 1; } || echo "get after logout rejected OK (no daemon)"
echo "--- no-daemon 错误信息面向 agent（与 SKILL.md 口径匹配）:"
$BIN get GH_TOKEN 2>&1 | grep -q 'vault is locked.*rsenv login' && echo "agent guidance: locked → login OK" || { echo "FAIL: guidance missing: $($BIN get GH_TOKEN 2>&1)"; exit 1; }
mkdir -p $TD/empty
SENV_VAULT_DIR=$TD/empty $BIN get X 2>&1 | grep -q 'vault is not initialized.*rsenv init' && echo "agent guidance: not-init → init OK" || { echo "FAIL: not-init guidance"; exit 1; }
echo "--- info: daemon 不在时 guard_paths 照给、names 空:"
$BIN info | tee $TD/info2.json | grep -q '"entries": \[\]' && grep -q "vault.db" $TD/info2.json && echo "info: no-daemon fallback OK" || { echo "FAIL: info no-daemon: $(cat $TD/info2.json)"; exit 1; }
echo "--- daemon-down 分层守卫（守卫可用性跟着保护对象走）:"
echo "{\"command\":\"cat $TD/vault.db\"}" | $BIN parse | grep -q '"action":"reject"' && echo "file-mention guard: daemon-down 仍拒 OK" || { echo "FAIL: file-mention guard down"; exit 1; }
echo '{"command":"echo plain"}' | $BIN parse | grep -q '"action":"pass"' && echo "plain command: daemon-down 透传 OK" || { echo "FAIL: passthrough"; exit 1; }
echo "--- wrong pw rejected at daemon-start verification:"
echo "wrongpass" | $BIN login && { echo "FAIL: wrong pw accepted"; exit 1; } || echo "wrong pw rejected OK"
echo "--- relogin correct (passwd 已换成 newpass):"
echo "newpass" | $BIN login
[ "$($BIN get GH_TOKEN)" = "ghp_fake_value_123" ] && echo "post-relogin OK" || { echo "FAIL"; exit 1; }
echo "--- disk: no plaintext value in vault files:"
if grep -r "ghp_fake_value_123" $TD/vault.db* >/dev/null 2>&1; then echo "FAIL: plaintext on disk"; exit 1; else echo "encrypted on disk OK"; fi
# 收尾清理：末轮 relogin 会拉起 daemon（launchd 作业），测试完必须退场，否则残留进程+占用 label
$BIN logout > /dev/null && echo "cleanup: daemon stopped OK"
echo "ALL PASS"
