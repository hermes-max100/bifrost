#!/usr/bin/env bash
# Live test for bifrost-breaker on the VPS. Run ON the VPS as root.
# Prints PASS/FAIL per assertion plus raw evidence. Exit 0 only if all pass.
set -u
B=http://100.83.164.96:8082
FAIL=0
say() { echo "== $*"; }
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "PASS: $1 (=$3)"; else echo "FAIL: $1 expected=$2 actual=$3"; FAIL=1; fi
}
cc() { # chat completion via breaker; prints "HTTP:<code> <time>s <body-snippet>"
  local model="$1"
  local t0 t1 code body
  t0=$(date +%s.%N)
  body=$(curl -s -m 15 -w "\nHTTP:%{http_code}" -X POST "$B/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"$model\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":8}")
  code=$(echo "$body" | grep -o 'HTTP:[0-9]*' | cut -d: -f2)
  t1=$(date +%s.%N)
  echo "$code $(awk -v a="$t1" -v b="$t0" 'BEGIN{printf "%.3f", a-b}')s $(echo "$body" | head -c 160 | tr '\n' ' ')"
}
state() { curl -s -m 5 "$B/breaker/state/$1" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['state'], 'failures=', d['consecutive_failures'], 'fast_fails=', d['total_fast_fails'], 'reqs=', d['total_requests'])"; }

say "0. stub up (mode=fail), breaker reset"
echo fail > /tmp/breaker-test-mode
pkill -f flap_stub.py 2>/dev/null; sleep 1
nohup python3 /opt/bifrost-breaker/flap_stub.py > /tmp/flap_stub.log 2>&1 &
sleep 1
curl -s -m 5 http://127.0.0.1:18099/health; echo
curl -s -m 5 -X POST "$B/breaker/reset" -H 'Content-Type: application/json' -d '{}'; echo

say "A. dead endpoint test/dead -> 127.0.0.1:9 (connection refused)"
echo "req1: $(cc test/dead)"
echo "req2: $(cc test/dead)"
echo "req3: $(cc test/dead)"
echo "state after 3 failures: $(state test-dead)"
check "A1 breaker open after 3 failures" "open" "$(curl -s $B/breaker/state/test-dead | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
echo "req4 (expect 503 fast-fail, no upstream attempt): $(cc test/dead)"
CODE4=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "$B/v1/chat/completions" -H 'Content-Type: application/json' -d '{"model":"test/dead","messages":[{"role":"user","content":"hi"}],"max_tokens":8}')
check "A2 4th request fast-fails 503" "503" "$CODE4"
FF=$(curl -s $B/breaker/state/test-dead | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_fast_fails"])')
check "A3 fast-fail counter >= 2" "yes" "$([ "$FF" -ge 2 ] && echo yes || echo no)"

say "B. cooldown + half-open probe fails -> re-opens (cooldown 5s)"
sleep 6
echo "probe after cooldown (expect 502, breaker re-opens): $(cc test/dead)"
check "B1 breaker open again after failed probe" "open" "$(curl -s $B/breaker/state/test-dead | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"

say "C. flap recovery test/flap: fail 3x -> open, then mode=ok, probe closes"
echo "req1: $(cc test/flap)"
echo "req2: $(cc test/flap)"
echo "req3: $(cc test/flap)"
check "C1 flap breaker open" "open" "$(curl -s $B/breaker/state/test-flap | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
echo ok > /tmp/breaker-test-mode
sleep 6
echo "probe after cooldown (expect 200 STUB-OK): $(cc test/flap)"
check "C2 flap breaker closed after successful probe" "closed" "$(curl -s $B/breaker/state/test-flap | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
echo "next request (expect 200): $(cc test/flap)"

say "D. slow endpoint test/slow: 2s timeout, threshold 2 -> open, then fast-fail"
echo slow > /tmp/breaker-test-mode
echo "req1 (expect ~2s then 502): $(cc test/slow)"
echo "req2 (expect ~2s then 502): $(cc test/slow)"
check "D1 slow breaker open after 2 timeouts" "open" "$(curl -s $B/breaker/state/test-slow | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
T0=$(date +%s.%N); CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST "$B/v1/chat/completions" -H 'Content-Type: application/json' -d '{"model":"test/slow","messages":[{"role":"user","content":"hi"}],"max_tokens":8}'); T1=$(date +%s.%N)
DT=$(awk -v a="$T1" -v b="$T0" 'BEGIN{printf "%.3f", a-b}')
check "D2 fast-fail is 503" "503" "$CODE"
echo "D2 fast-fail took ${DT}s (must be < 1s, vs 2s timeout + 5s upstream sleep)"
check "D3 fast-fail under 1s" "yes" "$(awk -v d="$DT" 'BEGIN{print (d < 1) ? "yes" : "no"}')"

say "E. real Bifrost traffic unaffected (groq via breaker + direct)"
echo "via breaker: $(cc groq/qwen/qwen3.8-27b)"
echo "direct bifrost: $(curl -s -m 30 -w ' HTTP:%{http_code}' -X POST http://100.83.164.96:8081/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"groq/qwen/qwen3.8-27b","messages":[{"role":"user","content":"Reply with exactly OK"}],"max_tokens":8}' | head -c 200)"; echo
check "E1 groq breaker stays closed" "closed" "$(curl -s $B/breaker/state/groq | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
check "E2 groq breaker zero failures" "0" "$(curl -s $B/breaker/state/groq | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_failures"])')"

say "F. metrics endpoint"
curl -s -m 5 "$B/metrics" | grep -E 'test-dead|groq' | head -12

say "G. breaker still serving health + bifrost untouched"
curl -s -m 5 "$B/health"; echo
curl -s -m 5 http://100.83.164.96:8081/health; echo
systemctl is-active bifrost.service bifrost-breaker.service

echo
if [ "$FAIL" = 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit $FAIL
