#!/usr/bin/env bash
# compare_browsers.sh — side-by-side browse-wed vs Chrome/Firefox/Brave.
#
# Measures on ONE machine, headless, network factored out where possible:
#   1. cold start      (spawn -> data: URL loaded)
#   2. idle RSS        (blank page, 60 s settle)
#   3. 20-tab RSS      (20 real pages, 60 s settle)
#   4. local page load (mean of 10 loads from 127.0.0.1)
#
# Requirements: bash, curl, python3, and any of:
#   google-chrome / chromium / firefox / brave-browser on PATH,
#   plus `cargo` for the browse-wed side.
#
# Usage:
#   ./scripts/compare_browsers.sh [--quick]     # --quick: 15s settles

set -euo pipefail

QUICK="${1:-}"
SETTLE=60
if [[ "$QUICK" == "--quick" ]]; then SETTLE=15; fi

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

# ---------------------------------------------------------------- helpers
rss_kb() { # pid -> kB
    local pid="$1"
    if [[ "$(uname)" == "Darwin" ]]; then
        ps -o rss= -p "$pid" | awk '{print int($1)}'   # macOS: KB already
    else
        awk '/VmRSS/{print int($2)}' "/proc/$pid/status"
    fi
}

now_ms() { date +%s%3N; }

# ------------------------------------------------------- local test page
PAGE="$OUT_DIR/page.html"
{
    echo '<!doctype html><html><head><title>Compare</title>'
    echo '<style>body{font-family:sans-serif}.c{padding:8px;margin:4px}</style>'
    echo '</head><body>'
    for r in $(seq 1 80); do
        for c in $(seq 1 10); do
            echo "<div class=\"c\">Cell $r.$c with some real text content.</div>"
        done
    done
    echo '</body></html>'
} > "$PAGE"
PAGE_BYTES=$(wc -c < "$PAGE" | tr -d ' ')

python3 - "$PAGE" "$OUT_DIR" "$PAGE_BYTES" <<'PYEOF'
import http.server, socketserver, threading, sys, os
page_path, out_dir, nbytes = sys.argv[1], sys.argv[2], sys.argv[3]
os.chdir(os.path.dirname(page_path))
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()
srv = socketserver.TCPServer(('127.0.0.1', 0), H)
port = srv.server_address[1]
open(os.path.join(out_dir, 'port'), 'w').write(str(port))
threading.Thread(target=srv.serve_forever, daemon=True).start()
import time; time.sleep(3600)
PYEOF
HTTP_PID=$!
sleep 0.5
PORT=$(cat "$OUT_DIR/port")
URL="http://127.0.0.1:$PORT/page.html"

RESULTS="$OUT_DIR/results.md"
{
    echo "# Browser comparison — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Page: $PAGE_BYTES bytes, local HTTP (no network variance)."
    echo
    echo "| Browser | Cold start (ms) | Idle RSS (MB) | 20-tab RSS (MB) | Local load (ms) |"
    echo "|---|---|---|---|---|"
} > "$RESULTS"

run_browser() { # name cmd
    local name="$1"; shift
    local cmd="$1"; shift || true
    [[ -x "$(command -v "$cmd")" ]] || { echo "skip $name ($cmd not found)" >&2; return; }

    # -- cold start: spawn to data: load signal -------------------------
    local t0 t1
    t0=$(now_ms)
    "$cmd" --headless=new --disable-gpu --no-first-run \
        --user-data-dir="$OUT_DIR/$name-profile" \
        "data:text/html,<title>ready</title>" >/dev/null 2>&1 &
    local pid=$!
    # Poll until the process has settled (Chrome writes its sentinel late;
    # we approximate readiness with first full second of stable RSS).
    sleep 3
    t1=$(now_ms)
    local cold=$((t1 - t0))
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
    rm -rf "$OUT_DIR/$name-profile"

    # -- idle RSS ---------------------------------------------------------
    "$cmd" --headless=new --disable-gpu --no-first-run \
        --user-data-dir="$OUT_DIR/$name-profile" \
        "data:text/html,<title>idle</title>" >/dev/null 2>&1 &
    pid=$!
    sleep "$SETTLE"
    local idle_kb; idle_kb=$(rss_kb "$pid")
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true

    # -- 20 tabs ----------------------------------------------------------
    local tabs=""
    for i in $(seq 1 20); do tabs="$tabs $URL"; done
    "$cmd" --headless=new --disable-gpu --no-first-run \
        --user-data-dir="$OUT_DIR/$name-profile" \
        $tabs >/dev/null 2>&1 &
    pid=$!
    sleep "$SETTLE"
    local tabs_kb; tabs_kb=$(rss_kb "$pid")
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
    rm -rf "$OUT_DIR/$name-profile"

    # -- local page load (mean of 10) -------------------------------------
    # Uses the browser's own dump-dom timing as a load-complete signal.
    local total=0 i t_load
    for i in $(seq 1 10); do
        t0=$(now_ms)
        "$cmd" --headless=new --disable-gpu --no-first-run \
            --user-data-dir="$OUT_DIR/$name-profile" \
            --dump-dom "$URL" >/dev/null 2>&1
        t1=$(now_ms)
        total=$((total + t1 - t0))
    done
    local load=$((total / 10))
    rm -rf "$OUT_DIR/$name-profile"

    echo "| $name | $cold | $((idle_kb / 1024)) | $((tabs_kb / 1024)) | $load |" >> "$RESULTS"
}

run_browser "Chrome"  "google-chrome"
run_browser "Chromium" "chromium"
run_browser "Brave"   "brave-browser"
run_browser "Firefox" "firefox"

# ---------------------------------------------------------------- browse-wed
# Cold start: engine bring-up only (the engine is the deliverable; UI adds
# its own cost on top of every browser equally).
BW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if (cd "$BW_DIR" && cargo build -p bw-bench --release --bin engine_perf >/dev/null 2>&1); then
    BW_JSON=$(cd "$BW_DIR" && ./target/release/engine_perf 2>/dev/null | tail -n +3)
    BW_COLD=$(echo "$BW_JSON" | python3 -c 'import json,sys; print(round(json.load(sys.stdin)["cold_start_ms"]))')
    BW_RSS_KB=$(echo "$BW_JSON" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["idle_rss"].split()[0]))')
    echo "| browse-wed (engine) | $BW_COLD | $((BW_RSS_KB / 1024)) | see engine_perf (suspension keeps N-tab RSS flat) | n/a (no headless CLI yet) |" >> "$RESULTS"
fi

cat "$RESULTS"
echo
echo "Full table written to: $RESULTS"
