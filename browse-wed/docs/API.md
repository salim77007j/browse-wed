# browse-wed Engine — UI Integration Guide

The engine exposes exactly one contract: [`bw-api`](../api/src/lib.rs).
Any UI — Rust-native, Electron, Tauri, a webview host, even a remote
debugger — binds through it. This document is the full contract.

## Startup

```rust
use bw_api::{BrowserApi, EngineOptions};

let options = EngineOptions {
    profile_dir: Some("/path/to/profile".into()),
    privacy_preset: true,            // DoH + HTTPS upgrades + starter lists
    doh_url: Some("https://dns.quad9.net/dns-query".into()),
    background_suspend_secs: 300,
    max_active_tabs: 16,
};
let api = BrowserApi::start(options).await?;
```

`EngineOptions` is `serde`-serializable — a JSON-config-driven UI needs no
Rust types at all:

```json
{ "profile_dir": "/path/to/profile", "privacy_preset": true,
  "background_suspend_secs": 300, "max_active_tabs": 16 }
```

## The command loop

Commands are plain JSON:

```json
{ "type": "navigate", "tab": 1, "url": "https://example.com" }
```

Send them through `BrowserApi::command` (Rust) or any IPC bridge you build
on top of it. Every reply is a JSON value.

| Command | Payload | Reply | Events fired |
|---|---|---|---|
| `new_tab` | — | `{"tab": <id>}` | `tab_opened` |
| `close_tab` | `tab` | `{"closed": true}` | `tab_closed` |
| `navigate` | `tab`, `url` | `{"navigated": true}` | `navigation_completed` (or `navigation_failed`) |
| `go_back` / `go_forward` | `tab` | `{"went_back": true}` | `navigation_completed` |
| `background_tab` | `tab` | `{"backgrounded": true}` | — |
| `activate_tab` | `tab` | `{"activated": true}` | `navigation_completed` (if waking) |
| `suspend_tab` | `tab` | `{"suspended": true}` | — |
| `sweep_idle` | — | `{"suspended": <n>}` | `tabs_suspended` (n > 0), `memory_pressure` (on change) |
| `save_session` | — | `{"saved": true}` | `session_saved` |
| `exec_js` | `site`, `code` | the script's value as JSON | — |

## Events

Subscribe *before* issuing commands (the broadcast ring holds 1024 events;
late subscribers miss history by design):

```rust
let mut events = api.subscribe();
while let Ok(event) = events.recv().await {
    match event { /* render */ }
}
```

Event shapes (all carry `"type"`):

```json
{ "type": "navigation_completed", "tab": 1,
  "outcome": { "final_url": "https://example.com/", "status": 200,
               "title": "Example", "body_len": 125640,
               "protocol": "h2", "from_cache": false,
               "page": { "nodes": 412, "elements": 98, "scripts": 3,
                          "stylesheets": 2, "images": 9 },
               "cosmetic_hidden": 4, "blocked": 0, "total_ms": 184.2 } }

{ "type": "tabs_suspended", "count": 7 }
{ "type": "memory_pressure", "level": "moderate" }
{ "type": "session_saved" }
```

`protocol` is one of `http/1.1`, `h2`, `h3`, `cache`, `synthetic`,
`local`. `blocked` is 1 when policy served a synthetic response — the
event still fires, so the UI can render its blocked-page interstitial.

## Polling state (rendering a tab list)

```rust
let tabs: Vec<TabEntry> = api.tabs().await;
// TabEntry: { id, state, history, history_cursor, backgrounded_at,
//             blocked_count, site }
// state: "blank" | "loading" | "loaded" | "backgrounded" | "suspended"
```

```rust
let stats = api.stats().await;
// cold-start timings, memory snapshot + pressure, tab counts,
// cache budgets, JS heap totals, DNS/policy counters
```

## Background services

`api.start_background_services()` spawns the 30-second idle sweeper
(suspension + budget refresh + pressure events). Returns a `JoinHandle`;
drop or abort it for manual control (kiosk modes, tests).

## Rendering contract (v0.1)

The engine hands the UI page *data*, not pixels:

* `navigation_completed.outcome.page` — node/element/script/style/image
  counts per page,
* `cosmetic_hidden` — how many elements privacy filtering hides
  (renderers should skip painting them entirely),
* the DOM itself lives in the engine; `bw-engine`'s `page` module exposes
  the parsed `Document` for Rust-native renderers that want to walk it.

A pixel-producing renderer is the v0.2 track; the engine's rendering crate
(tokenizer, DOM, CSS cascade, fonts) is the foundation it builds on.

## Sessions

Sessions persist atomically to `<profile>/session.json` on `save_session`.
On startup the UI decides what to restore:

```rust
let session = bw_engine::session::load_session(profile_dir)?;
for tab in session.tabs {
    let id = api.command(Command::NewTab).await?;
    if let Some(url) = tab.current_url() {
        api.command(Command::Navigate { tab: id, url: url.into() }).await?;
    }
}
```

Suspended tabs restore as re-navigations — usually HTTP-cache hits.

## Error contract

Every failure is an `ApiError` with a stable tag:

| Tag | Meaning | UI action |
|---|---|---|
| `invalid_command` | malformed payload | log; do not crash |
| `engine_start` | profile/storage/network init failure | fatal dialog |
| `no_such_tab` | tab id unknown | refresh tab list |
| `navigation` | bad URL / transport / timeout | error page |
| `js` | script exception (timeout, memory cap) | devtools only |
| `session` | persistence failure | non-fatal warning |

## Minimal Tauri example

```rust
#[tauri::command]
async fn navigate(api: tauri::State<'_, ApiHandle>, tab: u64, url: String)
    -> Result<serde_json::Value, String>
{
    api.0.command(bw_api::Command::Navigate { tab, url })
        .await
        .map_err(|e| e.to_string())
}
```

The same shape works over Electron IPC, WebSocket, or stdin/stdout JSON
lines — the command and event types are the entire protocol.
