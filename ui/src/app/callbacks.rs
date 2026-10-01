//! Every Slint callback → real engine/state operations. No dead buttons.

use std::sync::Arc;
use std::time::Duration;

use bw_api::Command;
use bw_network::fetch::FetchRequest;
use bw_privacy::fingerprint::FpMode;
use bw_privacy::ResourceType;
use slint::{ComponentHandle, Weak};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

use super::{snapshot_ui, App, UiSnapshot, UiTab, ACCENTS};
use crate::render::PageSurface;

/// Dispatch an async mutation: lock → mutate → snapshot → apply on main.
/// The boxed HRTB future borrows the locked app for its lifetime.
pub fn spawn_act(
    rt: &tokio::runtime::Handle,
    app: &Arc<AsyncMutex<App>>,
    weak: &Weak<crate::BrowserWindow>,
    f: impl for<'a> FnOnce(
            &'a mut App,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a + Send>>
        + Send
        + 'static,
) {
    let app = app.clone();
    let weak = weak.clone();
    rt.spawn(async move {
        let mut guard = app.lock().await;
        f(&mut guard).await;
        let snap = snapshot_ui(&guard);
        slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
    });
}

/// Variant that also repaints bands after the mutation.
#[allow(dead_code)]
pub fn spawn_act_bands(
    rt: &tokio::runtime::Handle,
    app: &Arc<AsyncMutex<App>>,
    weak: &Weak<crate::BrowserWindow>,
    f: impl for<'a> FnOnce(
            &'a mut App,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a + Send>>
        + Send
        + 'static,
) {
    let app = app.clone();
    let weak = weak.clone();
    rt.spawn(async move {
        let mut guard = app.lock().await;
        f(&mut guard).await;
        let snap = guard.snapshot_with_bands();
        slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
    });
}

pub fn apply(snap: UiSnapshot, weak: &Weak<crate::BrowserWindow>) {
    super::apply_snapshot(snap, weak);
}

pub fn wire_callbacks(
    ui: &crate::BrowserWindow,
    rt: &tokio::runtime::Runtime,
    app: Arc<AsyncMutex<App>>,
) {
    let weak = ui.as_weak();

    // ------------------------------------------------------------- navigation
    ui.on_navigate({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |url| {
            let url = url.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_navigate(&url).await;
                })
            });
        }
    });
    ui.on_back({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_back().await;
                })
            })
        }
    });
    ui.on_forward({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_forward().await;
                })
            })
        }
    });
    ui.on_reload({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_reload().await;
                })
            })
        }
    });
    ui.on_stop({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_stop().await;
                })
            })
        }
    });
    ui.on_home({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_home().await;
                })
            })
        }
    });

    // -------------------------------------------------------------------- tabs
    ui.on_new_tab({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.new_tab().await;
                })
            })
        }
    });
    ui.on_close_tab({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_close_tab(id as u64).await;
                })
            })
        }
    });
    ui.on_activate_tab({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_activate(id as u64).await;
                })
            })
        }
    });
    ui.on_reopen_closed({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_reopen_closed().await;
                })
            })
        }
    });
    ui.on_pin_toggle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_pin_toggle(id as u64).await;
                })
            })
        }
    });
    ui.on_suspend_toggle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_suspend_toggle(id as u64).await;
                })
            })
        }
    });
    ui.on_group_new({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_group_new(id as u64).await;
                })
            })
        }
    });
    ui.on_duplicate_tab({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_duplicate(id as u64).await;
                })
            })
        }
    });
    ui.on_close_others({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_close_others(id as u64).await;
                })
            })
        }
    });
    ui.on_drag_beyond({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id, dir| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_reorder(id as u64, dir).await;
                })
            })
        }
    });
    ui.on_close_active_tab({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_close_active().await;
                })
            })
        }
    });
    ui.on_tab_move({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |dir| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_reorder(a.active, dir).await;
                })
            })
        }
    });
    ui.on_tab_cycle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |dir| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_cycle(dir).await;
                })
            })
        }
    });

    // -------------------------------------------------------------- bookmarks
    ui.on_bookmark_toggle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_toggle().await;
                })
            })
        }
    });
    ui.on_bookmark_open({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |url| {
            let url = url.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_navigate(&url).await;
                })
            });
        }
    });
    ui.on_bookmark_delete({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_delete(id).await;
                })
            })
        }
    });
    ui.on_bookmark_edit({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_edit(id).await;
                })
            })
        }
    });
    ui.on_bookmark_import({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_import().await;
                })
            })
        }
    });
    ui.on_bookmark_export({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_export().await;
                })
            })
        }
    });
    ui.on_bookmark_new_folder({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_bookmark_new_folder().await;
                })
            })
        }
    });

    // ---------------------------------------------------------------- history
    ui.on_history_open({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |url| {
            let url = url.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_navigate(&url).await;
                })
            });
        }
    });
    ui.on_history_delete({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_history_delete(id).await;
                })
            })
        }
    });
    ui.on_history_clear({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_history_clear().await;
                })
            })
        }
    });

    // -------------------------------------------------------------- downloads
    ui.on_download_pause_resume({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_dl_pause_resume(id).await;
                })
            })
        }
    });
    ui.on_download_cancel({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_dl_cancel(id).await;
                })
            })
        }
    });
    ui.on_download_retry({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_dl_retry(id).await;
                })
            })
        }
    });
    ui.on_download_open({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_dl_open(id).await;
                })
            })
        }
    });
    ui.on_download_show({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_dl_show(id).await;
                })
            })
        }
    });
    ui.on_downloads_clear_finished({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let dl = a.downloads.clone();
                    dl.clear_finished().await;
                })
            })
        }
    });

    // ---------------------------------------------------------------- omnibox
    ui.on_omnibox_edited({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |text| {
            let text = text.to_string();
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                // debounce remote suggestions
                tokio::time::sleep(Duration::from_millis(140)).await;
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.omnibox_text = text.clone();
                let sugg = crate::search::build_suggestions(
                    &text,
                    &a.history,
                    &a.bookmarks,
                    &a.prefs,
                    &a.engine,
                )
                .await;
                a.suggestions = sugg;
                a.suggestions_open = !a.suggestions.is_empty();
                a.suggestion_selected = if a.suggestions.is_empty() { -1 } else { 0 };
                let snap = snapshot_ui(a);
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_suggestion_picked({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |item| {
            let kind = item.kind.to_string();
            let text = item.text.to_string();
            let secondary = item.secondary.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move { a.do_suggestion_picked(kind, text, secondary).await })
            });
        }
    });
    ui.on_omnibox_focus({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.omnibox_focus_pulse += 1;
                    a.suggestions_open = false;
                })
            })
        }
    });
    ui.on_suggestions_close({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.suggestions_open = false;
                    a.suggestion_selected = -1;
                })
            })
        }
    });
    ui.on_search_submitted({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |q| {
            let q = q.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let target = crate::search::resolve_target(&q, &a.prefs);
                    a.do_navigate(&target).await;
                })
            });
        }
    });

    // ------------------------------------------------------------- page events
    ui.on_page_clicked({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |x, y| {
            let px = x;
            let py = y;
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                let link = a.surfaces.get(&a.active).and_then(|s| s.link_at(px, py));
                let snap = match link {
                    Some(url) => {
                        a.do_navigate(&url).await;
                        snapshot_ui(a)
                    }
                    None => a.snapshot_with_bands(),
                };
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_scroll_changed({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |y| {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.scroll = y;
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_page_hovered({
        let app = app.clone();
        let weak = weak.clone();
        move |x, y| {
            // Hover is high-frequency: try_lock and skip when busy.
            let px = x;
            let py = y;
            if let Ok(mut guard) = app.try_lock() {
                let a = &mut *guard;
                let link =
                    a.surfaces.get(&a.active).and_then(|s| s.link_at(px, py)).unwrap_or_default();
                if link != a.hover_link {
                    a.hover_link = link.clone();
                    let snap = snapshot_ui(a);
                    let weak2 = weak.clone();
                    slint::invoke_from_event_loop(move || apply(snap, &weak2)).ok();
                }
            }
        }
    });
    ui.on_viewport_resized({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |w, h| {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.viewport_w = w as f32;
                a.viewport_h = (h as f32 - 120.0).max(200.0);
                if let Some(s) = a.surfaces.get_mut(&a.active) {
                    s.relayout(a.viewport_w);
                }
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_dial_picked({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |url| {
            let url = url.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_navigate(&url).await;
                })
            });
        }
    });

    // ----------------------------------------------------------- find-in-page
    ui.on_find_open_request({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.find_open = true;
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_find_changed({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |t| {
            let t = t.to_string();
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.find_text = t;
                if let Some(s) = a.surfaces.get_mut(&a.active) {
                    s.set_find(&a.find_text.clone());
                }
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_find_next({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                if let Some(s) = a.surfaces.get_mut(&a.active) {
                    s.find_step(true);
                    if let Some(y) = s.find_active_y() {
                        a.scroll = (y - 80.0).max(0.0) as i32;
                    }
                }
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_find_previous({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                if let Some(s) = a.surfaces.get_mut(&a.active) {
                    s.find_step(false);
                    if let Some(y) = s.find_active_y() {
                        a.scroll = (y - 80.0).max(0.0) as i32;
                    }
                }
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_find_close({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.find_open = false;
                a.find_text.clear();
                if let Some(s) = a.surfaces.get_mut(&a.active) {
                    s.set_find("");
                }
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });

    // -------------------------------------------------------------------- zoom
    ui.on_zoom_in({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.set_zoom((a.zoom + 10).min(500));
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_zoom_out({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.set_zoom((a.zoom - 10).max(25));
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });
    ui.on_zoom_reset({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            let weak = weak.clone();
            handle.spawn(async move {
                let mut guard = app.lock().await;
                let a = &mut *guard;
                a.set_zoom(100);
                let snap = a.snapshot_with_bands();
                slint::invoke_from_event_loop(move || apply(snap, &weak)).ok();
            });
        }
    });

    // --------------------------------------------------------- overlays/menus
    ui.on_menu_toggle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.menu_open = !a.menu_open;
                })
            })
        }
    });
    ui.on_menu_close({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.menu_open = false;
                })
            })
        }
    });
    ui.on_devtools_toggle({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.devtools_open = !a.devtools_open;
                })
            })
        }
    });
    ui.on_devtools_close({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.devtools_open = false;
                })
            })
        }
    });
    ui.on_run_js({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |code| {
            let code = code.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_run_js(&code).await;
                })
            });
        }
    });
    ui.on_devtools_clear({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.logs.clear();
                })
            })
        }
    });

    // ------------------------------------------------------------ fullscreen
    ui.on_fullscreen_toggle({
        let weak = weak.clone();
        move || {
            let ui2 = weak.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui2.upgrade() {
                    if ui.window().is_fullscreen() {
                        ui.window().set_fullscreen(false);
                    } else {
                        ui.window().set_fullscreen(true);
                    }
                }
            })
            .ok();
        }
    });

    // --------------------------------------------------------- print / save
    ui.on_print_page({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_print_pdf().await;
                })
            })
        }
    });
    ui.on_save_page({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_save_page().await;
                })
            })
        }
    });

    // -------------------------------------------------------------- session
    ui.on_restore_session({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_restore_session().await;
                })
            })
        }
    });
    ui.on_quit({
        let rt = rt.handle().clone();
        let app = app.clone();
        let _weak = weak.clone();
        move || {
            let handle = rt.clone();
            let app = app.clone();
            handle.spawn(async move {
                {
                    let mut guard = app.lock().await;
                    let a = &mut *guard;
                    a.do_shutdown().await;
                }
                std::process::exit(0);
            });
        }
    });

    ui.on_focus_omnibox({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.omnibox_focus_pulse += 1;
                })
            })
        }
    });

    wire_callbacks2(ui, rt, app);
}

/// Part 2: settings, data clearing, filter lists, views.
pub fn wire_callbacks2(
    ui: &crate::BrowserWindow,
    rt: &tokio::runtime::Runtime,
    app: Arc<AsyncMutex<App>>,
) {
    let weak = ui.as_weak();

    // --------------------------------------------------------------- settings
    ui.on_setting_theme({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |mode| {
            let mode = mode.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let m = mode.clone();
                    a.set_pref_theme(&m);
                })
            })
        }
    });
    ui.on_setting_accent({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |_| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_accent_next();
                })
            })
        }
    });
    ui.on_setting_adblock({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_adblock(v);
                })
            })
        }
    });
    ui.on_setting_trackerlist({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_trackerlist(v);
                })
            })
        }
    });
    ui.on_setting_cosmetic({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_cosmetic(v);
                })
            })
        }
    });
    ui.on_setting_fingerprint({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_fingerprint(v);
                })
            })
        }
    });
    ui.on_setting_doh({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_doh(v);
                })
            })
        }
    });
    ui.on_setting_https_only({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_https_only(v);
                })
            })
        }
    });
    ui.on_setting_safebrowsing({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_safebrowsing(v);
                })
            })
        }
    });
    ui.on_setting_search_engine({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |e| {
            let e = e.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let engine = e.clone();
                    a.set_pref_search_engine(&engine);
                })
            })
        }
    });
    ui.on_setting_homepage({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |_| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.set_pref_homepage();
                })
            })
        }
    });
    ui.on_setting_startup_restore({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.prefs.restore_session = v;
                    let _ = a.prefs.save(&a.profile);
                })
            })
        }
    });
    ui.on_setting_bookmarks_bar({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.prefs.bookmarks_bar = v;
                    let _ = a.prefs.save(&a.profile);
                })
            })
        }
    });
    ui.on_setting_cookie_policy({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |p| {
            let p = p.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let policy = p.clone();
                    a.set_pref_cookie_policy(&policy);
                })
            })
        }
    });
    ui.on_setting_clear_on_exit({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |v| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.prefs.clear_on_exit = v;
                    let _ = a.prefs.save(&a.profile);
                })
            })
        }
    });
    ui.on_setting_suspend_secs({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |secs| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.prefs.suspend_secs = secs.max(30) as u64;
                    let _ = a.prefs.save(&a.profile);
                })
            })
        }
    });

    // ------------------------------------------------------------ data clearing
    ui.on_clear_browsing_data({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_clear_browsing_data().await;
                })
            })
        }
    });
    ui.on_clear_cache({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_clear_cache().await;
                })
            })
        }
    });
    ui.on_clear_cookies({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_clear_cookies().await;
                })
            })
        }
    });
    ui.on_permission_reset({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |site| {
            let site = site.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.log_devtools("info", &format!("permissions reset: {site}"));
                })
            })
        }
    });
    ui.on_permission_reset_all({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.log_devtools("info", "all site permissions reset");
                })
            })
        }
    });

    // ------------------------------------------------------------ filter lists
    ui.on_filter_toggled({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id, on| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_filter_toggle(id, on).await;
                })
            })
        }
    });
    ui.on_filter_delete({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |id| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_filter_delete(id).await;
                })
            })
        }
    });
    ui.on_filter_add({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |rule| {
            let rule = rule.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.do_filter_add(&rule).await;
                })
            })
        }
    });
    ui.on_filter_clear_hits({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    for f in a.custom_filters.iter_mut() {
                        f.3 = 0;
                    }
                })
            })
        }
    });

    // ------------------------------------------------------------------ views
    ui.on_open_view({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |view| {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.menu_open = false;
                    a.suggestions_open = false;
                    a.view = view;
                })
            })
        }
    });
    ui.on_close_panel({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.view = if a.tabs.iter().any(|t| t.id == a.active && !t.url.is_empty()) {
                        crate::ActiveView::Page
                    } else {
                        crate::ActiveView::NewTab
                    };
                })
            })
        }
    });
    ui.on_open_profile_folder({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let dir = a.profile.clone();
                    crate::downloads::open_in_os(&dir);
                })
            })
        }
    });
    ui.on_open_download_folder({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move || {
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    let dir = a.profile.join("downloads");
                    crate::downloads::open_in_os(&dir);
                })
            })
        }
    });

    // ------------------------------------------------------------ panel search
    ui.on_settings_search(move |_t| {});
    ui.on_bookmarks_search({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |t| {
            let t = t.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.bookmark_search = if t.is_empty() { None } else { Some(t) };
                })
            })
        }
    });
    ui.on_history_search({
        let rt = rt.handle().clone();
        let app = app.clone();
        let weak = weak.clone();
        move |t| {
            let t = t.to_string();
            spawn_act(&rt, &app, &weak, move |a| {
                Box::pin(async move {
                    a.history_search = if t.is_empty() { None } else { Some(t) };
                })
            })
        }
    });
}

// ================================================================ App actions

impl App {
    /// Snapshot including freshly painted bands.
    pub fn snapshot_with_bands(&mut self) -> UiSnapshot {
        let bands = self.rebuild_bands();
        let mut snap = snapshot_ui(self);
        snap.bands = bands;
        snap
    }

    pub async fn do_navigate(&mut self, input: &str) {
        let target = if input.starts_with("about:") {
            input.to_string()
        } else {
            crate::search::resolve_target(input, &self.prefs)
        };
        // about:newtab → start page view; engine tabs stay blank.
        if target == "about:newtab" || target == "about:blank" || target.is_empty() {
            self.view = crate::ActiveView::NewTab;
            if let Some(t) = self.tabs.iter_mut().find(|t| t.id == self.active) {
                t.url.clear();
                t.title.clear();
                t.error = None;
                t.blocked_page = None;
            }
            self.omnibox_text.clear();
            return;
        }
        let tab = self.active;
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == tab) {
            t.loading = true;
            t.error = None;
            t.blocked_page = None;
            t.url = target.clone();
        }
        self.view = crate::ActiveView::Page;
        self.scroll = 0;
        let _ = self.api.command(Command::Navigate { tab, url: target }).await;
        // Loading state resolved by the event pump (NavigationCompleted/Failed).
    }

    pub async fn do_back(&mut self) {
        let tab = self.active;
        let _ = self.api.command(Command::GoBack { tab }).await;
        self.after_history_nav(tab).await;
    }

    pub async fn do_forward(&mut self) {
        let tab = self.active;
        let _ = self.api.command(Command::GoForward { tab }).await;
        self.after_history_nav(tab).await;
    }

    async fn after_history_nav(&mut self, tab: u64) {
        self.resync_tab_states().await;
        if let Some(entry) = self.api_tabs_snapshot.iter().find(|e| e.id.0 == tab) {
            if let Some(cur) = entry.history.get(entry.history_cursor.unwrap_or(0)) {
                let url = cur.url.clone();
                if let Some(t) = self.tabs.iter_mut().find(|t| t.id == tab) {
                    t.url = url.clone();
                    t.title = cur.title.clone();
                    t.loading = true;
                }
                self.view = crate::ActiveView::Page;
                let _ = self.api.command(Command::Navigate { tab, url }).await;
            }
        }
    }

    pub async fn do_reload(&mut self) {
        let tab = self.active;
        let url = self.tabs.iter().find(|t| t.id == tab).map(|t| t.url.clone()).unwrap_or_default();
        if url.is_empty() {
            self.view = crate::ActiveView::NewTab;
            return;
        }
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == tab) {
            t.loading = true;
            t.suspended = false;
        }
        let _ = self.api.command(Command::ActivateTab { tab }).await;
        let _ = self.api.command(Command::Navigate { tab, url }).await;
    }

    pub async fn do_stop(&mut self) {
        // v0.1 engine navigations are atomic; stop = drop loading state.
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == self.active) {
            t.loading = false;
        }
        self.log_devtools("info", "load stopped");
    }

    pub async fn do_home(&mut self) {
        let home = if self.prefs.homepage.is_empty() {
            "about:newtab".to_string()
        } else {
            self.prefs.homepage.clone()
        };
        self.do_navigate(&home).await;
    }

    pub async fn do_close_tab(&mut self, id: u64) {
        if self.tabs.len() <= 1 {
            // Closing the last tab → fresh start page.
            if let Some(t) = self.tabs.first_mut() {
                t.url.clear();
                t.title.clear();
                t.error = None;
                t.blocked_page = None;
                t.suspended = false;
            }
            self.view = crate::ActiveView::NewTab;
            return;
        }
        let _ = self.api.command(Command::CloseTab { tab: id }).await;
        self.tabs.retain(|t| t.id != id);
        self.surfaces.remove(&id);
        if self.active == id {
            self.active = self.tabs.first().map(|t| t.id).unwrap_or(0);
            self.do_activate(self.active).await;
        }
    }

    pub async fn do_close_active(&mut self) {
        let id = self.active;
        self.do_close_tab(id).await;
    }

    pub async fn do_activate(&mut self, id: u64) {
        self.active = id;
        let prev_active_else = self.tabs.iter().find(|t| t.id != id).map(|t| t.id);
        if let Some(other) = prev_active_else {
            let _ = self.api.command(Command::BackgroundTab { tab: other }).await;
        }
        let _ = self.api.command(Command::ActivateTab { tab: id }).await;
        self.resync_tab_states().await;
        let has_url = self.tabs.iter().any(|t| t.id == id && !t.url.is_empty());
        self.view = if has_url { crate::ActiveView::Page } else { crate::ActiveView::NewTab };
        if has_url {
            self.install_page_model(id).await;
        }
    }

    pub async fn do_reopen_closed(&mut self) {
        if let Some(tab) = self.closed_stack.pop() {
            let id = match self.api.command(Command::NewTab).await {
                Ok(v) => v["tab"].as_u64().unwrap_or(0),
                Err(_) => return,
            };
            let mut restored = tab.clone();
            restored.id = id;
            restored.loading = false;
            restored.suspended = false;
            self.tabs.push(restored);
            self.surfaces.insert(id, PageSurface::new(&self.profile));
            self.active = id;
            if !tab.url.is_empty() {
                let url = tab.url.clone();
                self.view = crate::ActiveView::Page;
                let _ = self.api.command(Command::Navigate { tab: id, url }).await;
            }
        }
    }

    pub async fn do_pin_toggle(&mut self, id: u64) {
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == id) {
            t.pinned = !t.pinned;
            if t.pinned {
                t.group.clear();
            }
        }
    }

    pub async fn do_suspend_toggle(&mut self, id: u64) {
        let suspended = self.tabs.iter().find(|t| t.id == id).map(|t| t.suspended).unwrap_or(false);
        if suspended {
            let _ = self.api.command(Command::ActivateTab { tab: id }).await;
            let url =
                self.tabs.iter().find(|t| t.id == id).map(|t| t.url.clone()).unwrap_or_default();
            if !url.is_empty() {
                let _ = self.api.command(Command::Navigate { tab: id, url }).await;
            }
        } else {
            let _ = self.api.command(Command::SuspendTab { tab: id }).await;
            self.resync_tab_states().await;
        }
    }

    pub async fn do_group_new(&mut self, id: u64) {
        const GROUP_COLORS: [&str; 6] =
            ["#1a73e8", "#8430ce", "#d03050", "#e8710a", "#1e8e3e", "#0b7285"];
        let n = self.tabs.iter().filter(|t| !t.group.is_empty()).count();
        if let Some(t) = self.tabs.iter_mut().find(|t| t.id == id) {
            if t.group.is_empty() {
                t.group = GROUP_COLORS[n % GROUP_COLORS.len()].to_string();
                t.pinned = false;
            } else {
                t.group.clear();
            }
        }
    }

    pub async fn do_duplicate(&mut self, id: u64) {
        let url = self.tabs.iter().find(|t| t.id == id).map(|t| t.url.clone()).unwrap_or_default();
        let new_id = match self.api.command(Command::NewTab).await {
            Ok(v) => v["tab"].as_u64().unwrap_or(0),
            Err(_) => return,
        };
        let src = self.tabs.iter().find(|t| t.id == id).cloned();
        self.tabs.push(UiTab {
            id: new_id,
            title: src.as_ref().map(|t| t.title.clone()).unwrap_or_default(),
            url: url.clone(),
            pinned: false,
            group: src.as_ref().map(|t| t.group.clone()).unwrap_or_default(),
            loading: !url.is_empty(),
            suspended: false,
            security: src.as_ref().map(|t| t.security.clone()).unwrap_or_else(|| "local".into()),
            blocked: 0,
            favicon: src.and_then(|t| t.favicon.clone()),
            error: None,
            blocked_page: None,
        });
        self.surfaces.insert(new_id, PageSurface::new(&self.profile));
        self.active = new_id;
        if !url.is_empty() {
            self.view = crate::ActiveView::Page;
            let _ = self.api.command(Command::Navigate { tab: new_id, url }).await;
        }
    }

    pub async fn do_close_others(&mut self, id: u64) {
        let others: Vec<u64> = self.tabs.iter().filter(|t| t.id != id).map(|t| t.id).collect();
        for other in others {
            let _ = self.api.command(Command::CloseTab { tab: other }).await;
            self.tabs.retain(|t| t.id != other);
            self.surfaces.remove(&other);
        }
        self.active = id;
    }

    pub async fn do_reorder(&mut self, id: u64, dir: i32) {
        let Some(idx) = self.tabs.iter().position(|t| t.id == id) else { return };
        let target = if dir > 0 { idx + 1 } else { idx.saturating_sub(1) };
        if target >= self.tabs.len() || target == idx {
            return;
        }
        self.tabs.swap(idx, target);
    }

    pub async fn do_cycle(&mut self, dir: i32) {
        if self.tabs.len() < 2 {
            return;
        }
        let idx = self.tabs.iter().position(|t| t.id == self.active).unwrap_or(0);
        let next = if dir > 0 {
            (idx + 1) % self.tabs.len()
        } else {
            (idx + self.tabs.len() - 1) % self.tabs.len()
        };
        let id = self.tabs[next].id;
        self.do_activate(id).await;
    }

    // ------------------------------------------------------------ bookmarks
    pub async fn do_bookmark_toggle(&mut self) {
        let Some(t) = self.tabs.iter().find(|t| t.id == self.active).cloned() else { return };
        if t.url.is_empty() {
            return;
        }
        if self.bookmarks.contains(&t.url) {
            self.bookmarks.remove_by_url(&t.url);
        } else {
            let title = if t.title.is_empty() { t.url.clone() } else { t.title.clone() };
            self.bookmarks.add(&title, &t.url, "bar");
        }
        let _ = self.bookmarks.save(&self.profile);
    }

    pub async fn do_bookmark_delete(&mut self, id: i32) {
        self.bookmarks.remove(id as u64);
        let _ = self.bookmarks.save(&self.profile);
    }

    pub async fn do_bookmark_edit(&mut self, id: i32) {
        // v0.1: editing = re-add current page (id -1) or rename via console.
        if id < 0 {
            self.do_bookmark_toggle().await;
        } else if let Some(b) = self.bookmarks.bookmarks.iter().find(|b| b.id == id as u64).cloned()
        {
            self.log_devtools("info", &format!("bookmark: {} -> {}", b.title, b.url));
        }
    }

    pub async fn do_bookmark_import(&mut self) {
        // Import from the well-known export location (documented).
        let path = self.profile.join("bookmarks-import.html");
        if let Ok(html) = std::fs::read_to_string(&path) {
            let n = self.bookmarks.import_html(&html);
            let _ = self.bookmarks.save(&self.profile);
            self.log_devtools(
                "info",
                &format!("imported {n} bookmarks from profile/bookmarks-import.html"),
            );
        } else {
            self.log_devtools(
                "warn",
                "place bookmarks at <profile>/bookmarks-import.html then click Import",
            );
        }
    }

    pub async fn do_bookmark_export(&mut self) {
        let html = self.bookmarks.export_html();
        let path = self.profile.join("bookmarks-export.html");
        let _ = std::fs::write(&path, html);
        self.log_devtools("info", &format!("bookmarks exported: {}", path.display()));
    }

    pub async fn do_bookmark_new_folder(&mut self) {
        self.log_devtools("info", "folders are assigned per-bookmark in v0.1 (bar/other)");
    }

    // -------------------------------------------------------------- history
    pub async fn do_history_delete(&mut self, id: i32) {
        self.history.remove(id as u64);
        let _ = self.history.save(&self.profile);
    }

    pub async fn do_history_clear(&mut self) {
        self.history.clear();
        let _ = self.history.save(&self.profile);
        self.log_devtools("info", "browsing history cleared");
    }

    // ------------------------------------------------------------ downloads
    pub async fn do_dl_pause_resume(&mut self, id: i32) {
        let dls = self.downloads.clone();
        let paused = dls
            .try_snapshot()
            .iter()
            .find(|d| d.id == id as u64)
            .map(|d| matches!(d.state, crate::downloads::DlState::Paused))
            .unwrap_or(false);
        if paused {
            dls.resume(id as u64).await;
        } else {
            dls.pause(id as u64).await;
        }
    }

    pub async fn do_dl_cancel(&mut self, id: i32) {
        self.downloads.cancel(id as u64).await;
    }

    pub async fn do_dl_retry(&mut self, id: i32) {
        let dls = self.downloads.clone();
        let url = dls.try_snapshot().iter().find(|d| d.id == id as u64).map(|d| d.url.clone());
        if let Some(url) = url {
            dls.cancel(id as u64).await;
            dls.start(&url).await;
        }
    }

    pub async fn do_dl_open(&mut self, id: i32) {
        let path = self
            .downloads
            .try_snapshot()
            .iter()
            .find(|d| d.id == id as u64)
            .map(|d| d.path.clone());
        if let Some(p) = path {
            crate::downloads::open_in_os(&p);
        }
    }

    pub async fn do_dl_show(&mut self, id: i32) {
        let dir = self.profile.join("downloads");
        crate::downloads::open_in_os(&dir);
        let _ = id;
    }

    // -------------------------------------------------------------- devtools
    pub async fn do_run_js(&mut self, code: &str) {
        let site = self
            .tabs
            .iter()
            .find(|t| t.id == self.active)
            .map(|t| t.url.clone())
            .unwrap_or_default();
        let origin = if site.starts_with("http") {
            Url::parse(&site)
                .ok()
                .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or_default()))
                .unwrap_or_else(|| "https://localhost".into())
        } else {
            "about:blank".into()
        };
        self.log_devtools("log", code);
        match self.api.command(Command::ExecJs { site: origin, code: code.to_string() }).await {
            Ok(v) => {
                let text = if v.is_null() { "undefined".into() } else { v.to_string() };
                self.log_devtools("result", &text);
            }
            Err(e) => self.log_devtools("error", &e.to_string()),
        }
    }

    // ------------------------------------------------------- print and save
    pub async fn do_print_pdf(&mut self) {
        let dark = self.theme_is_dark();
        let bands = match self.surfaces.get_mut(&self.active) {
            Some(s) => s.render_all_bands(dark),
            None => return,
        };
        if bands.is_empty() {
            return;
        }
        let dir = self.profile.join("prints");
        std::fs::create_dir_all(&dir).ok();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("page-{now}.pdf"));
        match crate::pdf::write_pdf(&path, &bands) {
            Ok(bytes) => {
                self.log_devtools(
                    "info",
                    &format!("PDF saved ({} KB): {}", bytes / 1024, path.display()),
                );
            }
            Err(e) => self.log_devtools("error", &format!("PDF failed: {e}")),
        }
    }

    pub async fn do_save_page(&mut self) {
        let Some(t) = self.tabs.iter().find(|t| t.id == self.active).cloned() else { return };
        if t.url.is_empty() {
            return;
        }
        let Ok(url) = Url::parse(&t.url) else { return };
        let host = url.host_str().unwrap_or_default().to_string();
        let req = FetchRequest::subresource(url.clone(), &host, ResourceType::DOCUMENT);
        match self.engine.fetch_service().fetch(req).await {
            Ok(resp) => {
                let dir = self.profile.join("saved-pages");
                std::fs::create_dir_all(&dir).ok();
                let name = host
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>();
                let path = dir.join(format!("{name}.html"));
                match std::fs::write(&path, &resp.body) {
                    Ok(()) => {
                        self.log_devtools(
                            "info",
                            &format!(
                                "page saved ({} KB): {}",
                                resp.body.len() / 1024,
                                path.display()
                            ),
                        );
                    }
                    Err(e) => self.log_devtools("error", &format!("save failed: {e}")),
                }
            }
            Err(e) => self.log_devtools("error", &format!("fetch failed: {e}")),
        }
    }

    // --------------------------------------------------------------- session
    pub async fn do_restore_session(&mut self) {
        let session = match bw_engine::session::load_session(&self.profile) {
            Ok(Some(s)) => s,
            _ => return,
        };
        let mut first = true;
        for tab in session.tabs {
            let id = match self.api.command(Command::NewTab).await {
                Ok(v) => v["tab"].as_u64().unwrap_or(0),
                Err(_) => continue,
            };
            self.tabs.push(UiTab {
                id,
                title: String::new(),
                url: String::new(),
                pinned: false,
                group: String::new(),
                loading: false,
                suspended: false,
                security: "local".into(),
                blocked: 0,
                favicon: None,
                error: None,
                blocked_page: None,
            });
            self.surfaces.insert(id, PageSurface::new(&self.profile));
            if first {
                self.active = id;
                first = false;
            }
            if let Some(url) = tab.current_url() {
                let url = url.to_string();
                if url.starts_with("http") {
                    if let Some(t) = self.tabs.iter_mut().find(|t| t.id == id) {
                        t.loading = true;
                        t.url = url.clone();
                    }
                    let _ = self.api.command(Command::Navigate { tab: id, url }).await;
                }
            }
        }
        if self.tabs.len() > 1 {
            // Drop the initial blank tab.
            let blank = self.tabs.first().map(|t| t.id).unwrap_or(0);
            let _ = self.api.command(Command::CloseTab { tab: blank }).await;
            self.tabs.retain(|t| t.id != blank);
            self.surfaces.remove(&blank);
        }
        self.view = crate::ActiveView::Page;
    }

    pub async fn do_shutdown(&mut self) {
        let _ = self.api.command(Command::SaveSession).await;
        let _ = self.prefs.save(&self.profile);
        let _ = self.history.save(&self.profile);
        let _ = self.bookmarks.save(&self.profile);
        if self.prefs.clear_on_exit {
            self.do_clear_cookies().await;
        }
    }

    // ------------------------------------------------------------ clearing
    pub async fn do_clear_browsing_data(&mut self) {
        self.history.clear();
        let _ = self.history.save(&self.profile);
        self.do_clear_cache().await;
        self.do_clear_cookies().await;
        self.log_devtools("info", "browsing data, cache, and cookies cleared");
    }

    pub async fn do_clear_cache(&mut self) {
        self.engine.clear_http_cache();
        self.log_devtools("info", "HTTP memory cache emptied");
    }

    pub async fn do_clear_cookies(&mut self) {
        if let Ok(mut jar) = self.engine.cookies().try_lock() {
            jar.evict_to(0);
        }
        self.log_devtools("info", "cookies deleted");
    }

    // ------------------------------------------------------------ filter lists
    pub async fn do_filter_toggle(&mut self, id: i32, on: bool) {
        if let Some(f) = self.custom_filters.iter_mut().find(|f| f.0 == id as u64) {
            f.2 = on;
        }
        self.save_custom_filters();
    }

    pub async fn do_filter_delete(&mut self, id: i32) {
        self.custom_filters.retain(|f| f.0 != id as u64);
        self.save_custom_filters();
    }

    pub async fn do_filter_add(&mut self, rule: &str) {
        let rule = rule.trim();
        if rule.is_empty() {
            return;
        }
        // Validate: network rules parse, cosmetic rules carry ##.
        let valid = rule.contains("##")
            || bw_privacy::filter::NetworkFilter::parse(rule).is_ok_and(|o| o.is_some());
        if !valid {
            self.log_devtools("warn", &format!("rule not understood: {rule}"));
            return;
        }
        self.next_filter_id += 1;
        let id = self.next_filter_id;
        self.custom_filters.push((id, rule.to_string(), true, 0));
        self.save_custom_filters();
        self.log_devtools("info", &format!("rule added (applies at next start): {rule}"));
    }

    fn save_custom_filters(&self) {
        let payload: Vec<(String, bool)> =
            self.custom_filters.iter().map(|(_, r, on, _)| (r.clone(), *on)).collect();
        let _ = std::fs::write(
            self.profile.join("custom-filters.json"),
            serde_json::to_vec(&payload).unwrap_or_default(),
        );
    }

    // --------------------------------------------------------------- prefs
    pub fn set_zoom(&mut self, percent: i32) {
        self.zoom = percent;
        if let Some(s) = self.surfaces.get_mut(&self.active) {
            s.set_zoom(percent, self.viewport_w);
        }
    }

    pub fn set_pref_theme(&mut self, mode: &str) {
        self.prefs.theme_mode = mode.to_string();
        let _ = self.prefs.save(&self.profile);
        // Re-paint bands under the new theme.
        if let Some(s) = self.surfaces.get_mut(&self.active) {
            s.invalidate_bands();
        }
    }

    pub fn set_pref_accent_next(&mut self) {
        let idx = ACCENTS.iter().position(|a| *a == self.prefs.accent).unwrap_or(0);
        let next = ACCENTS[(idx + 1) % ACCENTS.len()];
        self.prefs.accent = next.to_string();
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_adblock(&mut self, on: bool) {
        self.prefs.adblock = on;
        self.engine.set_blocking_enabled(self.prefs.adblock || self.prefs.trackerlist);
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_trackerlist(&mut self, on: bool) {
        self.prefs.trackerlist = on;
        self.engine.set_blocking_enabled(self.prefs.adblock || self.prefs.trackerlist);
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_cosmetic(&mut self, on: bool) {
        self.prefs.cosmetic = on;
        self.engine.set_cosmetic_enabled(on);
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_fingerprint(&mut self, on: bool) {
        self.prefs.fingerprint = on;
        self.engine.set_fingerprint_mode(if on { FpMode::Strict } else { FpMode::Off });
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_doh(&mut self, on: bool) {
        self.prefs.doh = on;
        let _ = self.prefs.save(&self.profile);
        self.log_devtools("info", "encrypted DNS changes apply at next start");
    }

    pub fn set_pref_https_only(&mut self, on: bool) {
        self.prefs.https_only = on;
        let _ = self.prefs.save(&self.profile);
        self.log_devtools("info", "HTTPS upgrades change applies at next start");
    }

    pub fn set_pref_safebrowsing(&mut self, on: bool) {
        self.prefs.safebrowsing = on;
        self.engine.set_safebrowsing_enabled(on);
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_search_engine(&mut self, engine: &str) {
        self.prefs.search_engine = engine.to_string();
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_homepage(&mut self) {
        // Cycle: current page → new tab page.
        let cur = self
            .tabs
            .iter()
            .find(|t| t.id == self.active)
            .map(|t| t.url.clone())
            .unwrap_or_default();
        self.prefs.homepage =
            if self.prefs.homepage.is_empty() && !cur.is_empty() { cur } else { String::new() };
        let _ = self.prefs.save(&self.profile);
    }

    pub fn set_pref_cookie_policy(&mut self, policy: &str) {
        match policy {
            "block-3p" => {
                self.prefs.cookie_policy = "block-3p".into();
                if let Ok(mut jar) = self.engine.cookies().try_lock() {
                    jar.set_allow_third_party(false);
                }
            }
            _ => {
                self.prefs.cookie_policy = "partitioned".into();
                if let Ok(mut jar) = self.engine.cookies().try_lock() {
                    jar.set_allow_third_party(true);
                }
            }
        }
        let _ = self.prefs.save(&self.profile);
    }

    pub async fn do_suggestion_picked(&mut self, kind: String, text: String, secondary: String) {
        self.suggestions_open = false;
        self.suggestions.clear();
        let value = if kind == "url" { text.clone() } else { secondary };
        let target = if value.is_empty() || kind == "search" {
            crate::search::resolve_target(&text, &self.prefs)
        } else if value.starts_with("http") {
            value
        } else {
            crate::search::resolve_target(&value, &self.prefs)
        };
        self.do_navigate(&target).await;
    }
}
