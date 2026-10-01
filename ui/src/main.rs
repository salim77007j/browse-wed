//! browse-wed browser UI — bootstrap and engine/UI bridge.

// Slint generated code uses unsafe internally; our own code stays unsafe-free.

slint::include_modules!();

mod app;
mod downloads;
mod favicon;
mod imgdata;
mod pdf;
mod prefs;
mod render;
mod search;
mod stores;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bw_ui=info,bw_engine=warn".into()),
        )
        .compact()
        .init();

    let ui = BrowserWindow::new().expect("window creation failed");
    app::run(ui);
}
