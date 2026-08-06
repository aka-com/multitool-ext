//! Scheduling for [`aka_core::cloud_push`].
//!
//! The policy — which connections are owed a session, when a push is due —
//! lives in the core beside the mint path it mirrors. This is the part that
//! has to know about the app: a task for the app's lifetime, and a nudge for
//! the moments where waiting out the tick would look broken.

use std::sync::Arc;
use std::time::Duration;

use aka_core::cloud_push::{refresh_once, LeashPins, PushedClock};
use tauri::{AppHandle, Manager as _};

use crate::commands::AppState;

/// How often to look for sessions that need renewing. Well inside the
/// shortest session (15 minutes), so a missed tick is not an outage.
const TICK: Duration = Duration::from_secs(60);

fn install_id() -> String {
    aka_core::paths::Paths::default_locations()
        .map(|paths| paths.install_id())
        .unwrap_or_default()
}

async fn refresh(handle: &AppHandle, install_id: &str) {
    let Some(state) = handle.try_state::<AppState>() else {
        return;
    };
    let Some(clock) = handle.try_state::<Arc<PushedClock>>() else {
        return;
    };
    let Some(pins) = handle.try_state::<Arc<LeashPins>>() else {
        return;
    };
    refresh_once(state.brokers.backend(), install_id, clock.inner(), pins.inner()).await;
}

/// Start the refresher for the app's lifetime.
///
/// Runs against whichever broker is active at each tick: a local broker
/// reads the files itself (its listing says so), so the pass finds nothing
/// owed and costs a list.
pub fn start(handle: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let install_id = install_id();
        loop {
            tokio::time::sleep(TICK).await;
            refresh(&handle, &install_id).await;
        }
    });
}

/// Push now rather than at the next tick — after adding a connection, or
/// after switching brokers, where a minute of silence would look like a
/// failure.
pub fn refresh_soon(handle: &AppHandle) {
    let handle = handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(clock) = handle.try_state::<Arc<PushedClock>>() {
            // The new broker holds none of what the old one did.
            clock.reset();
        }
        refresh(&handle, &install_id()).await;
    });
}
