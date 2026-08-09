//! Tray + window
//!
//! Multitool has a resizable main window, an NSStatusItem-style tray
//! dropdown, and a short-lived approval HUD. The tray icon is always present
//! and toggles the compact dropdown beneath its status item.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, MenuItemKind, PredefinedMenuItem, WINDOW_SUBMENU_ID};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Rect, UserAttentionType};

#[cfg(target_os = "macos")]
use tauri_nspanel::{tauri_panel, ManagerExt as _, WebviewWindowExt as _};

const TRAY_ICON_BYTES: &[u8] = include_bytes!("../icons/tray.png");
#[cfg(test)]
const APP_ICON_BYTES: &[u8] = include_bytes!("../icons/icon.png");

pub const MAIN: &str = "main";
pub const DROPDOWN: &str = "dropdown";
pub const ATTENTION: &str = "attention";
pub const EVT_DROPDOWN_HIDDEN: &str = "aka://dropdown-hidden";
pub const EVT_DROPDOWN_SHOWN: &str = "aka://dropdown-shown";
pub const EVT_OPEN_SETTINGS: &str = "aka://open-settings";
pub const EVT_OPEN_CREDENTIAL: &str = "aka://open-credential";
pub const EVT_OPEN_REQUESTS: &str = "aka://open-requests";
pub const EVT_ATTENTION_HUD: &str = "aka://attention-hud";
const APP_WINDOW_MENU_ID: &str = "app-window";
const NEW_WINDOW_MENU_ID: &str = "new-window";
const LOCK_MENU_ID: &str = "lock-now";
const SETTINGS_MENU_ID: &str = "app-settings";
const TRAY_OPEN_ID: &str = "tray-open";
const TRAY_REQUESTS_ID: &str = "tray-requests";
const TRAY_SETTINGS_ID: &str = "tray-settings";
const TRAY_QUIT_ID: &str = "tray-quit";

/// Payload for [`EVT_OPEN_REQUESTS`]: open the Request Inbox, optionally
/// deep-linking a specific traffic-confirmation prompt so the decision sheet
/// can open without a second click.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequestsPayload {
    /// Preferred approval id to present as a modal sheet, when still pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Payload for [`EVT_OPEN_CREDENTIAL`]: select one Credentials row.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenCredentialPayload {
    pub id: String,
}

/// Result of draining a pending Request Inbox navigation for one webview.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TakeOpenRequests {
    pub open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Privacy-minimized state for the app-owned approval popup. Request details
/// remain in the Inbox so this surface is safe to show above other apps.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttentionHudPayload {
    pub count: usize,
    pub urgent: bool,
}

/// Pending work changes the icon itself in addition to the count, so it stays
/// visible at a glance. macOS gets a monochrome shape that remains a native
/// adaptive template; Windows and Linux get the same badge in red.
fn request_tray_icon(waiting: bool) -> tauri::Result<Image<'static>> {
    let icon = Image::from_bytes(TRAY_ICON_BYTES)?;
    if !waiting {
        return Ok(icon);
    }

    let width = icon.width();
    let height = icon.height();
    let mut rgba = icon.rgba().to_vec();
    let radius = (width.min(height) / 5).max(2) as i32;
    let center_x = width as i32 - radius - 1;
    let center_y = radius + 1;
    for y in 0..height as i32 {
        for x in 0..width as i32 {
            let dx = x - center_x;
            let dy = y - center_y;
            if dx * dx + dy * dy <= radius * radius {
                let offset = ((y as u32 * width + x as u32) * 4) as usize;
                rgba[offset..offset + 4].copy_from_slice(&request_badge_pixel());
            }
        }
    }
    Ok(Image::new_owned(rgba, width, height))
}

const fn request_badge_pixel() -> [u8; 4] {
    #[cfg(target_os = "macos")]
    return [0, 0, 0, 255];
    #[cfg(not(target_os = "macos"))]
    [232, 82, 70, 255]
}

const DROPDOWN_GAP: f64 = 6.0;
const ATTENTION_HUD_MARGIN: f64 = 12.0;
const ATTENTION_HUD_TIMEOUT: Duration = Duration::from_secs(10);
static LAST_TRAY_ANCHOR: Mutex<Option<TrayAnchor>> = Mutex::new(None);
/// The HUD webview can load after its first event is emitted. Retaining the
/// current payload also lets a webview reload reconstruct a still-visible HUD.
static ATTENTION_HUD_PAYLOAD: Mutex<Option<AttentionHudPayload>> = Mutex::new(None);
/// Every show/hide advances the generation so an old auto-hide task cannot
/// dismiss a newer, coalesced request popup.
static ATTENTION_HUD_GENERATION: AtomicU64 = AtomicU64::new(0);
/// A dropdown form may hold credentials that must survive focus changes and
/// any error returned afterwards. While it is open, focus loss must not
/// dismiss it. The webview renews this lease; a crashed/reloaded form cannot
/// strand the panel.
static DROPDOWN_FORM_ACTIVE: Mutex<Option<Instant>> = Mutex::new(None);
const DROPDOWN_FORM_TTL: Duration = Duration::from_secs(2 * 60);
/// Outside-click hide can race the tray's mouse-up toggle: the same press
/// that dismissed the panel would reopen it on button-up. Swallow tray
/// toggles that arrive within this window of an outside-click dismiss.
static DROPDOWN_OUTSIDE_CLICK_HID_AT: Mutex<Option<Instant>> = Mutex::new(None);
const OUTSIDE_CLICK_TRAY_GRACE: Duration = Duration::from_millis(350);

/// AppKit event-monitor tokens. `Retained<AnyObject>` is not Sync, but these
/// handles only move on the main thread (show/hide paths).
#[cfg(target_os = "macos")]
struct OutsideClickMonitors {
    global: Option<objc2::rc::Retained<objc2::runtime::AnyObject>>,
    local: Option<objc2::rc::Retained<objc2::runtime::AnyObject>>,
}

#[cfg(target_os = "macos")]
unsafe impl Send for OutsideClickMonitors {}
#[cfg(target_os = "macos")]
unsafe impl Sync for OutsideClickMonitors {}

/// macOS mouse-down monitors (global + local) that dismiss the tray panel
/// when the user clicks outside it. Keyboard focus loss (Cmd-Tab, etc.) does not.
#[cfg(target_os = "macos")]
static DROPDOWN_OUTSIDE_CLICK_MONITORS: Mutex<OutsideClickMonitors> = Mutex::new(OutsideClickMonitors {
    global: None,
    local: None,
});
/// Tray / notification navigation can happen before a webview installs its
/// event listener. Keep one pending open (and optional approval deep-link)
/// per request surface so the destination can drain it after boot instead of
/// silently losing the user's click.
static MAIN_REQUESTS_PENDING: Mutex<Option<Option<String>>> = Mutex::new(None);
static DROPDOWN_REQUESTS_PENDING: Mutex<Option<Option<String>>> = Mutex::new(None);
/// Window focus and request-tab visibility are written by the main-thread
/// window/webview event handlers and read by async notification delivery.
/// Keeping this state here avoids synchronous window-server calls from a
/// broker task while still distinguishing a visible Inbox from another tab.
static MAIN_FOCUSED: AtomicBool = AtomicBool::new(false);
static DROPDOWN_FOCUSED: AtomicBool = AtomicBool::new(false);
static MAIN_INBOX_VISIBLE: AtomicBool = AtomicBool::new(false);
static DROPDOWN_INBOX_VISIBLE: AtomicBool = AtomicBool::new(false);

fn dropdown_hide_allowed() -> bool {
    dropdown_hide_allowed_at(Instant::now())
}

fn dropdown_hide_allowed_at(now: Instant) -> bool {
    let mut active = DROPDOWN_FORM_ACTIVE.lock().unwrap();
    if active.is_some_and(|renewed| now.duration_since(renewed) < DROPDOWN_FORM_TTL) {
        return false;
    }
    *active = None;
    true
}

pub fn clear_dropdown_form_hold() {
    *DROPDOWN_FORM_ACTIVE.lock().unwrap() = None;
}

#[cfg(target_os = "macos")]
tauri_panel! {
    panel!(AkaDropdownPanel {
        config: {
            can_become_key_window: true,
            can_become_main_window: false,
            becomes_key_only_if_needed: true,
            is_floating_panel: true,
            hides_on_deactivate: false
        }
    })
    panel!(AkaAttentionPanel {
        config: {
            can_become_key_window: false,
            can_become_main_window: false,
            becomes_key_only_if_needed: true,
            is_floating_panel: true,
            hides_on_deactivate: false
        }
    })
}

/// Convert the dropdown's ordinary Tauri NSWindow into a non-activating
/// NSPanel. A panel can accept keyboard input without activating Multitool and
/// raising the already-visible main window above the user's current app.
#[cfg(target_os = "macos")]
pub fn setup_dropdown_panel(app: &AppHandle) -> tauri::Result<()> {
    use tauri_nspanel::panel::NSWindowStyleMask;

    let window = app
        .get_webview_window(DROPDOWN)
        .ok_or_else(|| tauri::Error::AssetNotFound("configured dropdown window".into()))?;
    let panel = window.to_panel::<AkaDropdownPanel>()?;
    let style = panel.as_panel().styleMask() | NSWindowStyleMask::NonactivatingPanel;
    panel.set_style_mask(style);
    // The panel frame is rectangular even though the web surface is rounded.
    // Its native shadow therefore sticks past the lower CSS corners; the
    // surface supplies its own radius-aware shadow instead.
    panel.set_has_shadow(false);
    panel.set_floating_panel(true);
    panel.set_becomes_key_only_if_needed(true);
    panel.set_hides_on_deactivate(false);
    Ok(())
}

/// Convert the HUD into a non-activating panel. It can receive pointer clicks
/// without taking keyboard focus or bringing Multitool's other windows along.
#[cfg(target_os = "macos")]
pub fn setup_attention_panel(app: &AppHandle) -> tauri::Result<()> {
    use tauri_nspanel::panel::NSWindowStyleMask;

    let window = app
        .get_webview_window(ATTENTION)
        .ok_or_else(|| tauri::Error::AssetNotFound("configured attention window".into()))?;
    let panel = window.to_panel::<AkaAttentionPanel>()?;
    let style = panel.as_panel().styleMask() | NSWindowStyleMask::NonactivatingPanel;
    panel.set_style_mask(style);
    panel.set_has_shadow(false);
    panel.set_floating_panel(true);
    panel.set_becomes_key_only_if_needed(true);
    panel.set_hides_on_deactivate(false);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn setup_dropdown_panel(_app: &AppHandle) -> tauri::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn setup_attention_panel(_app: &AppHandle) -> tauri::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
static MAIN_TRAFFIC_LIGHT_TOP_INSET: Mutex<[Option<f64>; 3]> = Mutex::new([None; 3]);

/// Convert between a button's AppKit Y coordinate and its visual distance
/// from the top of its containing title-bar view. AppKit uses an unflipped
/// (bottom-up) coordinate system here today, but keeping the conversion
/// explicit avoids baking that implementation detail into resize behavior.
#[cfg(any(target_os = "macos", test))]
fn traffic_light_top_inset(
    container_height: f64,
    button_y: f64,
    button_height: f64,
    flipped: bool,
) -> f64 {
    if flipped {
        button_y
    } else {
        container_height - button_y - button_height
    }
}

#[cfg(any(target_os = "macos", test))]
fn traffic_light_y(
    container_height: f64,
    button_height: f64,
    top_inset: f64,
    flipped: bool,
) -> f64 {
    if flipped {
        top_inset
    } else {
        container_height - top_inset - button_height
    }
}

/// Keep the standard window buttons centred in the main window's taller
/// unified toolbar. AppKit lays these views out again during native drags and
/// resizes, so remember their adjusted distance from the top edge. An absolute
/// Y coordinate is measured from the bottom in AppKit; replaying one after a
/// height change makes the lights jump between the old Y and AppKit's newly
/// laid-out Y throughout a live resize.
#[cfg(target_os = "macos")]
pub fn position_main_traffic_lights(window: &tauri::WebviewWindow) -> tauri::Result<()> {
    use objc2_app_kit::{NSWindow, NSWindowButton};

    const DOWN_OFFSET: f64 = 8.0;
    let ns_window = window.ns_window()?;
    let ns_window: &NSWindow = unsafe { &*ns_window.cast() };
    let mut target_top_inset = MAIN_TRAFFIC_LIGHT_TOP_INSET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (index, kind) in [
        NSWindowButton::CloseButton,
        NSWindowButton::MiniaturizeButton,
        NSWindowButton::ZoomButton,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(button) = ns_window.standardWindowButton(kind) {
            let frame = button.frame();
            let Some(container) = (unsafe { button.superview() }) else {
                continue;
            };
            let container_height = container.bounds().size.height;
            let flipped = container.isFlipped();
            let top_inset = *target_top_inset[index].get_or_insert_with(|| {
                traffic_light_top_inset(
                    container_height,
                    frame.origin.y,
                    frame.size.height,
                    flipped,
                ) + DOWN_OFFSET
            });
            let mut origin = frame.origin;
            origin.y = traffic_light_y(container_height, frame.size.height, top_inset, flipped);
            button.setFrameOrigin(origin);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn position_main_traffic_lights(_window: &tauri::WebviewWindow) -> tauri::Result<()> {
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct TrayAnchor {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

/// Extend Tauri's conventional macOS application menu with a reliable way
/// back to Multitool when its Dock and tray affordances are unavailable.
pub fn setup_app_menu(app: &AppHandle) -> tauri::Result<()> {
    let menu = Menu::default(app)?;
    let new_window = MenuItem::with_id(
        app,
        NEW_WINDOW_MENU_ID,
        "New Window",
        true,
        Some("CmdOrCtrl+N"),
    )?;
    for item in menu.items()? {
        if let MenuItemKind::Submenu(submenu) = item {
            if submenu.text()? == "File" {
                let separator = PredefinedMenuItem::separator(app)?;
                submenu.prepend_items(&[&new_window, &separator])?;
                break;
            }
        }
    }

    // ⌘L is the platform-conventional one-shot lock. Automatic-lock
    // preferences do not gate an explicit user request.
    let lock_now = MenuItem::with_id(app, LOCK_MENU_ID, "Lock Now", true, Some("CmdOrCtrl+L"))?;
    for item in menu.items()? {
        if let MenuItemKind::Submenu(submenu) = item {
            if submenu.text()? == "File" {
                submenu.append_items(&[&PredefinedMenuItem::separator(app)?, &lock_now])?;
                break;
            }
        }
    }

    // ⌘, is the platform-conventional Settings accelerator. On macOS it
    // lives in the application menu (after About); elsewhere File is the
    // closest conventional home.
    let settings = MenuItem::with_id(
        app,
        SETTINGS_MENU_ID,
        "Settings…",
        true,
        Some("CmdOrCtrl+,"),
    )?;
    let settings_sep = PredefinedMenuItem::separator(app)?;
    #[cfg(target_os = "macos")]
    {
        // Default app menu: About, sep, Services, sep, Hide, Hide Others, sep, Quit.
        // Insert Settings after About + its separator (index 2).
        if let Some(MenuItemKind::Submenu(app_menu)) = menu.items()?.into_iter().next() {
            app_menu.insert_items(&[&settings, &settings_sep], 2)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Windows has File; Linux's default menu does not — fall back to Edit
        // so Ctrl+, still has a conventional home.
        let mut placed = false;
        for preferred in ["File", "Edit"] {
            for item in menu.items()? {
                if let MenuItemKind::Submenu(submenu) = item {
                    if submenu.text()? == preferred {
                        submenu.append_items(&[&settings_sep, &settings])?;
                        placed = true;
                        break;
                    }
                }
            }
            if placed {
                break;
            }
        }
    }

    let app_window = MenuItem::with_id(app, APP_WINDOW_MENU_ID, "Multitool", true, None::<&str>)?;
    if let Some(MenuItemKind::Submenu(window_menu)) = menu.get(WINDOW_SUBMENU_ID) {
        let separator = PredefinedMenuItem::separator(app)?;
        window_menu.append_items(&[&separator, &app_window])?;
    }
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| match event.id().as_ref() {
        NEW_WINDOW_MENU_ID => open_main(app),
        APP_WINDOW_MENU_ID => focus_existing_or_reopen(app),
        SETTINGS_MENU_ID => open_settings(app),
        LOCK_MENU_ID => {
            if let Some(lock) = app.try_state::<std::sync::Arc<crate::applock::AppLock>>() {
                lock.lock_now(app);
            }
        }
        _ => {}
    });
    Ok(())
}

fn focus_existing_or_reopen(app: &AppHandle) {
    if !dropdown_hide_allowed() {
        show_dropdown(app);
        return;
    }
    for label in [MAIN, DROPDOWN] {
        let Some(window) = app.get_webview_window(label) else {
            continue;
        };
        if window.is_visible().unwrap_or(false) {
            let _ = window.unminimize();
            let _ = window.set_focus();
            return;
        }
    }
    open_main(app);
}

/// Install the always-present tray icon. Left-click toggles the compact
/// dropdown; right-click exposes the conventional app menu.
pub fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = tray_menu(app, 0)?;
    let tray = app
        .tray_by_id("main")
        .ok_or_else(|| tauri::Error::AssetNotFound("configured tray icon".into()))?;
    tray.set_menu(Some(menu))?;
    tray.set_show_menu_on_left_click(false)?;
    tray.on_menu_event(|app, event| match event.id().as_ref() {
        TRAY_OPEN_ID => open_main(app),
        TRAY_REQUESTS_ID => open_request_inbox(app, None),
        // Prefer the full desktop Settings sheet; a protected menu-bar form
        // keeps the dropdown up so an unfinished draft is not destroyed.
        TRAY_SETTINGS_ID => open_settings(app),
        TRAY_QUIT_ID => app.exit(0),
        _ => {}
    });
    tray.on_tray_icon_event(|tray, event| match event {
        TrayIconEvent::Click {
            rect,
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } => {
            let app = tray.app_handle();
            remember_tray_anchor(app, rect);
            toggle_dropdown(app);
        }
        TrayIconEvent::Click { rect, .. } => {
            remember_tray_anchor(tray.app_handle(), rect);
        }
        _ => {}
    });
    Ok(())
}

fn tray_menu(app: &AppHandle, request_count: usize) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, TRAY_OPEN_ID, "Open Multitool", true, None::<&str>)?;
    let request_label = if request_count == 0 {
        "Request Inbox…".to_string()
    } else {
        format!(
            "Review {request_count} request{}…",
            if request_count == 1 { "" } else { "s" }
        )
    };
    let requests = MenuItem::with_id(app, TRAY_REQUESTS_ID, request_label, true, None::<&str>)?;
    let settings = MenuItem::with_id(app, TRAY_SETTINGS_ID, "Settings…", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, TRAY_QUIT_ID, "Quit Multitool", true, None::<&str>)?;
    Menu::with_items(app, &[&open, &requests, &settings, &separator, &quit])
}

/// Keep the native tray affordance in sync with the authoritative active
/// queue. The count title is visible beside the icon on macOS and supported
/// Linux panels; Windows still gets the dynamic menu label.
pub fn update_request_count(app: &AppHandle, request_count: usize) {
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        // Main-thread work from different producers can be delivered out of
        // order. Re-read the coordinator here so a stale captured count can
        // never overwrite a newer tray state.
        let request_count = app
            .try_state::<crate::attention::RequestAttention>()
            .map(|attention| attention.count())
            .unwrap_or(request_count);
        sync_attention_hud_on_main(&app, request_count);
        let Some(tray) = app.tray_by_id("main") else {
            return;
        };
        match tray_menu(&app, request_count) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(error) => {
                tracing::warn!(%error, "could not update the tray request menu");
            }
        }
        let tooltip = if request_count == 0 {
            "Multitool".to_string()
        } else {
            format!(
                "Multitool — {request_count} request{} waiting",
                if request_count == 1 { "" } else { "s" }
            )
        };
        let _ = tray.set_tooltip(Some(tooltip));
        match request_tray_icon(request_count > 0) {
            Ok(icon) => {
                #[cfg(target_os = "macos")]
                let _ = tray.set_icon_with_as_template(Some(icon), true);
                #[cfg(not(target_os = "macos"))]
                let _ = tray.set_icon(Some(icon));
            }
            Err(error) => tracing::warn!(%error, "could not update the tray request icon"),
        }
        #[cfg(target_os = "macos")]
        {
            let title = (request_count > 0).then(|| request_count.to_string());
            let _ = tray.set_title(title.as_deref());
        }
        if let Some(window) = app.get_webview_window(MAIN) {
            let badge = (request_count > 0).then_some(request_count as i64);
            let _ = window.set_badge_count(badge);
        }
    });
}

fn remember_tray_anchor(app: &AppHandle, rect: Rect) {
    // Tray events report a physical rectangle. Resolve that point against the
    // desktop before converting the rect so the first dropdown placement does
    // not inherit the scale of whichever monitor created its hidden window.
    let tray_position = rect.position.to_physical::<f64>(1.0);
    let scale = app
        .monitor_from_point(tray_position.x, tray_position.y)
        .ok()
        .flatten()
        .map(|monitor| monitor.scale_factor())
        .unwrap_or(1.0);
    let position = rect.position.to_physical::<f64>(scale);
    let size = rect.size.to_physical::<f64>(scale);
    *LAST_TRAY_ANCHOR.lock().unwrap() = Some(TrayAnchor {
        x: position.x,
        y: position.y,
        width: size.width,
        height: size.height,
    });
}

/// Escalate a waiting request beyond a passive banner. On macOS this maps to
/// the critical Dock bounce; other desktop runtimes use their strongest
/// supported attention request.
pub fn request_critical_attention(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.request_user_attention(Some(UserAttentionType::Critical));
    }
}

fn toggle_dropdown(app: &AppHandle) {
    // An outside-click dismiss on the tray icon itself already closed the
    // panel on mouse-down; the matching mouse-up must not reopen it.
    {
        let mut hid_at = DROPDOWN_OUTSIDE_CLICK_HID_AT.lock().unwrap();
        if hid_at.is_some_and(|at| at.elapsed() < OUTSIDE_CLICK_TRAY_GRACE) {
            *hid_at = None;
            return;
        }
    }
    if window_visible(app, DROPDOWN) {
        let _ = hide_dropdown(app);
    } else if app
        .try_state::<crate::attention::RequestAttention>()
        .is_some_and(|attention| attention.count() > 0)
    {
        show_dropdown_requests(app);
    } else {
        show_dropdown(app);
    }
}

fn show_dropdown(app: &AppHandle) {
    let Some(window) = app.get_webview_window(DROPDOWN) else {
        return;
    };
    if let Some(anchor) = *LAST_TRAY_ANCHOR.lock().unwrap() {
        if let Ok(size) = window.outer_size() {
            let monitor = app
                .monitor_from_point(
                    anchor.x + anchor.width / 2.0,
                    anchor.y + anchor.height / 2.0,
                )
                .ok()
                .flatten();
            let bounds = monitor.map(|monitor| {
                let work = monitor.work_area();
                Bounds {
                    x: work.position.x as f64,
                    y: work.position.y as f64,
                    width: work.size.width as f64,
                    height: work.size.height as f64,
                }
            });
            let (x, y) = dropdown_origin(anchor, size.width as f64, size.height as f64, bounds);
            let _ = window.set_position(PhysicalPosition::new(x, y));
        }
    }
    show_dropdown_window(app, &window);
    install_outside_click_monitor(app);
    let _ = app.emit_to(DROPDOWN, EVT_DROPDOWN_SHOWN, ());
}

/// A pending-count click is an explicit request to review the queue. Keep it
/// in the compact surface rather than raising the desktop window, and never
/// replace an unfinished protected form.
fn show_dropdown_requests(app: &AppHandle) {
    show_dropdown(app);
    if !dropdown_hide_allowed() {
        return;
    }
    *DROPDOWN_REQUESTS_PENDING.lock().unwrap() = Some(None);
    let _ = app.emit_to(DROPDOWN, EVT_OPEN_REQUESTS, OpenRequestsPayload { id: None });
}

/// Show the macOS dropdown through NSPanel rather than Tauri's `show` and
/// `set_focus`: Tauri activates the whole application when focusing a native
/// window, which also raises the main Multitool window.
#[cfg(target_os = "macos")]
fn show_dropdown_window(app: &AppHandle, window: &tauri::WebviewWindow) {
    if let Ok(panel) = app.get_webview_panel(DROPDOWN) {
        panel.show_and_make_key();
    } else {
        // Startup normally makes this unreachable, but retaining a fallback
        // keeps the dropdown recoverable if panel registration ever changes.
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(target_os = "windows")]
fn show_dropdown_window(_app: &AppHandle, window: &tauri::WebviewWindow) {
    let _ = window.show();
    let _ = window.set_focus();
}

/// StatusNotifierItem dropdowns should not activate the application merely
/// because the tray icon was clicked. The first explicit control click can
/// focus the panel naturally.
#[cfg(all(unix, not(target_os = "macos")))]
fn show_dropdown_window(_app: &AppHandle, window: &tauri::WebviewWindow) {
    // Some Linux window managers activate any newly-shown focusable window.
    // Make the show itself non-activating, then restore focusability so the
    // user's first explicit click can focus a control naturally.
    let _ = window.set_focusable(false);
    let _ = window.show();
    let window = window.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = window.set_focusable(true);
    });
}

fn dropdown_origin(
    anchor: TrayAnchor,
    window_width: f64,
    window_height: f64,
    bounds: Option<Bounds>,
) -> (i32, i32) {
    let mut x = anchor.x + anchor.width / 2.0 - window_width / 2.0;
    let mut y = anchor.y + anchor.height + DROPDOWN_GAP;

    if let Some(bounds) = bounds {
        let right = bounds.x + bounds.width;
        let bottom = bounds.y + bounds.height;
        if anchor.y + anchor.height / 2.0 > bounds.y + bounds.height / 2.0 {
            y = anchor.y - window_height - DROPDOWN_GAP;
        }
        x = x.clamp(bounds.x, (right - window_width).max(bounds.x));
        y = y.clamp(bounds.y, (bottom - window_height).max(bounds.y));
    }
    (x.round() as i32, y.round() as i32)
}

fn attention_hud_origin(
    anchor: Option<TrayAnchor>,
    window_width: f64,
    window_height: f64,
    bounds: Bounds,
) -> (i32, i32) {
    let right = bounds.x + bounds.width;
    let bottom = bounds.y + bounds.height;
    let (mut x, mut y) = if let Some(anchor) = anchor {
        let y = if anchor.y + anchor.height / 2.0 > bounds.y + bounds.height / 2.0 {
            anchor.y - window_height - DROPDOWN_GAP
        } else {
            anchor.y + anchor.height + DROPDOWN_GAP
        };
        (anchor.x + anchor.width - window_width, y)
    } else {
        (
            right - window_width - ATTENTION_HUD_MARGIN,
            bounds.y + ATTENTION_HUD_MARGIN,
        )
    };
    x = x.clamp(
        bounds.x + ATTENTION_HUD_MARGIN,
        (right - window_width - ATTENTION_HUD_MARGIN).max(bounds.x + ATTENTION_HUD_MARGIN),
    );
    y = y.clamp(
        bounds.y + ATTENTION_HUD_MARGIN,
        (bottom - window_height - ATTENTION_HUD_MARGIN).max(bounds.y + ATTENTION_HUD_MARGIN),
    );
    (x.round() as i32, y.round() as i32)
}

/// Show an app-owned, non-activating request popup. Unlike a system
/// notification this is not filtered by Focus, which is why it is opt-in.
/// New work replaces the current payload and resets the auto-hide timer.
pub fn show_attention_hud(app: &AppHandle, count: usize, urgent: bool) -> bool {
    if count == 0 || request_surface_focused() || session_unavailable() {
        return false;
    }
    if app.get_webview_window(ATTENTION).is_none() {
        return false;
    }

    let payload = AttentionHudPayload { count, urgent };
    let generation = ATTENTION_HUD_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    *ATTENTION_HUD_PAYLOAD.lock().unwrap() = Some(payload.clone());

    let show_app = app.clone();
    let _ = app.run_on_main_thread(move || {
        if ATTENTION_HUD_GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        // Focus/session state may have changed while this main-thread task
        // waited. A focused Inbox needs no duplicate popup; a locked session
        // must not receive an app-owned overlay.
        if request_surface_focused() || session_unavailable() {
            clear_attention_hud_if_current(generation);
            hide_attention_hud_window(&show_app);
            return;
        }
        position_attention_hud(&show_app);
        show_attention_hud_window(&show_app);
        let _ = show_app.emit_to(ATTENTION, EVT_ATTENTION_HUD, payload);
    });

    let timeout_app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(ATTENTION_HUD_TIMEOUT).await;
        if !clear_attention_hud_if_current(generation) {
            return;
        }
        let hide_app = timeout_app.clone();
        let _ = timeout_app.run_on_main_thread(move || hide_attention_hud_window(&hide_app));
    });
    true
}

fn clear_attention_hud_if_current(generation: u64) -> bool {
    if ATTENTION_HUD_GENERATION
        .compare_exchange(
            generation,
            generation.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }
    *ATTENTION_HUD_PAYLOAD.lock().unwrap() = None;
    true
}

/// Dismiss the popup without resolving any work. The tray badge remains the
/// durable indicator until the underlying queue reaches zero.
pub fn hide_attention_hud(app: &AppHandle) {
    ATTENTION_HUD_GENERATION.fetch_add(1, Ordering::AcqRel);
    *ATTENTION_HUD_PAYLOAD.lock().unwrap() = None;
    let hide_app = app.clone();
    let _ = app.run_on_main_thread(move || hide_attention_hud_window(&hide_app));
}

fn dismiss_attention_hud_on_main(app: &AppHandle) {
    ATTENTION_HUD_GENERATION.fetch_add(1, Ordering::AcqRel);
    *ATTENTION_HUD_PAYLOAD.lock().unwrap() = None;
    hide_attention_hud_window(app);
}

fn sync_attention_hud_on_main(app: &AppHandle, count: usize) {
    let payload = {
        let mut current = ATTENTION_HUD_PAYLOAD.lock().unwrap();
        if count == 0 {
            if current.take().is_none() {
                return;
            }
            None
        } else if let Some(payload) = current.as_mut() {
            payload.count = count;
            Some(payload.clone())
        } else {
            return;
        }
    };
    if let Some(payload) = payload {
        let _ = app.emit_to(ATTENTION, EVT_ATTENTION_HUD, payload);
    } else {
        ATTENTION_HUD_GENERATION.fetch_add(1, Ordering::AcqRel);
        hide_attention_hud_window(app);
    }
}

fn position_attention_hud(app: &AppHandle) {
    let Some(window) = app.get_webview_window(ATTENTION) else {
        return;
    };
    let Ok(size) = window.outer_size() else {
        return;
    };
    let anchor = *LAST_TRAY_ANCHOR.lock().unwrap();
    let monitor = anchor
        .and_then(|anchor| {
            app.monitor_from_point(
                anchor.x + anchor.width / 2.0,
                anchor.y + anchor.height / 2.0,
            )
            .ok()
            .flatten()
        })
        .or_else(|| app.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let work = monitor.work_area();
    let bounds = Bounds {
        x: work.position.x as f64,
        y: work.position.y as f64,
        width: work.size.width as f64,
        height: work.size.height as f64,
    };
    let (x, y) = attention_hud_origin(anchor, size.width as f64, size.height as f64, bounds);
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

#[cfg(target_os = "macos")]
fn show_attention_hud_window(app: &AppHandle) {
    if let Ok(panel) = app.get_webview_panel(ATTENTION) {
        panel.show();
    } else if let Some(window) = app.get_webview_window(ATTENTION) {
        let _ = window.show();
    }
}

#[cfg(not(target_os = "macos"))]
fn show_attention_hud_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(ATTENTION) {
        let _ = window.set_focusable(false);
        let _ = window.show();
    }
}

#[cfg(target_os = "macos")]
fn hide_attention_hud_window(app: &AppHandle) {
    if let Ok(panel) = app.get_webview_panel(ATTENTION) {
        panel.hide();
    } else if let Some(window) = app.get_webview_window(ATTENTION) {
        let _ = window.hide();
    }
}

#[cfg(not(target_os = "macos"))]
fn hide_attention_hud_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(ATTENTION) {
        let _ = window.hide();
    }
}

/// Bring a window forward because traffic is waiting on a decision.
///
/// Suppress raising only when the Request Inbox is already the focused
/// surface — a focused Settings or Services tab must still bring the queue
/// forward, because the in-app banner alone is easy to miss during a short
/// confirmation timeout. Runs on the main thread — the broker calls this
/// from whichever task parked the traffic.
pub fn surface_for_approval(app: &AppHandle) {
    let app = app.clone();
    let _ = app.clone().run_on_main_thread(move || {
        if request_surface_focused() {
            dismiss_attention_hud_on_main(&app);
            return;
        }
        // Prefer opening the inbox itself so the waiting cards (and any
        // auto-presented decision sheet) are on screen, not only the window.
        open_request_inbox_on_main(&app, None);
        // orderFrontRegardless / unminimize even when Multitool was already
        // visible on another Space or minimized.
        if let Some(window) = [DROPDOWN, MAIN].into_iter().find_map(|label| {
            window_presented(&app, label)
                .then(|| app.get_webview_window(label))
                .flatten()
        }) {
            raise_for_approval(&window);
        }
    });
}

/// Record native focus without making a synchronous window-server call from
/// notification delivery.
pub fn set_window_focused(app: &AppHandle, label: &str, focused: bool) {
    match label {
        MAIN => MAIN_FOCUSED.store(focused, Ordering::Release),
        DROPDOWN => DROPDOWN_FOCUSED.store(focused, Ordering::Release),
        _ => {}
    }
    let inbox_visible = match label {
        MAIN => MAIN_INBOX_VISIBLE.load(Ordering::Acquire),
        DROPDOWN => DROPDOWN_INBOX_VISIBLE.load(Ordering::Acquire),
        _ => false,
    };
    if focused && inbox_visible {
        dismiss_attention_hud_on_main(app);
    }
}

fn set_inbox_visible(label: &str, visible: bool) {
    match label {
        MAIN => MAIN_INBOX_VISIBLE.store(visible, Ordering::Release),
        DROPDOWN => DROPDOWN_INBOX_VISIBLE.store(visible, Ordering::Release),
        _ => {}
    }
}

/// Whether the Inbox is genuinely frontmost. A focused window showing
/// another tab must not suppress a native request notification, nor may a
/// locked or switched-away macOS session. Also gates
/// [`surface_for_approval`]: only a focused Inbox skips raising.
pub fn request_surface_focused() -> bool {
    request_surface_state(
        MAIN_FOCUSED.load(Ordering::Acquire),
        MAIN_INBOX_VISIBLE.load(Ordering::Acquire),
        DROPDOWN_FOCUSED.load(Ordering::Acquire),
        DROPDOWN_INBOX_VISIBLE.load(Ordering::Acquire),
        session_unavailable(),
    )
}

fn request_surface_state(
    main_focused: bool,
    main_inbox: bool,
    dropdown_focused: bool,
    dropdown_inbox: bool,
    session_unavailable: bool,
) -> bool {
    !session_unavailable && ((main_focused && main_inbox) || (dropdown_focused && dropdown_inbox))
}

#[cfg(target_os = "macos")]
fn session_unavailable() -> bool {
    use objc2_core_foundation::{CFBoolean, CFDictionary, CFString};

    let Some(session) = objc2_core_graphics::CGSessionCopyCurrentDictionary() else {
        return false;
    };
    // CGSession's dictionary is untyped. These two known keys both carry
    // CFBoolean values: one catches the lock screen, the other fast-user
    // switching to a different console session.
    let session: &CFDictionary<CFString, CFBoolean> = unsafe { session.cast_unchecked() };
    let locked = CFString::from_static_str("CGSSessionScreenIsLocked");
    if session.get(&locked).is_some_and(|value| value.as_bool()) {
        return true;
    }
    let on_console = CFString::from_static_str("kCGSSessionOnConsoleKey");
    session
        .get(&on_console)
        .is_some_and(|value| !value.as_bool())
}

#[cfg(not(target_os = "macos"))]
fn session_unavailable() -> bool {
    false
}

fn raise_for_approval(window: &tauri::WebviewWindow) {
    let _ = window.unminimize();
    let _ = window.show();
    #[cfg(target_os = "macos")]
    if let Ok(raw) = window.ns_window() {
        use objc2_app_kit::{NSWindow, NSWindowCollectionBehavior};

        let native: &NSWindow = unsafe { &*raw.cast() };
        native.setCollectionBehavior(
            native.collectionBehavior() | NSWindowCollectionBehavior::MoveToActiveSpace,
        );
        native.orderFrontRegardless();
    }
    let _ = window.set_focus();
}

/// Visible and not minimized. Window managers may report a minimized window
/// as visible; that is not enough for a multi-minute approval prompt.
fn window_presented(app: &AppHandle, label: &str) -> bool {
    app.get_webview_window(label).is_some_and(|window| {
        window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
    })
}

fn window_visible(app: &AppHandle, label: &str) -> bool {
    app.get_webview_window(label)
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false)
}

/// Hide the compact dropdown and ask its webview to clear transient secret
/// prefixes and unfinished modal state before the next open. An active form
/// blocks hiding so ordinary focus transfers cannot destroy the draft before
/// a command reports its outcome.
pub fn hide_dropdown(app: &AppHandle) -> bool {
    if !dropdown_hide_allowed() {
        return false;
    }
    remove_outside_click_monitor();
    if let Some(window) = app.get_webview_window(DROPDOWN) {
        if window.is_visible().unwrap_or(false) {
            let _ = app.emit_to(DROPDOWN, EVT_DROPDOWN_HIDDEN, ());
            hide_dropdown_window(app, &window);
        }
    }
    crate::applock::lock_if_hidden(app);
    true
}

/// Dismiss the tray panel when the user clicks outside it. Keyboard focus
/// loss alone (Cmd-Tab, activating another app without a click) must not.
///
/// AppKit delivers global monitors only while this app is inactive and local
/// monitors only while it is active — install both so a click away always
/// dismisses, regardless of whether Multitool's main window is frontmost.
#[cfg(target_os = "macos")]
fn install_outside_click_monitor(app: &AppHandle) {
    use block2::RcBlock;
    use objc2_app_kit::{NSEvent, NSEventMask};
    use std::ptr::NonNull;

    remove_outside_click_monitor();
    let mask = NSEventMask::LeftMouseDown | NSEventMask::RightMouseDown;

    let app_global = app.clone();
    let global_block = RcBlock::new(move |_event: NonNull<NSEvent>| {
        dismiss_dropdown_if_outside_click(&app_global);
    });
    let global = NSEvent::addGlobalMonitorForEventsMatchingMask_handler(mask, &global_block);

    let app_local = app.clone();
    let local_block = RcBlock::new(move |event: NonNull<NSEvent>| -> *mut NSEvent {
        dismiss_dropdown_if_outside_click(&app_local);
        event.as_ptr()
    });
    let local =
        unsafe { NSEvent::addLocalMonitorForEventsMatchingMask_handler(mask, &local_block) };

    *DROPDOWN_OUTSIDE_CLICK_MONITORS.lock().unwrap() = OutsideClickMonitors { global, local };
}

#[cfg(target_os = "macos")]
fn dismiss_dropdown_if_outside_click(app: &AppHandle) {
    if !window_visible(app, DROPDOWN) {
        return;
    }
    if mouse_inside_dropdown(app) {
        return;
    }
    // Only stamp the tray-toggle grace when hide actually ran — a form hold
    // that refuses dismiss must not swallow the next tray click.
    if hide_dropdown(app) {
        *DROPDOWN_OUTSIDE_CLICK_HID_AT.lock().unwrap() = Some(Instant::now());
    }
}

#[cfg(target_os = "macos")]
fn remove_outside_click_monitor() {
    use objc2_app_kit::NSEvent;

    let mut handles = DROPDOWN_OUTSIDE_CLICK_MONITORS.lock().unwrap();
    if let Some(monitor) = handles.global.take() {
        unsafe { NSEvent::removeMonitor(&monitor) };
    }
    if let Some(monitor) = handles.local.take() {
        unsafe { NSEvent::removeMonitor(&monitor) };
    }
}

#[cfg(target_os = "macos")]
fn mouse_inside_dropdown(app: &AppHandle) -> bool {
    use objc2_app_kit::{NSEvent, NSWindow};

    let Some(window) = app.get_webview_window(DROPDOWN) else {
        return false;
    };
    let Ok(ns_window) = window.ns_window() else {
        return false;
    };
    let ns_window: &NSWindow = unsafe { &*ns_window.cast() };
    let frame = ns_window.frame();
    let mouse = NSEvent::mouseLocation();
    // NSWindow frames and mouseLocation share Cocoa screen space (origin
    // bottom-left). Treat a hit anywhere in the panel as "inside".
    mouse.x >= frame.origin.x
        && mouse.x < frame.origin.x + frame.size.width
        && mouse.y >= frame.origin.y
        && mouse.y < frame.origin.y + frame.size.height
}

#[cfg(not(target_os = "macos"))]
fn install_outside_click_monitor(_app: &AppHandle) {}

#[cfg(not(target_os = "macos"))]
fn remove_outside_click_monitor() {}

#[cfg(target_os = "macos")]
fn hide_dropdown_window(app: &AppHandle, window: &tauri::WebviewWindow) {
    if let Ok(panel) = app.get_webview_panel(DROPDOWN) {
        panel.hide();
    } else {
        let _ = window.hide();
    }
}

#[cfg(not(target_os = "macos"))]
fn hide_dropdown_window(_app: &AppHandle, window: &tauri::WebviewWindow) {
    let _ = window.hide();
}

#[tauri::command]
pub fn ui_hide_dropdown(app: AppHandle) {
    let _ = hide_dropdown(&app);
}

/// Keep the menu-bar form visible across focus changes while it may contain
/// unfinished or sensitive input. Only the dropdown webview can hold this
/// lock; other windows must not be able to strand the dropdown open.
#[tauri::command]
pub fn ui_set_dropdown_form_active(
    window: tauri::WebviewWindow,
    active: bool,
) -> Result<(), String> {
    if window.label() != DROPDOWN {
        return Err("only the menu-bar dropdown can hold its form open".into());
    }
    *DROPDOWN_FORM_ACTIVE.lock().unwrap() = active.then(Instant::now);
    Ok(())
}

/// The webview owns tab visibility; the native layer owns actual focus.
/// Combining both prevents a focused Settings/Activity tab from hiding an
/// approval notification.
#[tauri::command]
pub fn ui_set_request_inbox_visible(
    window: tauri::WebviewWindow,
    visible: bool,
) -> Result<(), String> {
    if !matches!(window.label(), MAIN | DROPDOWN) {
        return Err("only a request surface can report Inbox visibility".into());
    }
    set_inbox_visible(window.label(), visible);
    let focused = match window.label() {
        MAIN => MAIN_FOCUSED.load(Ordering::Acquire),
        DROPDOWN => DROPDOWN_FOCUSED.load(Ordering::Acquire),
        _ => false,
    };
    if visible && focused {
        hide_attention_hud(window.app_handle());
    }
    Ok(())
}

/// Show and focus the main window under the regular (Dock-visible)
/// activation policy. Restores the Dock icon if a prior menu-bar retreat
/// had hidden it.
fn open_main(app: &AppHandle) {
    if !hide_dropdown(app) {
        return;
    }
    set_activation_policy(app, true);
    if let Some(win) = app.get_webview_window(MAIN) {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Open Settings in the desktop window (⌘, / Ctrl+, and the tray item).
///
/// The full Settings sheet is a main-window surface. When a protected
/// menu-bar form is open, route Settings into the dropdown instead so the
/// draft is not discarded — the same hold used for Request Inbox deep links.
fn open_settings(app: &AppHandle) {
    if !dropdown_hide_allowed() {
        show_dropdown(app);
        let _ = app.emit_to(DROPDOWN, EVT_OPEN_SETTINGS, ());
        return;
    }
    open_main(app);
    let _ = app.emit_to(MAIN, EVT_OPEN_SETTINGS, ());
}

/// Quit from the tray panel's own gear menu. The tray icon's context menu
/// already offers this; the panel is a complete home, so it does too.
#[tauri::command]
pub fn ui_quit(app: AppHandle) {
    app.exit(0);
}

/// Show one credential on the desktop Credentials page (a tray row's
/// deep link). The id names a row to select, not a value: the webview still
/// has to ask the core for anything sensitive, and the lock still applies.
#[tauri::command]
pub fn ui_open_credential(app: AppHandle, id: String) {
    let payload = OpenCredentialPayload { id };
    // As with Settings and the guide: a protected menu-bar form may hold a
    // draft, so render into the dropdown rather than tearing it down.
    if !dropdown_hide_allowed() {
        show_dropdown(&app);
        let _ = app.emit_to(DROPDOWN, EVT_OPEN_CREDENTIAL, payload);
        return;
    }
    open_main(&app);
    let _ = app.emit_to(MAIN, EVT_OPEN_CREDENTIAL, payload);
}

pub(crate) fn open_request_inbox(app: &AppHandle, approval_id: Option<String>) {
    let app = app.clone();
    let _ = app
        .clone()
        .run_on_main_thread(move || open_request_inbox_on_main(&app, approval_id));
}

fn open_request_inbox_on_main(app: &AppHandle, approval_id: Option<String>) {
    dismiss_attention_hud_on_main(app);
    let payload = OpenRequestsPayload {
        id: approval_id.clone(),
    };
    // A protected dropdown form may contain credentials. Keep it open and
    // queue the navigation until the form closes rather than destroying a
    // draft or losing the user's request.
    if !dropdown_hide_allowed() {
        show_dropdown(app);
        *DROPDOWN_REQUESTS_PENDING.lock().unwrap() = Some(approval_id);
        let _ = app.emit_to(DROPDOWN, EVT_OPEN_REQUESTS, payload);
        return;
    }
    open_main(app);
    *MAIN_REQUESTS_PENDING.lock().unwrap() = Some(approval_id);
    let _ = app.emit_to(MAIN, EVT_OPEN_REQUESTS, payload);
}

/// Consume a tray / notification Request Inbox route for the invoking
/// webview. The pending slot makes navigation reliable during webview boot
/// and while a protected form temporarily prevents navigation. When the
/// slot carries an approval id, the webview should present that decision
/// sheet once it is safe to do so.
#[tauri::command]
pub fn ui_take_open_requests(window: tauri::WebviewWindow) -> TakeOpenRequests {
    let pending = match window.label() {
        MAIN => MAIN_REQUESTS_PENDING.lock().unwrap().take(),
        DROPDOWN => DROPDOWN_REQUESTS_PENDING.lock().unwrap().take(),
        _ => None,
    };
    match pending {
        Some(id) => TakeOpenRequests { open: true, id },
        None => TakeOpenRequests {
            open: false,
            id: None,
        },
    }
}

/// Read the current HUD payload after installing the webview's event
/// listener. The value remains available for reload recovery until the HUD is
/// dismissed or times out.
#[tauri::command]
pub fn ui_get_attention_hud(
    window: tauri::WebviewWindow,
) -> Result<Option<AttentionHudPayload>, String> {
    if window.label() != ATTENTION {
        return Err("only the attention popup can read its payload".into());
    }
    Ok(ATTENTION_HUD_PAYLOAD.lock().unwrap().clone())
}

#[tauri::command]
pub fn ui_hide_attention_hud(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    if window.label() != ATTENTION {
        return Err("only the attention popup can dismiss itself".into());
    }
    hide_attention_hud(&app);
    Ok(())
}

#[tauri::command]
pub fn ui_review_attention_hud(window: tauri::WebviewWindow, app: AppHandle) -> Result<(), String> {
    if window.label() != ATTENTION {
        return Err("only the attention popup can open its request".into());
    }
    open_request_inbox(&app, None);
    Ok(())
}

/// Hide the main window, leaving the broker running behind the tray icon. If
/// the user opted to hide the Dock icon in the menu bar, drop to accessory
/// activation; otherwise keep the Dock icon (the conventional default).
fn retreat_to_menu_bar(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN) {
        let _ = win.hide();
    }
    if menu_bar_hides_dock(app) {
        set_activation_policy(app, false);
    }
}

/// Read the "hide Dock icon in the menu bar" preference. Defaults to `false`
/// (keep the Dock icon) if the broker state is not yet managed, and for a
/// remote broker: window chrome is a this-machine concern, and this sync
/// window-event path cannot await a network round trip.
fn menu_bar_hides_dock(app: &AppHandle) -> bool {
    app.try_state::<crate::commands::AppState>()
        .and_then(|s| s.brokers.local_broker())
        .map(|broker| broker.settings().menu_bar_hides_dock)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn set_activation_policy(app: &AppHandle, regular: bool) {
    let policy = if regular {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    let _ = app.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn set_activation_policy(_app: &AppHandle, _regular: bool) {}

/// Reopen the main window (Dock-icon reactivation via `RunEvent::Reopen`,
/// which only macOS emits).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn ui_open_main(app: AppHandle) {
    open_main(&app);
}

/// Switch chrome: "window" opens the main window; "tray" minimizes to the
/// menu bar.
#[tauri::command]
pub fn ui_set_mode(app: AppHandle, mode: String) -> Result<(), String> {
    match mode.as_str() {
        "window" => {
            open_main(&app);
            Ok(())
        }
        "tray" => {
            retreat_to_menu_bar(&app);
            Ok(())
        }
        other => Err(format!("unknown mode {other:?}")),
    }
}

/// Closing the main window hides it and keeps the broker running rather than
/// quitting; honors the "hide Dock in the menu bar" preference.
#[tauri::command]
pub fn ui_hide_main(app: AppHandle) {
    retreat_to_menu_bar(&app);
    crate::applock::lock_if_hidden(&app);
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK: Bounds = Bounds {
        x: 0.0,
        y: 24.0,
        width: 1440.0,
        height: 876.0,
    };

    #[test]
    fn active_form_blocks_dropdown_hiding() {
        let now = Instant::now();
        *DROPDOWN_FORM_ACTIVE.lock().unwrap() = Some(now);
        assert!(!dropdown_hide_allowed_at(now + Duration::from_secs(119)));
        assert!(dropdown_hide_allowed_at(now + Duration::from_secs(120)));
        assert!(DROPDOWN_FORM_ACTIVE.lock().unwrap().is_none());
    }

    #[test]
    fn notification_suppression_requires_the_focused_inbox() {
        assert!(request_surface_state(true, true, false, false, false));
        assert!(request_surface_state(false, false, true, true, false));
        assert!(!request_surface_state(true, false, false, false, false));
        assert!(!request_surface_state(false, true, false, false, false));
    }

    #[test]
    fn surface_for_approval_only_skips_when_the_inbox_is_focused() {
        // Mirrors the request_surface_focused gate used by surface_for_approval:
        // any Multitool window focus is not enough — the Inbox itself must be
        // frontmost before raising is suppressed.
        assert!(request_surface_state(true, true, false, false, false));
        assert!(!request_surface_state(true, false, false, false, false));
        assert!(!request_surface_state(false, false, false, false, false));
    }

    #[test]
    fn unavailable_session_never_suppresses_notification() {
        assert!(!request_surface_state(true, true, false, false, true));
        assert!(!request_surface_state(false, false, true, true, true));
    }

    #[test]
    fn traffic_lights_keep_the_same_top_inset_during_vertical_resize() {
        let button_height = 14.0;
        let top_inset = traffic_light_top_inset(48.0, 12.0, button_height, false);
        assert_eq!(top_inset, 22.0);
        assert_eq!(traffic_light_y(48.0, button_height, top_inset, false), 12.0);
        assert_eq!(traffic_light_y(80.0, button_height, top_inset, false), 44.0);
    }

    #[test]
    fn traffic_light_anchor_supports_flipped_titlebar_coordinates() {
        let top_inset = traffic_light_top_inset(48.0, 22.0, 14.0, true);
        assert_eq!(top_inset, 22.0);
        assert_eq!(traffic_light_y(80.0, 14.0, top_inset, true), 22.0);
    }

    #[test]
    fn dropdown_is_centered_below_a_top_tray_item() {
        let anchor = TrayAnchor {
            x: 1200.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(dropdown_origin(anchor, 330.0, 400.0, Some(WORK)), (1047, 30));
    }

    #[test]
    fn dropdown_flips_above_a_bottom_tray_item() {
        let anchor = TrayAnchor {
            x: 700.0,
            y: 900.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(
            dropdown_origin(anchor, 330.0, 400.0, Some(WORK)),
            (547, 494)
        );
    }

    #[test]
    fn dropdown_stays_inside_the_monitor_work_area() {
        let anchor = TrayAnchor {
            x: 1430.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(
            dropdown_origin(anchor, 330.0, 400.0, Some(WORK)),
            (1110, 30)
        );
    }

    #[test]
    fn attention_hud_aligns_to_the_tray_and_stays_inside_work_area() {
        let anchor = TrayAnchor {
            x: 1400.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        assert_eq!(
            attention_hud_origin(Some(anchor), 360.0, 126.0, WORK),
            (1064, 36)
        );
    }

    #[test]
    fn attention_hud_has_a_top_right_fallback_without_a_tray_anchor() {
        assert_eq!(attention_hud_origin(None, 360.0, 126.0, WORK), (1068, 36));
    }

    #[test]
    fn tray_icon_has_a_visible_shape_with_transparent_padding() {
        let icon = Image::from_bytes(TRAY_ICON_BYTES).expect("tray icon should be valid PNG");
        let alpha = icon.rgba().chunks_exact(4).map(|pixel| pixel[3]);
        let pixel_count = alpha.len();
        let (transparent, visible) = alpha.fold((0, 0), |(transparent, visible), value| {
            (
                transparent + usize::from(value == 0),
                visible + usize::from(value > 0),
            )
        });

        assert!(
            transparent > pixel_count / 10,
            "tray icon needs transparent padding"
        );
        assert!(
            visible > pixel_count / 10,
            "tray icon needs a substantial visible shape"
        );
    }

    #[test]
    fn pending_request_tray_icon_has_a_visible_badge() {
        let ordinary = request_tray_icon(false).unwrap();
        let pending = request_tray_icon(true).unwrap();
        assert_eq!(
            (ordinary.width(), ordinary.height()),
            (pending.width(), pending.height())
        );
        assert_ne!(ordinary.rgba(), pending.rgba());
        assert!(pending
            .rgba()
            .chunks_exact(4)
            .any(|pixel| pixel == request_badge_pixel()));
    }

    #[test]
    fn bundled_app_icon_is_retina_sized_and_not_a_placeholder() {
        let icon = Image::from_bytes(APP_ICON_BYTES).expect("app icon should be valid PNG");
        assert_eq!((icon.width(), icon.height()), (1024, 1024));

        let mut pixels = icon.rgba().chunks_exact(4);
        let first = pixels.next().expect("app icon should contain pixels");
        assert!(
            pixels.any(|pixel| pixel != first),
            "app icon should contain real artwork"
        );
    }
}
