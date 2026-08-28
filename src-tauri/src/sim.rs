//! Timer-driven engine for explicit `--features demo` builds only.
//!
//! The module is absent from the default production build. Production
//! pairing, downloads, retry, local commits, deletion and S3 uploads all
//! route through `composition.rs`; no command falls back here on failure.

use std::collections::HashMap;
use std::time::Duration;

use rand::Rng;
use tauri::{AppHandle, Manager};

use crate::application::{
    emit_devices_event, emit_library_event, emit_pairing_event, emit_sessions_event,
    emit_transfers_event,
};
#[cfg(feature = "demo")]
use crate::models::DeviceState;
use crate::models::{LibraryEntry, Transfer, TransferDirection, TransferState, UploadStatus};
use crate::state::AppState;

/// Simulator-only purpose attached to a synthetic transfer. Production
/// transfer routing is derived from the durable transfer store instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DemoTransferContext {
    DownloadSession {
        device_id: String,
        session_id: String,
    },
    DownloadFile,
}

/// Process-local state for demo transfers. The entire type and its owning
/// `AppData` field disappear when the `demo` feature is disabled.
#[derive(Debug, Default)]
pub(crate) struct DemoTransferState {
    contexts: HashMap<String, DemoTransferContext>,
    transfers: Vec<Transfer>,
}

impl DemoTransferState {
    pub(crate) fn insert(&mut self, key: String, context: DemoTransferContext) {
        self.contexts.insert(key, context);
    }

    pub(crate) fn get(&self, key: &str) -> Option<&DemoTransferContext> {
        self.contexts.get(key)
    }

    pub(crate) fn contains(&self, key: &str) -> bool {
        self.contexts.contains_key(key)
    }

    pub(crate) fn remove(&mut self, key: &str) -> Option<DemoTransferContext> {
        self.contexts.remove(key)
    }

    pub(crate) fn transfers(&self) -> &[Transfer] {
        &self.transfers
    }

    pub(crate) fn transfers_mut(&mut self) -> &mut Vec<Transfer> {
        &mut self.transfers
    }
}

pub const MAX_CONCURRENT_TRANSFERS: usize = 3;
#[cfg(feature = "demo")]
const PAIRING_TOTAL_TICKS: i32 = 5;
#[cfg(feature = "demo")]
const PAIRING_TICK_MS: u64 = 620;
const TRANSFER_TICK_MS: u64 = 150;

#[cfg(feature = "demo")]
fn emit_devices(app: &AppHandle) {
    let state = app.state::<AppState>();
    let devices = state.0.lock().unwrap().devices.clone();
    let _ = emit_devices_event(app, devices);
}

/// Non-demo builds have no `AppData::devices` field to read (real device
/// state lives in `composition::Composition` instead) — see module doc
/// comment for why `finish_transfer`'s device-mutation-on-failure path
/// only ever fires under the `demo` feature in the first place.
#[cfg(not(feature = "demo"))]
fn emit_devices(_app: &AppHandle) {}

fn emit_transfers(app: &AppHandle) {
    let state = app.state::<AppState>();
    let (composition, demo_transfers) = {
        let data = state.0.lock().unwrap();
        (
            data.composition.clone(),
            data.demo_transfer_state.transfers().to_vec(),
        )
    };
    let mut transfers = match composition.transfer_projections() {
        Ok(transfers) => transfers,
        Err(error) => {
            eprintln!("[demo] cannot emit transfers: durable projection read failed: {error}");
            return;
        }
    };
    transfers.extend(demo_transfers);
    let _ = emit_transfers_event(app, transfers);
}

fn emit_library(app: &AppHandle) {
    let state = app.state::<AppState>();
    let library = state
        .0
        .lock()
        .unwrap()
        .library
        .iter()
        .map(LibraryEntry::view)
        .collect::<Vec<_>>();
    let _ = emit_library_event(app, library);
}

fn emit_sessions(app: &AppHandle, device_id: &str) {
    let state = app.state::<AppState>();
    let sessions = state.0.lock().unwrap().session_views(device_id);
    let _ = emit_sessions_event(app, device_id, sessions);
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    // PC-08 incidental fix: the previous `state.0.lock().unwrap().notify_enabled`
    // as a block tail expression does not borrow-check (E0597 -- `State`'s
    // `Deref::deref` ties its output to `&state`'s own borrow, which does
    // not outlive the anonymous `MutexGuard` temporary at the end of this
    // block). Binding the guard to `data` first (same fix applied to the
    // real device/pairing calls introduced in `commands.rs`) resolves it.
    let enabled = {
        let state = app.state::<AppState>();
        let data = state.0.lock().unwrap();
        data.notify_enabled
    };
    if !enabled {
        return;
    }
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

/* ------------------------------- pairing ------------------------------- */

/// Drives the on-device confirmation wait described in
/// LAN_TRANSFER_PROTOCOL.md §4.3.1. Polls its own cancellation by checking
/// whether the device is still `Pending` each tick, so `cancel_pairing`
/// (which just flips the device back to `Idle`) is enough to stop it — no
/// explicit cancellation token needed for a wait this short.
///
/// `#[cfg(feature = "demo")]`-only (PC-08) — real pairing is
/// `composition::run_pairing` now; this remains reachable only through
/// `commands.rs`'s demo-fleet fallback path.
#[cfg(feature = "demo")]
pub async fn run_pairing(app: AppHandle, device_id: String, attempt_id: String) {
    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();
        if let Some(d) = data.devices.iter_mut().find(|d| d.id == device_id) {
            d.state = DeviceState::Pending;
        }
    }
    emit_devices(&app);

    for remaining in (0..=PAIRING_TOTAL_TICKS).rev() {
        if !is_pending(&app, &device_id) {
            return;
        }
        let _ = emit_pairing_event(
            &app,
            false,
            serde_json::json!({ "deviceId": device_id, "attemptId": attempt_id, "remaining": remaining, "total": PAIRING_TOTAL_TICKS }),
        );
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(PAIRING_TICK_MS)).await;
    }

    if !is_pending(&app, &device_id) {
        return;
    }

    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();
        if let Some(d) = data.devices.iter_mut().find(|d| d.id == device_id) {
            d.state = DeviceState::Connected;
        }
    }
    emit_devices(&app);
    let _ = emit_pairing_event(
        &app,
        true,
        serde_json::json!({
            "deviceId": device_id,
            "attemptId": attempt_id,
            "outcome": "connected",
            "error": null,
        }),
    );
}

#[cfg(feature = "demo")]
fn is_pending(app: &AppHandle, device_id: &str) -> bool {
    let state = app.state::<AppState>();
    let data = state.0.lock().unwrap();
    matches!(
        data.devices
            .iter()
            .find(|d| d.id == device_id)
            .map(|d| d.state),
        Some(DeviceState::Pending)
    )
}

/* ------------------------------ transfers ------------------------------ */

pub struct StartTransferArgs {
    pub label: String,
    pub total_bytes: u64,
    pub direction: TransferDirection,
    pub target_label: String,
    pub context: DemoTransferContext,
}

/// Enqueues a transfer and starts it immediately if under the concurrency
/// cap, otherwise marks it `queued` — mirrors the original prototype's
/// `startTransfer`/`processQueue` pair, including the off-by-one fix (the
/// capacity check happens before the new transfer is added to the active
/// count).
pub fn start_transfer(app: &AppHandle, args: StartTransferArgs) -> String {
    let key = uuid::Uuid::new_v4().to_string();
    let run_now;
    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();
        let active = data
            .demo_transfer_state
            .transfers()
            .iter()
            .filter(|t| matches!(t.state, TransferState::Preparing | TransferState::Running))
            .count();
        run_now = active < MAX_CONCURRENT_TRANSFERS;

        data.demo_transfer_state.transfers_mut().insert(
            0,
            Transfer {
                key: key.clone(),
                label: args.label,
                total_bytes: args.total_bytes,
                sent_bytes: 0,
                state: if run_now {
                    TransferState::Preparing
                } else {
                    TransferState::Queued
                },
                error: None,
                retryable: false,
                direction: args.direction,
                target_label: args.target_label,
            },
        );
        data.demo_transfer_state
            .insert(key.clone(), args.context.clone());
    }
    emit_transfers(app);
    emit_for_context(app, &args.context);

    if run_now {
        let app2 = app.clone();
        let key2 = key.clone();
        tauri::async_runtime::spawn(async move { run_transfer(app2, key2).await });
    }
    key
}

fn emit_for_context(app: &AppHandle, context: &DemoTransferContext) {
    match context {
        DemoTransferContext::DownloadSession { device_id, .. } => emit_sessions(app, device_id),
        DemoTransferContext::DownloadFile => {}
    }
}

/// Resumes a failed transfer from its last `sent_bytes` — this is the
/// client-side half of the Range-based resume described in
/// LAN_TRANSFER_PROTOCOL.md §5.3; `sent_bytes` is deliberately *not* reset.
pub fn retry_transfer(app: &AppHandle, key: &str) -> bool {
    let run_now;
    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();
        if !data.demo_transfer_state.contains(key) {
            return false;
        }
        let active = data
            .demo_transfer_state
            .transfers()
            .iter()
            .filter(|t| {
                t.key != key && matches!(t.state, TransferState::Preparing | TransferState::Running)
            })
            .count();
        run_now = active < MAX_CONCURRENT_TRANSFERS;
        if !prepare_demo_retry(data.demo_transfer_state.transfers_mut(), key, run_now) {
            return false;
        }
    }
    emit_transfers(app);
    if run_now {
        let app2 = app.clone();
        let key2 = key.to_string();
        tauri::async_runtime::spawn(async move { run_transfer(app2, key2).await });
    }
    true
}

fn prepare_demo_retry(transfers: &mut [Transfer], key: &str, run_now: bool) -> bool {
    let Some(transfer) = transfers
        .iter_mut()
        .find(|transfer| transfer.key == key && transfer.state == TransferState::Failed)
    else {
        return false;
    };
    transfer.state = if run_now {
        TransferState::Preparing
    } else {
        TransferState::Queued
    };
    transfer.error = None;
    true
}

async fn run_transfer(app: AppHandle, key: String) {
    let (total_bytes, mut sent_bytes) = {
        let state = app.state::<AppState>();
        let data = state.0.lock().unwrap();
        match data
            .demo_transfer_state
            .transfers()
            .iter()
            .find(|t| t.key == key)
        {
            Some(t) => (t.total_bytes, t.sent_bytes),
            None => return,
        }
    };

    let (will_fail, fail_point, speed_bps) = {
        let mut rng = rand::thread_rng();
        let will_fail = rng.gen_bool(0.22);
        let fail_point = 0.35 + rng.gen::<f64>() * 0.4;
        let speed_bps = total_bytes as f64 / (2.2 + rng.gen::<f64>() * 1.6);
        (will_fail, fail_point, speed_bps)
    };

    loop {
        tokio::time::sleep(Duration::from_millis(TRANSFER_TICK_MS)).await;

        let jitter = 0.7 + rand::thread_rng().gen::<f64>() * 0.6;
        let increment = speed_bps * (TRANSFER_TICK_MS as f64 / 1000.0) * jitter;
        sent_bytes = ((sent_bytes as f64 + increment).min(total_bytes as f64)) as u64;
        let fraction = if total_bytes > 0 {
            sent_bytes as f64 / total_bytes as f64
        } else {
            1.0
        };

        if will_fail && fraction >= fail_point {
            // PC-08 incidental fix: same E0597 temporary-lifetime issue as
            // `notify()` above -- bind the guard to `data` before chaining.
            let direction = {
                let state = app.state::<AppState>();
                let data = state.0.lock().unwrap();
                data.demo_transfer_state
                    .transfers()
                    .iter()
                    .find(|t| t.key == key)
                    .map(|t| t.direction)
            };
            let error = match direction {
                Some(TransferDirection::Down) => "连接中断，设备可能已离线",
                _ => "无法连接到对象存储",
            };
            finish_transfer(&app, &key, sent_bytes, Some(error.to_string())).await;
            return;
        }
        if sent_bytes >= total_bytes {
            finish_transfer(&app, &key, total_bytes, None).await;
            return;
        }

        {
            let state = app.state::<AppState>();
            let mut data = state.0.lock().unwrap();
            if let Some(t) = data
                .demo_transfer_state
                .transfers_mut()
                .iter_mut()
                .find(|t| t.key == key)
            {
                t.sent_bytes = sent_bytes;
            }
        }
        emit_transfers(&app);
    }
}

/// Applies the side effect for whatever this transfer was *for* (mark a
/// download done/failed, add a library entry, mark an upload done/failed),
/// persists if the library changed, emits the relevant update events, shows
/// a notification if enabled, and finally lets a queued transfer take the
/// freed concurrency slot.
async fn finish_transfer(app: &AppHandle, key: &str, sent_bytes: u64, error: Option<String>) {
    let failed = error.is_some();
    let mut touched_device: Option<String> = None;
    let mut touched_library = false;
    let transfer_snapshot;
    let context;

    {
        let state = app.state::<AppState>();
        let mut data = state.0.lock().unwrap();

        if let Some(t) = data
            .demo_transfer_state
            .transfers_mut()
            .iter_mut()
            .find(|t| t.key == key)
        {
            t.sent_bytes = sent_bytes;
            t.state = if failed {
                TransferState::Failed
            } else {
                TransferState::Succeeded
            };
            t.error = error.clone();
            t.retryable = failed;
        }
        transfer_snapshot = data
            .demo_transfer_state
            .transfers()
            .iter()
            .find(|t| t.key == key)
            .cloned();
        context = data.demo_transfer_state.remove(key);

        if let Some(ctx) = &context {
            match ctx {
                DemoTransferContext::DownloadSession {
                    device_id,
                    session_id,
                } => {
                    if !failed {
                        let session = data
                            .sessions
                            .get(device_id)
                            .and_then(|list| list.iter().find(|s| &s.id == session_id))
                            .cloned();
                        if let Some(session) = session {
                            let already = data
                                .library
                                .iter()
                                .any(|e| &e.device_id == device_id && &e.session_id == session_id);
                            if !already {
                                data.library.insert(
                                    0,
                                    LibraryEntry {
                                        device_id: device_id.clone(),
                                        session_id: session_id.clone(),
                                        date_label: session.date_label.clone(),
                                        downloaded_at: "刚刚".to_string(),
                                        bytes: session.video_bytes,
                                        processed_files: Vec::new(),
                                        files: session.files.clone(),
                                        complete: true,
                                        publication: None,
                                        library_root: None,
                                        object_receipts: Vec::new(),
                                        upload_projection: None,
                                        upload_status: UploadStatus::None,
                                        upload_retryable: false,
                                        uploaded_at: None,
                                        upload_error: None,
                                    },
                                );
                                touched_library = true;
                            }
                        }
                    } else {
                        #[cfg(feature = "demo")]
                        if let Some(d) = data.devices.iter_mut().find(|d| &d.id == device_id) {
                            if d.state == DeviceState::Connected {
                                d.state = DeviceState::Error;
                                touched_device = Some(device_id.clone());
                            }
                        }
                    }
                }
                DemoTransferContext::DownloadFile => {}
            }
        }
        if touched_library {
            data.persist();
        }
        // A failed demo row remains explicitly retryable while its visible
        // failed transfer exists. Success consumes the context permanently;
        // the workflow also verifies that failed row before routing a retry,
        // so a later row removal cannot leave a stale classification.
        if failed {
            if let Some(context) = context.clone() {
                data.demo_transfer_state.insert(key.to_string(), context);
            }
        }
    }

    emit_transfers(app);
    if touched_library {
        emit_library(app);
    }
    if let Some(device_id) = &touched_device {
        emit_devices(app);
        emit_sessions(app, device_id);
    } else if let Some(DemoTransferContext::DownloadSession { device_id, .. }) = &context {
        emit_sessions(app, device_id);
    }

    if let Some(t) = &transfer_snapshot {
        let direction_label = if matches!(t.direction, TransferDirection::Up) {
            "上传"
        } else {
            "下载"
        };
        if failed {
            notify(
                app,
                "YLX Transfer · 传输失败",
                &format!(
                    "{direction_label}失败：{}",
                    t.error.clone().unwrap_or_default()
                ),
            );
        } else {
            notify(
                app,
                "YLX Transfer · 传输完成",
                &format!("{direction_label}完成 · {}", t.label),
            );
        }
    }

    process_queue(app);
}

fn process_queue(app: &AppHandle) {
    loop {
        let next_key = {
            let state = app.state::<AppState>();
            let mut data = state.0.lock().unwrap();
            let active = data
                .demo_transfer_state
                .transfers()
                .iter()
                .filter(|t| matches!(t.state, TransferState::Preparing | TransferState::Running))
                .count();
            if active >= MAX_CONCURRENT_TRANSFERS {
                return;
            }
            let idx = data
                .demo_transfer_state
                .transfers()
                .iter()
                .enumerate()
                .filter(|(_, t)| t.state == TransferState::Queued)
                .map(|(i, _)| i)
                .next_back();
            match idx {
                None => return,
                Some(i) => {
                    let transfers = data.demo_transfer_state.transfers_mut();
                    transfers[i].state = TransferState::Preparing;
                    Some(transfers[i].key.clone())
                }
            }
        };
        match next_key {
            Some(key) => {
                emit_transfers(app);
                let app2 = app.clone();
                tauri::async_runtime::spawn(async move { run_transfer(app2, key).await });
            }
            None => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_transfer_state_owns_only_demo_download_context() {
        let mut state = DemoTransferState::default();
        state.insert(
            "session-job".to_string(),
            DemoTransferContext::DownloadSession {
                device_id: "demo-device".to_string(),
                session_id: "demo-session".to_string(),
            },
        );
        state.insert("file-job".to_string(), DemoTransferContext::DownloadFile);

        assert!(state.contains("session-job"));
        assert!(matches!(
            state.get("session-job"),
            Some(DemoTransferContext::DownloadSession { device_id, session_id })
                if device_id == "demo-device" && session_id == "demo-session"
        ));
        assert_eq!(
            state.get("file-job"),
            Some(&DemoTransferContext::DownloadFile)
        );
        assert_eq!(
            state.remove("session-job"),
            Some(DemoTransferContext::DownloadSession {
                device_id: "demo-device".to_string(),
                session_id: "demo-session".to_string(),
            })
        );
        assert!(
            !state.contains("session-job"),
            "a terminal demo transfer must not remain retry-routable"
        );
        assert!(!state.contains("unknown-job"));

        let mut transfers = vec![
            Transfer {
                key: "failed-job".to_string(),
                label: "failed".to_string(),
                total_bytes: 10,
                sent_bytes: 5,
                state: TransferState::Failed,
                error: Some("network".to_string()),
                retryable: true,
                direction: TransferDirection::Down,
                target_label: "demo-device".to_string(),
            },
            Transfer {
                key: "succeeded-job".to_string(),
                label: "succeeded".to_string(),
                total_bytes: 10,
                sent_bytes: 10,
                state: TransferState::Succeeded,
                error: None,
                retryable: false,
                direction: TransferDirection::Down,
                target_label: "demo-device".to_string(),
            },
        ];
        assert!(prepare_demo_retry(&mut transfers, "failed-job", true));
        assert_eq!(transfers[0].state, TransferState::Preparing);
        assert!(transfers[0].error.is_none());
        assert!(
            !prepare_demo_retry(&mut transfers, "failed-job", true),
            "the same failed row can transition only once"
        );
        assert!(
            !prepare_demo_retry(&mut transfers, "succeeded-job", true),
            "a non-failed demo row is never retryable"
        );
    }
}
