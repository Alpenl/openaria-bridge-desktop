//! Ubuntu lifecycle owner for mounted-media recovery and observation.
//!
//! The runtime is refreshed before durable import recovery on every process
//! start. That ordering is material: a recoverable import resolves its sealed
//! media generation through the runtime's live candidate/locator cache, so
//! recovering it before the mounted-volume scan would turn a present card into
//! a false `waiting_for_media` transition.
//!
//! This module deliberately depends only on narrow recovery and projection
//! seams. The concrete import, normalizer, and pipeline graphs are assembled
//! elsewhere and can evolve without changing the application lifecycle port.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::ports::{
    MediaErrorCode, MediaLifecyclePort, MediaPortError, MediaProjectionDelta, MediaProjectionSet,
    MediaProjectionSink, Observed,
};
use super::types::{DerivationJob, ImportJob};
use super::ubuntu::UbuntuMediaRuntime;

const DEFAULT_MOUNTED_MEDIA_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MOUNTED_MEDIA_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MOUNTED_MEDIA_STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Recovers imports after the Ubuntu runtime has rebuilt its mounted-media
/// candidate cache. Implementations must return the authoritative durable
/// import collection after recovery, not a locally cached job list.
pub trait UbuntuImportRecovery: Send + Sync {
    fn recover_imports(&self) -> Result<Observed<Vec<ImportJob>>, MediaPortError>;

    /// Releases worker lanes after recovery and managed-state registration.
    /// The default keeps lightweight test adapters compatible.
    fn start(&self) -> Result<(), MediaPortError> {
        Ok(())
    }

    /// Releases import-worker resources owned by this recovery implementation.
    /// The synchronous Ubuntu ingestor has nothing extra to release, so the
    /// default is intentionally a no-op. Implementations must be idempotent so
    /// lifecycle stop can retry after another owner reports `ResourceStuck`.
    fn shutdown(&self) -> Result<(), MediaPortError> {
        Ok(())
    }
}

/// Optional normalizer recovery. It remains separate because the Ubuntu MVP
/// can recover imports even when no reviewed quality-evidence evaluator has
/// been installed for derivations.
pub trait UbuntuNormalizerRecovery: Send + Sync {
    fn recover_derivations(&self) -> Result<Observed<Vec<DerivationJob>>, MediaPortError>;

    /// Stops process-owning derivation resources before the lifecycle reports
    /// shutdown complete. Implementations that do not own workers may keep the
    /// default no-op. Implementations must be idempotent across stop retries.
    fn shutdown(&self) -> Result<(), MediaPortError> {
        Ok(())
    }
}

/// Reads the complete durable application projection after recovery. The
/// lifecycle overwrites scan/import/optional-derivation entries with the exact
/// values produced in this recovery pass, while this supplier owns pipeline
/// and any future durable resource projections.
pub trait UbuntuProjectionSupplier: Send + Sync {
    fn durable_projections(&self) -> Result<MediaProjectionSet, MediaPortError>;
}

impl<F> UbuntuImportRecovery for F
where
    F: Fn() -> Result<Observed<Vec<ImportJob>>, MediaPortError> + Send + Sync,
{
    fn recover_imports(&self) -> Result<Observed<Vec<ImportJob>>, MediaPortError> {
        self()
    }
}

impl<F> UbuntuNormalizerRecovery for F
where
    F: Fn() -> Result<Observed<Vec<DerivationJob>>, MediaPortError> + Send + Sync,
{
    fn recover_derivations(&self) -> Result<Observed<Vec<DerivationJob>>, MediaPortError> {
        self()
    }
}

impl<F> UbuntuProjectionSupplier for F
where
    F: Fn() -> Result<MediaProjectionSet, MediaPortError> + Send + Sync,
{
    fn durable_projections(&self) -> Result<MediaProjectionSet, MediaPortError> {
        self()
    }
}

/// Closure-backed recovery adapter for a composition whose executor also owns
/// explicit shutdown work. Plain recovery closures implement the recovery
/// traits directly; use this helper when the composition must reap a worker or
/// process owner during lifecycle shutdown.
pub struct UbuntuRecoveryAdapter<T: 'static> {
    recover: Arc<dyn Fn() -> Result<T, MediaPortError> + Send + Sync>,
    start: Arc<dyn Fn() -> Result<(), MediaPortError> + Send + Sync>,
    shutdown: Arc<dyn Fn() -> Result<(), MediaPortError> + Send + Sync>,
}

impl<T: 'static> UbuntuRecoveryAdapter<T> {
    #[must_use]
    pub fn with_shutdown(
        recover: impl Fn() -> Result<T, MediaPortError> + Send + Sync + 'static,
        shutdown: impl Fn() -> Result<(), MediaPortError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            recover: Arc::new(recover),
            start: Arc::new(|| Ok(())),
            shutdown: Arc::new(shutdown),
        }
    }

    #[must_use]
    pub fn with_start_shutdown(
        recover: impl Fn() -> Result<T, MediaPortError> + Send + Sync + 'static,
        start: impl Fn() -> Result<(), MediaPortError> + Send + Sync + 'static,
        shutdown: impl Fn() -> Result<(), MediaPortError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            recover: Arc::new(recover),
            start: Arc::new(start),
            shutdown: Arc::new(shutdown),
        }
    }

    fn recover(&self) -> Result<T, MediaPortError> {
        (self.recover)()
    }

    fn stop(&self) -> Result<(), MediaPortError> {
        (self.shutdown)()
    }

    fn start(&self) -> Result<(), MediaPortError> {
        (self.start)()
    }
}

/// A shutdown-aware adapter for `UbuntuImportRecovery`.
pub type UbuntuImportRecoveryAdapter = UbuntuRecoveryAdapter<Observed<Vec<ImportJob>>>;

/// A shutdown-aware adapter for `UbuntuNormalizerRecovery`.
pub type UbuntuNormalizerRecoveryAdapter = UbuntuRecoveryAdapter<Observed<Vec<DerivationJob>>>;

impl UbuntuImportRecovery for UbuntuImportRecoveryAdapter {
    fn recover_imports(&self) -> Result<Observed<Vec<ImportJob>>, MediaPortError> {
        self.recover()
    }

    fn start(&self) -> Result<(), MediaPortError> {
        self.start()
    }

    fn shutdown(&self) -> Result<(), MediaPortError> {
        self.stop()
    }
}

impl UbuntuNormalizerRecovery for UbuntuNormalizerRecoveryAdapter {
    fn recover_derivations(&self) -> Result<Observed<Vec<DerivationJob>>, MediaPortError> {
        self.recover()
    }

    fn shutdown(&self) -> Result<(), MediaPortError> {
        self.stop()
    }
}

struct PollControl {
    stopping: Mutex<bool>,
    wake: Condvar,
}

impl PollControl {
    fn new() -> Self {
        Self {
            stopping: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn wait_for_stop(&self, interval: Duration) -> bool {
        let guard = lock(&self.stopping);
        if *guard {
            return true;
        }
        let (guard, _) = self
            .wake
            .wait_timeout_while(guard, interval, |stopping| !*stopping)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard
    }

    fn requested(&self) -> bool {
        *lock(&self.stopping)
    }

    fn request_stop(&self) {
        *lock(&self.stopping) = true;
        self.wake.notify_all();
    }
}

struct MountedMediaPoller {
    control: Arc<PollControl>,
    worker: Option<JoinHandle<()>>,
}

impl MountedMediaPoller {
    fn stop(&mut self, timeout: Duration) -> Result<(), MediaPortError> {
        self.control.request_stop();
        let deadline = Instant::now() + timeout;
        loop {
            let Some(worker) = self.worker.as_ref() else {
                return Ok(());
            };
            if worker.is_finished() {
                let worker = self
                    .worker
                    .take()
                    .expect("finished mounted-media worker remains installed");
                return worker.join().map_err(|_| {
                    MediaPortError::new(
                        MediaErrorCode::ResourceStuck,
                        "Ubuntu mounted-media watcher terminated unexpectedly during shutdown",
                    )
                    .with_retryable(false)
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(MediaPortError::new(
                    MediaErrorCode::ResourceStuck,
                    format!(
                        "Ubuntu mounted-media watcher did not stop within {} milliseconds",
                        timeout.as_millis()
                    ),
                )
                .with_retryable(true));
            }
            thread::sleep(
                MOUNTED_MEDIA_STOP_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
            );
        }
    }
}

#[derive(Default)]
struct LifecycleState {
    shutdown_requested: bool,
    resources_stopped: bool,
    watcher_started: bool,
    poller: Option<MountedMediaPoller>,
    imports_stopped: bool,
    runtime_stopped: bool,
    normalizer_stopped: bool,
}

/// Linux-only lifecycle port that owns startup recovery and, by default, a
/// bounded mounted-volume refresh worker.
pub struct UbuntuMediaLifecycle {
    runtime: Arc<UbuntuMediaRuntime>,
    imports: Arc<dyn UbuntuImportRecovery>,
    normalizer: Option<Arc<dyn UbuntuNormalizerRecovery>>,
    projections: Arc<dyn UbuntuProjectionSupplier>,
    refresh_interval: Duration,
    operation_gate: Mutex<()>,
    state: Mutex<LifecycleState>,
    last_watcher_error: Arc<Mutex<Option<MediaPortError>>>,
}

impl UbuntuMediaLifecycle {
    /// Builds the normal Ubuntu lifecycle with a two-second mounted-volume
    /// reconciliation interval. The first scan is performed by `recover`, not
    /// here, so composition can finish assembling all durable owners first.
    #[must_use]
    pub fn new(
        runtime: Arc<UbuntuMediaRuntime>,
        imports: Arc<dyn UbuntuImportRecovery>,
        normalizer: Option<Arc<dyn UbuntuNormalizerRecovery>>,
        projections: Arc<dyn UbuntuProjectionSupplier>,
    ) -> Self {
        Self {
            runtime,
            imports,
            normalizer,
            projections,
            refresh_interval: DEFAULT_MOUNTED_MEDIA_POLL_INTERVAL,
            operation_gate: Mutex::new(()),
            state: Mutex::new(LifecycleState::default()),
            last_watcher_error: Arc::new(Mutex::new(None)),
        }
    }

    /// Erases the concrete type for `MediaApplicationPorts`.
    #[must_use]
    pub fn into_port(self) -> Arc<dyn MediaLifecyclePort> {
        Arc::new(self)
    }

    fn ensure_activation_allowed(&self) -> Result<(), MediaPortError> {
        if lock(&self.state).shutdown_requested {
            Err(MediaPortError::new(
                MediaErrorCode::OperationConflict,
                "Ubuntu mounted-media shutdown has started and cannot be restarted in this process",
            )
            .with_retryable(false))
        } else {
            Ok(())
        }
    }

    fn start_poller(
        &self,
        sink: Arc<dyn MediaProjectionSink>,
        interval: Duration,
    ) -> Result<MountedMediaPoller, MediaPortError> {
        let control = Arc::new(PollControl::new());
        let runtime = Arc::clone(&self.runtime);
        let errors = Arc::clone(&self.last_watcher_error);
        let worker_control = Arc::clone(&control);
        let worker = thread::Builder::new()
            .name("ylx-ubuntu-media-poll".to_string())
            .spawn(move || loop {
                // Recovery already performed the initial scan. Waiting first
                // avoids immediately issuing a duplicate durable observation.
                if worker_control.wait_for_stop(interval) {
                    break;
                }
                let refresh = runtime.poll_mounted_volume_events();
                if worker_control.requested() {
                    break;
                }
                match refresh {
                    Ok(Some(scan)) => {
                        if let Err(error) = sink.publish(MediaProjectionDelta::scan(scan)) {
                            *lock(&errors) = Some(error);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        *lock(&errors) = Some(error);
                    }
                }
            })
            .map_err(|error| {
                MediaPortError::new(
                    MediaErrorCode::ResourceStuck,
                    format!("cannot start Ubuntu mounted-media watcher: {error}"),
                )
            })?;
        Ok(MountedMediaPoller {
            control,
            worker: Some(worker),
        })
    }

    fn stop_owned_resources(&self) -> Result<(), MediaPortError> {
        let _operation = lock(&self.operation_gate);
        let mut poller = {
            let mut state = lock(&self.state);
            if state.resources_stopped {
                return Ok(());
            }
            state.shutdown_requested = true;
            state.watcher_started = false;
            state.poller.take()
        };

        // Stop observation first so no scan can race the cancellation and
        // generation release sequence below. Do not return early: every owner
        // gets a shutdown opportunity even when another owner reports a
        // failure, and successful owners are not called again on a retry.
        let poller_error = poller
            .as_mut()
            .and_then(|worker| worker.stop(MOUNTED_MEDIA_STOP_TIMEOUT).err());
        let poller_stopped = poller_error.is_none();
        if !poller_stopped {
            lock(&self.state).poller = poller.take();
        }
        let mut first_error = poller_error;
        if let Some(error) = lock(&self.last_watcher_error).take() {
            eprintln!("[media] Ubuntu mounted-media watcher last reported: {error:?}");
        }
        let imports_pending = !lock(&self.state).imports_stopped;
        if imports_pending {
            match self.imports.shutdown() {
                Ok(()) => lock(&self.state).imports_stopped = true,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        // A poller that missed its deadline may still own `scan_gate`. Leave
        // the runtime intact for the next stop pass instead of blocking while
        // acquiring the same gate here.
        let runtime_pending = poller_stopped && !lock(&self.state).runtime_stopped;
        if runtime_pending {
            match self.runtime.shutdown() {
                Ok(()) => lock(&self.state).runtime_stopped = true,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        let normalizer_pending = self.normalizer.is_some() && !lock(&self.state).normalizer_stopped;
        if normalizer_pending {
            if let Some(normalizer) = &self.normalizer {
                match normalizer.shutdown() {
                    Ok(()) => lock(&self.state).normalizer_stopped = true,
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
        }

        let complete = {
            let mut state = lock(&self.state);
            let complete = state.imports_stopped
                && state.runtime_stopped
                && (self.normalizer.is_none() || state.normalizer_stopped)
                && state.poller.is_none();
            state.resources_stopped = complete;
            complete
        };
        if let Some(error) = first_error {
            return Err(error);
        }
        if !complete {
            return Err(MediaPortError::new(
                MediaErrorCode::ResourceStuck,
                "Ubuntu mounted-media shutdown did not release every owned resource",
            ));
        }
        Ok(())
    }
}

impl MediaLifecyclePort for UbuntuMediaLifecycle {
    fn recover(&self) -> Result<MediaProjectionSet, MediaPortError> {
        let _operation = lock(&self.operation_gate);
        self.ensure_activation_allowed()?;

        // This must be first. It binds every scanned candidate to the current
        // volume generation before recoverable imports resolve their locators.
        let scan = self.runtime.refresh_mounted_volumes()?;
        let imports = self.imports.recover_imports()?;
        let derivations = self
            .normalizer
            .as_ref()
            .map(|normalizer| normalizer.recover_derivations())
            .transpose()?;

        // Read the durable owner only after all recovery transitions have
        // committed, then replace the resources observed in this exact pass.
        let mut projections = self.projections.durable_projections()?;
        projections.scan = scan;
        projections.imports = imports;
        if let Some(derivations) = derivations {
            projections.derivations = derivations;
        }
        Ok(projections)
    }

    fn start(&self, sink: Arc<dyn MediaProjectionSink>) -> Result<(), MediaPortError> {
        let _operation = lock(&self.operation_gate);
        self.ensure_activation_allowed()?;
        if lock(&self.state).watcher_started {
            return Ok(());
        }

        // Recovery must complete before any lane can consume its durable
        // queue. Starting the lanes here also makes the lifecycle the single
        // owner of activation ordering, while keeping callbacks outside the
        // lifecycle state mutex.
        self.imports.start()?;

        let mut state = lock(&self.state);
        *lock(&self.last_watcher_error) = None;
        let poller = match self.start_poller(sink, self.refresh_interval) {
            Ok(poller) => poller,
            Err(error) => {
                // The lane has already been released. Ask it to stop before
                // returning so a failed watcher start cannot leak workers.
                drop(state);
                let _ = self.imports.shutdown();
                return Err(error);
            }
        };
        state.poller = Some(poller);
        state.watcher_started = true;
        Ok(())
    }

    fn stop(&self) -> Result<(), MediaPortError> {
        self.stop_owned_resources()
    }
}

impl Drop for UbuntuMediaLifecycle {
    fn drop(&mut self) {
        let _ = self.stop_owned_resources();
    }
}

/// Convenience constructor used by the Ubuntu composition root.
#[must_use]
pub fn ubuntu_media_lifecycle(
    runtime: Arc<UbuntuMediaRuntime>,
    imports: Arc<dyn UbuntuImportRecovery>,
    normalizer: Option<Arc<dyn UbuntuNormalizerRecovery>>,
    projections: Arc<dyn UbuntuProjectionSupplier>,
) -> Arc<dyn MediaLifecyclePort> {
    UbuntuMediaLifecycle::new(runtime, imports, normalizer, projections).into_port()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poller_timeout_retains_the_handle_for_a_later_stop_retry() {
        let control = Arc::new(PollControl::new());
        let (release, blocked) = std::sync::mpsc::channel();
        let mut poller = MountedMediaPoller {
            control,
            worker: Some(thread::spawn(move || {
                let _ = blocked.recv();
            })),
        };

        assert!(poller.stop(Duration::from_millis(5)).is_err());
        assert!(poller.worker.is_some());

        release.send(()).expect("release poller");
        poller
            .stop(Duration::from_secs(1))
            .expect("retry poller stop");
        assert!(poller.worker.is_none());
    }
}
