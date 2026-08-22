//! Process-local concurrency gates for import effects.
//!
//! The durable job aggregate prevents two owners from publishing conflicting
//! state. These gates solve the separate runtime problem: one physical card
//! should have one sequential reader, while a job must never have two writers
//! even when its locator changes between LAN and removable media.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::ingest::{ImportJobId, MediaLocator};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PhysicalMediaKey(String);

impl PhysicalMediaKey {
    /// Observation epochs and root-marker digests deliberately do not
    /// participate. A remove/arrival rescan, or a new recording on the same
    /// card, must not accidentally create a second physical-reader lane while
    /// an older observation is still draining.
    pub(crate) fn from_locator(locator: &MediaLocator) -> Option<Self> {
        let generation = locator.media_generation()?;
        Some(Self(generation.platform_volume_identity().to_string()))
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReaderGateRegistry {
    gates: Mutex<HashMap<PhysicalMediaKey, Arc<Mutex<()>>>>,
}

impl ReaderGateRegistry {
    pub(crate) fn gate_for(&self, key: &PhysicalMediaKey) -> Arc<Mutex<()>> {
        let mut gates = lock(&self.gates);
        Arc::clone(
            gates
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct JobControlRegistry {
    controls: Mutex<HashMap<ImportJobId, Arc<JobControl>>>,
}

impl JobControlRegistry {
    pub(crate) fn control_for(&self, job_id: &ImportJobId) -> Arc<JobControl> {
        let mut controls = lock(&self.controls);
        Arc::clone(
            controls
                .entry(job_id.clone())
                .or_insert_with(|| Arc::new(JobControl::default())),
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct JobControl {
    writer: Mutex<()>,
    stop_requested: AtomicBool,
}

impl JobControl {
    pub(crate) fn writer(&self) -> MutexGuard<'_, ()> {
        lock(&self.writer)
    }

    pub(crate) fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Release);
    }

    pub(crate) fn clear_stop(&self) {
        self.stop_requested.store(false, Ordering::Release);
    }

    pub(crate) fn should_stop(&self) -> bool {
        self.stop_requested.load(Ordering::Acquire)
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
