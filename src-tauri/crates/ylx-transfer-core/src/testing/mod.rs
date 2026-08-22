//! Deterministic test-support primitives (commit 07).
//!
//! Compiled only under `cfg(test)` (this crate's own unit tests) or with
//! the `testing` cargo feature enabled (integration tests / downstream
//! crates: `ylx-transfer-core = { path = "...", features = ["testing"] }`).
//! Nothing here is ever built into a production binary.
//!
//! # Why this module exists
//!
//! Concurrency tests in this workspace currently reach for
//! `thread::sleep(...)` to "probably" order two threads, or for private
//! coordinator fields to observe internal progress. Both are flaky and
//! both couple tests to implementation details. The five primitives below
//! are the deterministic replacements:
//!
//! - [`Rendezvous`] — "both threads are now at this exact point"; replaces
//!   `sleep` used as a happens-before fence.
//! - [`Deferred`] — a one-shot value another thread blocks on until the
//!   test explicitly releases it; replaces `sleep` used to hold a worker
//!   inside a critical section.
//! - [`FakeClock`] — an explicitly advanced clock; replaces `sleep` used
//!   to let a real timeout/backoff elapse.
//! - [`FaultPoint`] — an injectable, count-bounded failure; replaces
//!   "arrange for the real I/O to fail somehow".
//! - [`RecordingSink`] — an observation channel with a *blocking*
//!   `wait_for(n)`; replaces polling private fields in a sleep loop.
//!
//! Every primitive is `Clone` (an `Arc` handle to shared state), so a test
//! can hand a clone to each spawned thread and keep one for itself, and
//! every blocking operation is bounded by a timeout so a broken test fails
//! instead of hanging a CI run forever.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Upper bound applied by the convenience blocking calls ([`Rendezvous::wait`],
/// [`Deferred::get`]). Generous relative to any in-process signal, small
/// enough that a deadlocked test fails rather than hangs.
pub const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(10);

// =====================================================================
// Rendezvous
// =====================================================================

struct RendezvousState {
    waiting: usize,
    generation: u64,
}

struct RendezvousInner {
    parties: usize,
    state: Mutex<RendezvousState>,
    condvar: Condvar,
}

/// A reusable N-party barrier with timeouts.
///
/// `std::sync::Barrier` has no timed variant, so a test that deadlocks on
/// one hangs the whole suite. This one returns `false` on timeout instead,
/// and its generation counter makes it reusable across rounds.
#[derive(Clone)]
pub struct Rendezvous {
    inner: Arc<RendezvousInner>,
}

impl Rendezvous {
    /// A rendezvous that releases once `parties` threads have arrived.
    /// `parties` is clamped to at least 1.
    #[must_use]
    pub fn new(parties: usize) -> Self {
        Rendezvous {
            inner: Arc::new(RendezvousInner {
                parties: parties.max(1),
                state: Mutex::new(RendezvousState {
                    waiting: 0,
                    generation: 0,
                }),
                condvar: Condvar::new(),
            }),
        }
    }

    /// How many threads are parked at the rendezvous right now.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.inner.state.lock().unwrap().waiting
    }

    /// Arrive and block until every party has arrived (or `timeout`
    /// elapses). Returns `true` iff the rendezvous completed.
    ///
    /// On timeout the caller's arrival is withdrawn, so a timed-out round
    /// cannot silently release a later one.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock().unwrap();
        state.waiting += 1;
        if state.waiting >= self.inner.parties {
            state.waiting = 0;
            state.generation = state.generation.wrapping_add(1);
            self.inner.condvar.notify_all();
            return true;
        }

        let generation = state.generation;
        while state.generation == generation {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Withdraw this arrival: this round never completed.
                state.waiting = state.waiting.saturating_sub(1);
                return false;
            }
            let (next, _) = self
                .inner
                .condvar
                .wait_timeout(state, remaining)
                .expect("rendezvous mutex poisoned");
            state = next;
        }
        true
    }

    /// [`Self::wait_timeout`] with [`DEFAULT_TEST_TIMEOUT`], panicking on
    /// timeout so a stuck test reports the deadlock instead of hanging.
    pub fn wait(&self) {
        assert!(
            self.wait_timeout(DEFAULT_TEST_TIMEOUT),
            "rendezvous timed out after {DEFAULT_TEST_TIMEOUT:?}: not all parties arrived"
        );
    }
}

// =====================================================================
// Deferred
// =====================================================================

struct DeferredInner<T> {
    slot: Mutex<Option<T>>,
    condvar: Condvar,
}

/// A one-shot result the test releases on demand.
///
/// A collaborator (fake port, fake source, …) calls [`Deferred::get`] and
/// blocks; the test thread does its assertions and then calls
/// [`Deferred::release`] to let it proceed. This is the deterministic
/// replacement for "sleep long enough that the worker is probably still
/// inside the call".
pub struct Deferred<T> {
    inner: Arc<DeferredInner<T>>,
}

impl<T> Clone for Deferred<T> {
    fn clone(&self) -> Self {
        Deferred {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Default for Deferred<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Deferred<T> {
    #[must_use]
    pub fn new() -> Self {
        Deferred {
            inner: Arc::new(DeferredInner {
                slot: Mutex::new(None),
                condvar: Condvar::new(),
            }),
        }
    }

    /// Publish the value and wake every waiter. Returns `false` if this
    /// deferred was already released (the new value is dropped) — a
    /// double-release is a test bug, not a silent overwrite.
    pub fn release(&self, value: T) -> bool {
        let mut slot = self.inner.slot.lock().unwrap();
        if slot.is_some() {
            return false;
        }
        *slot = Some(value);
        self.inner.condvar.notify_all();
        true
    }

    #[must_use]
    pub fn is_released(&self) -> bool {
        self.inner.slot.lock().unwrap().is_some()
    }
}

impl<T: Clone> Deferred<T> {
    /// Block until released, or `timeout` elapses. `None` means timeout.
    pub fn get_timeout(&self, timeout: Duration) -> Option<T> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.inner.slot.lock().unwrap();
        loop {
            if let Some(value) = slot.as_ref() {
                return Some(value.clone());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self
                .inner
                .condvar
                .wait_timeout(slot, remaining)
                .expect("deferred mutex poisoned");
            slot = next;
        }
    }

    /// [`Self::get_timeout`] with [`DEFAULT_TEST_TIMEOUT`], panicking on
    /// timeout.
    pub fn get(&self) -> T {
        self.get_timeout(DEFAULT_TEST_TIMEOUT).unwrap_or_else(|| {
            panic!("deferred was never released within {DEFAULT_TEST_TIMEOUT:?}")
        })
    }
}

// =====================================================================
// FakeClock
// =====================================================================

/// A manually advanced monotonic clock.
///
/// "Now" is a [`Duration`] since an arbitrary epoch rather than an
/// `Instant`, because `Instant` cannot be constructed at an arbitrary
/// point on stable Rust. Code under test that takes a `&FakeClock` (or a
/// closure returning `Duration`) can then have its timeouts/backoffs
/// exercised without a single real sleep.
#[derive(Clone, Default)]
pub struct FakeClock {
    now: Arc<Mutex<Duration>>,
}

impl FakeClock {
    /// A clock starting at the epoch (`Duration::ZERO`).
    #[must_use]
    pub fn new() -> Self {
        Self::at(Duration::ZERO)
    }

    #[must_use]
    pub fn at(start: Duration) -> Self {
        FakeClock {
            now: Arc::new(Mutex::new(start)),
        }
    }

    #[must_use]
    pub fn now(&self) -> Duration {
        *self.now.lock().unwrap()
    }

    /// Move the clock forward and return the new "now". Monotonic by
    /// construction: there is no way to move it backwards.
    pub fn advance(&self, by: Duration) -> Duration {
        let mut now = self.now.lock().unwrap();
        *now = now.saturating_add(by);
        *now
    }

    /// Elapsed time since an earlier reading, saturating at zero.
    #[must_use]
    pub fn elapsed_since(&self, earlier: Duration) -> Duration {
        self.now().saturating_sub(earlier)
    }
}

// =====================================================================
// FaultPoint
// =====================================================================

struct FaultState<E> {
    error: Option<E>,
    remaining: usize,
    hits: usize,
    failures: usize,
}

/// An injectable failure site.
///
/// Production-shaped code calls [`FaultPoint::check`] where a real error
/// could occur; a test arms it with [`FaultPoint::fail_times`] (transient)
/// or [`FaultPoint::fail_always`] (permanent). [`FaultPoint::hits`] and
/// [`FaultPoint::failures`] let the test assert the retry budget was
/// actually consumed, without inspecting private state.
pub struct FaultPoint<E> {
    state: Arc<Mutex<FaultState<E>>>,
}

impl<E> Clone for FaultPoint<E> {
    fn clone(&self) -> Self {
        FaultPoint {
            state: self.state.clone(),
        }
    }
}

impl<E> Default for FaultPoint<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> FaultPoint<E> {
    /// A disarmed fault point: [`Self::check`] always succeeds.
    #[must_use]
    pub fn new() -> Self {
        FaultPoint {
            state: Arc::new(Mutex::new(FaultState {
                error: None,
                remaining: 0,
                hits: 0,
                failures: 0,
            })),
        }
    }

    /// Fail the next `times` calls to [`Self::check`], then succeed.
    pub fn fail_times(&self, times: usize, error: E) {
        let mut state = self.state.lock().unwrap();
        state.error = Some(error);
        state.remaining = times;
    }

    /// Fail every call to [`Self::check`] until [`Self::disarm`].
    pub fn fail_always(&self, error: E) {
        let mut state = self.state.lock().unwrap();
        state.error = Some(error);
        state.remaining = usize::MAX;
    }

    pub fn disarm(&self) {
        let mut state = self.state.lock().unwrap();
        state.error = None;
        state.remaining = 0;
    }

    /// Total number of times [`Self::check`] was reached, armed or not.
    #[must_use]
    pub fn hits(&self) -> usize {
        self.state.lock().unwrap().hits
    }

    /// How many of those hits actually returned an error.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.state.lock().unwrap().failures
    }

    #[must_use]
    pub fn is_armed(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.error.is_some() && state.remaining > 0
    }
}

impl<E: Clone> FaultPoint<E> {
    /// The call site. `Ok(())` unless this fault point is armed with
    /// budget remaining, in which case the configured error is returned
    /// and the budget is decremented.
    pub fn check(&self) -> Result<(), E> {
        let mut state = self.state.lock().unwrap();
        state.hits += 1;
        if state.remaining == 0 {
            return Ok(());
        }
        let Some(error) = state.error.clone() else {
            return Ok(());
        };
        if state.remaining != usize::MAX {
            state.remaining -= 1;
        }
        state.failures += 1;
        Err(error)
    }
}

// =====================================================================
// RecordingSink
// =====================================================================

/// An event sink that records everything it is given, with a *blocking*
/// [`RecordingSink::wait_for`] so a test can synchronize on "n events have
/// been emitted" instead of sleeping and hoping.
pub struct RecordingSink<E> {
    events: Arc<(Mutex<Vec<E>>, Condvar)>,
}

impl<E> Clone for RecordingSink<E> {
    fn clone(&self) -> Self {
        RecordingSink {
            events: self.events.clone(),
        }
    }
}

impl<E> Default for RecordingSink<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> RecordingSink<E> {
    #[must_use]
    pub fn new() -> Self {
        RecordingSink {
            events: Arc::new((Mutex::new(Vec::new()), Condvar::new())),
        }
    }

    /// Record one event and wake anything blocked in [`Self::wait_for`].
    pub fn emit(&self, event: E) {
        let (lock, condvar) = &*self.events;
        lock.lock().unwrap().push(event);
        condvar.notify_all();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.0.lock().unwrap().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Block until at least `count` events have been recorded. Returns
    /// `true` iff that happened before `timeout` elapsed.
    pub fn wait_for(&self, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, condvar) = &*self.events;
        let mut events = lock.lock().unwrap();
        loop {
            if events.len() >= count {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, _) = condvar
                .wait_timeout(events, remaining)
                .expect("recording sink mutex poisoned");
            events = next;
        }
    }

    /// Drain everything recorded so far.
    pub fn take(&self) -> Vec<E> {
        std::mem::take(&mut *self.events.0.lock().unwrap())
    }
}

impl<E: Clone> RecordingSink<E> {
    /// A snapshot of everything recorded so far, leaving the log intact.
    #[must_use]
    pub fn events(&self) -> Vec<E> {
        self.events.0.lock().unwrap().clone()
    }
}

// =====================================================================
// Tests — one per helper
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn rendezvous_releases_only_once_every_party_has_arrived() {
        let rendezvous = Rendezvous::new(2);
        let sink: RecordingSink<&'static str> = RecordingSink::new();

        let worker = {
            let rendezvous = rendezvous.clone();
            let sink = sink.clone();
            thread::spawn(move || {
                sink.emit("worker-arrived");
                rendezvous.wait();
                sink.emit("worker-released");
            })
        };

        // The worker cannot get past the rendezvous until we arrive too.
        assert!(sink.wait_for(1, DEFAULT_TEST_TIMEOUT));
        assert_eq!(sink.events(), vec!["worker-arrived"]);

        rendezvous.wait();
        worker.join().expect("worker thread");
        assert_eq!(sink.events(), vec!["worker-arrived", "worker-released"]);
    }

    #[test]
    fn rendezvous_times_out_instead_of_hanging_and_withdraws_the_arrival() {
        let rendezvous = Rendezvous::new(2);
        assert!(!rendezvous.wait_timeout(Duration::from_millis(20)));
        assert_eq!(
            rendezvous.waiting(),
            0,
            "a timed-out arrival must not leak into the next round"
        );
    }

    #[test]
    fn deferred_blocks_until_released_and_then_yields_the_value() {
        let deferred: Deferred<u32> = Deferred::new();
        let sink: RecordingSink<u32> = RecordingSink::new();

        let worker = {
            let deferred = deferred.clone();
            let sink = sink.clone();
            thread::spawn(move || sink.emit(deferred.get()))
        };

        assert!(!deferred.is_released());
        assert!(sink.is_empty());

        assert!(deferred.release(7));
        worker.join().expect("worker thread");
        assert_eq!(sink.events(), vec![7]);

        // One-shot: a second release is rejected, not silently applied.
        assert!(!deferred.release(9));
        assert_eq!(deferred.get(), 7);
        assert_eq!(deferred.get_timeout(Duration::ZERO), Some(7));
    }

    #[test]
    fn deferred_get_timeout_reports_a_never_released_value() {
        let deferred: Deferred<u32> = Deferred::new();
        assert_eq!(deferred.get_timeout(Duration::from_millis(20)), None);
    }

    #[test]
    fn fake_clock_only_moves_when_advanced() {
        let clock = FakeClock::new();
        assert_eq!(clock.now(), Duration::ZERO);

        let start = clock.now();
        let shared = clock.clone();
        thread::spawn(move || shared.advance(Duration::from_secs(30)))
            .join()
            .expect("advancing thread");

        // The advance is visible through the original handle: both are
        // views of the same clock.
        assert_eq!(clock.now(), Duration::from_secs(30));
        assert_eq!(clock.elapsed_since(start), Duration::from_secs(30));
        assert_eq!(
            clock.advance(Duration::from_secs(1)),
            Duration::from_secs(31)
        );
        // Never moves on its own.
        assert_eq!(clock.now(), clock.now());
    }

    #[test]
    fn fault_point_fails_a_bounded_number_of_times_then_recovers() {
        let fault: FaultPoint<&'static str> = FaultPoint::new();
        assert_eq!(fault.check(), Ok(()));
        assert!(!fault.is_armed());

        fault.fail_times(2, "boom");
        assert!(fault.is_armed());
        assert_eq!(fault.check(), Err("boom"));
        assert_eq!(fault.check(), Err("boom"));
        assert_eq!(fault.check(), Ok(()));
        assert_eq!(fault.hits(), 4);
        assert_eq!(fault.failures(), 2);

        fault.fail_always("always");
        assert_eq!(fault.check(), Err("always"));
        assert_eq!(fault.check(), Err("always"));
        fault.disarm();
        assert_eq!(fault.check(), Ok(()));
        assert_eq!(fault.failures(), 4);
    }

    #[test]
    fn recording_sink_wait_for_unblocks_without_polling() {
        let sink: RecordingSink<String> = RecordingSink::new();
        assert!(sink.is_empty());

        let writer = {
            let sink = sink.clone();
            thread::spawn(move || {
                for i in 0..3 {
                    sink.emit(format!("event-{i}"));
                }
            })
        };

        assert!(sink.wait_for(3, DEFAULT_TEST_TIMEOUT));
        writer.join().expect("writer thread");
        assert_eq!(sink.len(), 3);
        assert_eq!(sink.events()[0], "event-0");

        assert!(!sink.wait_for(4, Duration::from_millis(20)));
        assert_eq!(sink.take().len(), 3);
        assert!(sink.is_empty());
    }
}
