//! mDNS candidate browser for `_ylx-capture._tcp.local.`.
//!
//! # Scope: deliberately minimal (this task's own brief)
//!
//! This module browses the Conductor-advertised service and returns a list of
//! *candidates*. It does not attempt resolution retry
//! policy, TTL/staleness tracking beyond "did we see a removal event", or
//! any kind of ranking/preference logic. A caller can build that on
//! top of [`MdnsDiscovery::poll_events`]'s output if/when it's actually
//! needed.
//!
//! # mDNS is discovery-only, never a trust anchor (ADR-DISC-001)
//!
//! Every [`MdnsCandidate`] this module produces is **unauthenticated**:
//! its `device_id`/name/IP/TXT record are exactly what showed up on the
//! local network claiming to be `_ylx-capture._tcp.local.`, which anyone
//! on the same LAN segment can spoof. Nothing in this module (or anywhere
//! else in this crate) may treat a candidate as a paired/trusted device on
//! the strength of this data alone -- the only thing that establishes
//! trust is established outside mDNS: current lab/internal Device API v4
//! callers probe `GET /api/v4/device` over the candidate's advertised
//! host/port and derive the desktop identity from that descriptor, while
//! retained legacy v1 callers use the SAS/TLS-pin path. This module's own type
//! names deliberately say "candidate", not "device", to keep that distinction
//! visible at every call site.
//!
//! # Lifecycle: tagged poll outcomes + RAII shutdown
//!
//! Two lifecycle hazards used to be invisible here and are now modelled
//! explicitly:
//!
//! 1. **A dead browser is not the same as a quiet one.** [`Self::poll`]
//!    used to return `0` both when no event was pending (normal, keep
//!    polling) and when the browse channel had been torn down (the daemon
//!    thread is gone; polling can only ever return `0` again). A caller
//!    driving a `loop { poll(); sleep(); }` would then spin forever on a
//!    daemon that will never speak again. [`MdnsDiscovery::poll_events`]
//!    returns a tagged [`PollOutcome`] instead: [`PollOutcome::Idle`],
//!    [`PollOutcome::Events`], or [`PollOutcome::Disconnected`], the last
//!    of which is a *stop polling* instruction (see
//!    [`PollOutcome::is_disconnected`]).
//! 2. **Stopping the browse must not depend on the happy path.**
//!    Teardown lives in [`BrowseGuard`]'s `Drop`, so the browse is stopped
//!    and the daemon shut down even when the caller drops
//!    [`MdnsDiscovery`] without calling [`MdnsDiscovery::stop`], or when
//!    the poll loop unwinds through a panic. A teardown failure is
//!    returned from [`MdnsDiscovery::stop`] when the caller asked for it,
//!    and logged to stderr when it happens during an implicit drop --
//!    never silently swallowed into a leaked daemon thread.
//!
//! # Real multicast mDNS: not exercised end-to-end in this sandbox
//!
//! [`MdnsDiscovery::start`] constructs a real `mdns-sd` `ServiceDaemon` and
//! issues a real `browse()` call -- this is not a fake. However, this
//! default test environment is not required to support real multicast (a
//! live `_ylx-capture._tcp.local.` advertiser is not started by the test
//! suite). The tests in this
//! module therefore split into two honest categories: (1) real,
//! non-`#[ignore]`d unit tests of the pure `ServiceInfo` -> [`MdnsCandidate`]
//! mapping, the URL-composition helpers, and the poll/teardown state
//! machine driven through an in-memory [`BrowseTransport`] -- none of
//! which needs a network at all; and (2) an `#[ignore]`d
//! `real_daemon_starts_and_can_be_stopped` smoke test that *does* start a
//! real daemon and issue a real `browse()`, run manually
//! (`cargo test -p ylx-transfer-adapters --lib discovery_mdns -- --ignored`)
//! rather than in the default suite, so a sandbox/CI runner without
//! multicast support does not get a flaky/hanging default test run. See
//! that test's own doc comment for exactly what it does and does not
//! prove.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

/// The Conductor Device API's mDNS service type.
pub const YLX_CAPTURE_SERVICE_TYPE: &str = "_ylx-capture._tcp.local.";

/// One unauthenticated mDNS candidate. See module doc comment's
/// ADR-DISC-001 section -- nothing here is trusted on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsCandidate {
    /// The mDNS instance's full service name (`<instance>.{service_type}`),
    /// used as the stable key for update/removal tracking -- not a trusted
    /// device identifier.
    pub fullname: String,
    pub hostname: String,
    /// Every advertised address, IPv4 **and** IPv6 (loopback/link-local
    /// included, no filtering -- a caller attempting a pairing connection
    /// decides which to try, this module does not guess). Sorted
    /// ascending, which puts IPv4 before IPv6 (`IpAddr`'s own `Ord`), so a
    /// caller that just takes `addresses.first()` keeps the historical
    /// IPv4-preferring behaviour while still seeing v6-only devices.
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub txt: HashMap<String, String>,
}

impl MdnsCandidate {
    /// Composes a URL against this candidate's first address (see
    /// [`Self::addresses`] for the ordering), bracketing IPv6 literals
    /// correctly. `None` when the candidate advertised no address at all;
    /// `Err` when the address cannot be expressed as a URL host (which
    /// should not happen for daemon-produced candidates, but is surfaced
    /// rather than silently papered over).
    pub fn url(&self, scheme: &str, path: &str) -> Option<Result<String, MdnsDiscoveryError>> {
        let addr = self.addresses.first()?;
        Some(candidate_url(scheme, &addr.to_string(), self.port, path))
    }
}

fn candidate_from_service_info(info: &ServiceInfo) -> MdnsCandidate {
    let mut addresses: Vec<IpAddr> = info.get_addresses().iter().copied().collect();
    // `get_addresses` hands back a `HashSet`, whose iteration order is
    // unspecified; sort so `addresses.first()` is deterministic (and, per
    // `IpAddr: Ord`, IPv4-first).
    addresses.sort();
    let txt = info
        .get_properties()
        .iter()
        .map(|prop| (prop.key().to_string(), prop.val_str().to_string()))
        .collect();
    MdnsCandidate {
        fullname: info.get_fullname().to_string(),
        hostname: info.get_hostname().to_string(),
        addresses,
        port: info.get_port(),
        txt,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsDiscoveryError {
    /// The `mdns-sd` daemon thread failed to start (e.g. no usable network
    /// interface in this sandbox).
    DaemonUnavailable(String),
    /// Issuing the `browse()`/`stop_browse()`/`shutdown()` call itself
    /// failed.
    Operation(String),
    /// A host string could not be turned into a URL authority: not an IP
    /// literal at all, or an IP literal carrying a malformed/misplaced
    /// zone id. See [`url_host_literal`].
    InvalidAddress(String),
}

impl fmt::Display for MdnsDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonUnavailable(msg) => write!(f, "mdns daemon unavailable: {msg}"),
            Self::Operation(msg) => write!(f, "mdns operation failed: {msg}"),
            Self::InvalidAddress(msg) => write!(f, "invalid mdns address: {msg}"),
        }
    }
}

impl std::error::Error for MdnsDiscoveryError {}

/// Formats a bare IP literal as a URL *host* component, per RFC 3986
/// (`IP-literal`) and RFC 6874 (zone identifiers):
///
/// - IPv4 (`192.168.1.42`) is passed through unchanged.
/// - IPv6 (`fe80::1`, `2001:db8::1`) is bracketed: `[fe80::1]`.
/// - A scoped IPv6 literal (`fe80::1%eth0`) keeps its zone id, which must
///   be **percent-encoded** in a URL because a bare `%` is the
///   percent-encoding escape itself: `[fe80::1%25eth0]`.
///
/// `host` is the raw address as it comes off the wire / out of
/// `IpAddr::to_string()`, i.e. *not* already bracketed and *not* already
/// percent-encoded. Anything else -- a DNS name, an empty string, an
/// already-bracketed literal, a zone id on an IPv4 address, an empty or
/// non-alphanumeric zone id -- is rejected with
/// [`MdnsDiscoveryError::InvalidAddress`] rather than concatenated into a
/// malformed URL.
pub fn url_host_literal(host: &str) -> Result<String, MdnsDiscoveryError> {
    let invalid = || MdnsDiscoveryError::InvalidAddress(host.to_string());
    let (addr_part, zone) = match host.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (host, None),
    };
    let addr: IpAddr = addr_part.parse().map_err(|_| invalid())?;
    match (addr, zone) {
        (IpAddr::V4(v4), None) => Ok(v4.to_string()),
        // Zone ids scope a link-local *IPv6* address to an interface;
        // there is no such thing for IPv4, so this is a malformed input,
        // not something to quietly drop the zone from.
        (IpAddr::V4(_), Some(_)) => Err(invalid()),
        (IpAddr::V6(v6), None) => Ok(format!("[{v6}]")),
        (IpAddr::V6(v6), Some(zone)) => {
            let zone_ok = !zone.is_empty()
                && zone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
            if !zone_ok {
                return Err(invalid());
            }
            Ok(format!("[{v6}%25{zone}]"))
        }
    }
}

/// Composes `{scheme}://{host}:{port}{path}` with `host` formatted by
/// [`url_host_literal`], so IPv6 candidates produce a valid URL
/// (`http://[fe80::1%25eth0]:8080/api/v4`) instead of the malformed
/// `http://fe80::1%eth0:8080/api/v4` that naive `format!` interpolation
/// yields. `path` is normalised to have exactly one leading `/`.
pub fn candidate_url(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> Result<String, MdnsDiscoveryError> {
    let authority = url_host_literal(host)?;
    let path = path.trim_start_matches('/');
    Ok(format!("{scheme}://{authority}:{port}/{path}"))
}

/// One attempt to take an event off the browse channel.
#[derive(Debug)]
pub enum BrowseRecv {
    /// Boxed because `ServiceEvent` embeds a whole `ServiceInfo`, which
    /// would otherwise make every `Empty`/`Disconnected` result carry the
    /// same ~230 bytes around (clippy::large_enum_variant).
    Event(Box<ServiceEvent>),
    /// Nothing pending right now; the channel is still alive.
    Empty,
    /// The sending half is gone -- no further event can ever arrive.
    Disconnected,
}

/// The event source + teardown half of a browse, factored out of
/// [`MdnsDiscovery`] so the lifecycle state machine (drain, disconnect
/// detection, RAII teardown, teardown-failure reporting) can be tested
/// deterministically in-memory instead of via `thread::sleep` against a
/// real multicast daemon.
pub trait BrowseTransport {
    /// Non-blocking single-event take.
    fn try_recv(&self) -> BrowseRecv;
    /// Blocking single-event take, bounded by `timeout`. A timeout maps to
    /// [`BrowseRecv::Empty`], a closed channel to
    /// [`BrowseRecv::Disconnected`].
    fn recv_timeout(&self, timeout: Duration) -> BrowseRecv;
    /// Stops the browse and releases the underlying resources. Called
    /// exactly once, either from [`MdnsDiscovery::stop`] or from
    /// [`BrowseGuard`]'s `Drop`.
    fn stop_browse(&mut self) -> Result<(), MdnsDiscoveryError>;
}

/// The real `mdns-sd`-backed transport.
pub struct DaemonTransport {
    daemon: ServiceDaemon,
    receiver: mdns_sd::Receiver<ServiceEvent>,
    service_type: String,
}

impl BrowseTransport for DaemonTransport {
    fn try_recv(&self) -> BrowseRecv {
        match self.receiver.try_recv() {
            Ok(event) => BrowseRecv::Event(Box::new(event)),
            // Checked after the fact so buffered events are still drained
            // before we report the channel dead.
            Err(_) if self.receiver.is_disconnected() => BrowseRecv::Disconnected,
            Err(_) => BrowseRecv::Empty,
        }
    }

    fn recv_timeout(&self, timeout: Duration) -> BrowseRecv {
        match self.receiver.recv_timeout(timeout) {
            Ok(event) => BrowseRecv::Event(Box::new(event)),
            Err(_) if self.receiver.is_disconnected() => BrowseRecv::Disconnected,
            Err(_) => BrowseRecv::Empty,
        }
    }

    fn stop_browse(&mut self) -> Result<(), MdnsDiscoveryError> {
        // Always attempt the daemon shutdown, even if stopping the browse
        // failed -- otherwise a `stop_browse` error would leak the whole
        // daemon thread. The first error is the one reported.
        let stopped = self
            .daemon
            .stop_browse(&self.service_type)
            .map_err(|e| MdnsDiscoveryError::Operation(e.to_string()));
        let shutdown = self
            .daemon
            .shutdown()
            .map(|_status_receiver| ())
            .map_err(|e| MdnsDiscoveryError::Operation(e.to_string()));
        stopped.and(shutdown)
    }
}

/// RAII owner of an in-flight browse: [`BrowseTransport::stop_browse`] runs
/// on `Drop` if it has not already run, so an early return, an unwinding
/// panic in the caller's poll loop, or a plain `drop(discovery)` all tear
/// the browse down. A teardown failure during `Drop` is logged to stderr
/// (it cannot be returned from `Drop`); callers that want it as a value
/// call [`MdnsDiscovery::stop`] instead.
pub struct BrowseGuard<T: BrowseTransport> {
    transport: T,
    stopped: bool,
}

impl<T: BrowseTransport> BrowseGuard<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            stopped: false,
        }
    }

    /// Idempotent: the second and later calls are no-ops returning `Ok`.
    /// Marks itself stopped *before* delegating, so a failing
    /// `stop_browse` is not retried from `Drop` (and cannot be reported
    /// twice).
    pub fn stop(&mut self) -> Result<(), MdnsDiscoveryError> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        self.transport.stop_browse()
    }
}

impl<T: BrowseTransport> Drop for BrowseGuard<T> {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("[discovery_mdns] browse teardown failed during drop: {error}");
        }
    }
}

/// What one [`MdnsDiscovery::poll_events`] call observed. The point of the
/// tag is that `Idle` and `Disconnected` demand *opposite* reactions from a
/// polling caller ("try again later" vs "stop, this browser is dead"), and
/// the old `usize` return value collapsed both to `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// No event was pending. The browse is alive; keep polling.
    Idle,
    /// `processed` events were applied to the candidate table; call
    /// [`MdnsDiscovery::candidates`] for the new snapshot.
    Events { processed: usize },
    /// The browse channel is closed -- the daemon is gone and no further
    /// event can arrive. `processed` counts events drained before the
    /// closure was observed. The caller must stop polling (and typically
    /// drop the discovery, which tears the browse down).
    Disconnected { processed: usize },
}

impl PollOutcome {
    /// Number of events applied during this call.
    pub fn processed(self) -> usize {
        match self {
            Self::Idle => 0,
            Self::Events { processed } | Self::Disconnected { processed } => processed,
        }
    }

    /// `true` when polling must stop; see [`Self::Disconnected`].
    pub fn is_disconnected(self) -> bool {
        matches!(self, Self::Disconnected { .. })
    }
}

/// Browses for [`YLX_CAPTURE_SERVICE_TYPE`] candidates. Holds an in-memory
/// table of the most recently seen resolution per `fullname`, updated by
/// calling [`Self::poll_events`] -- this module does not spawn its own
/// background thread to keep that table current; a caller (e.g. a future
/// PC-02 actor's event loop) is expected to poll periodically, and to stop
/// when [`PollOutcome::is_disconnected`] says so.
pub struct MdnsDiscovery<T: BrowseTransport = DaemonTransport> {
    guard: BrowseGuard<T>,
    candidates: HashMap<String, MdnsCandidate>,
}

impl MdnsDiscovery<DaemonTransport> {
    /// Starts a real `mdns-sd` daemon and issues a real
    /// `browse(YLX_CAPTURE_SERVICE_TYPE)` call. See module doc comment for
    /// what is/isn't verified about real multicast in this sandbox.
    pub fn start() -> Result<Self, MdnsDiscoveryError> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| MdnsDiscoveryError::DaemonUnavailable(e.to_string()))?;
        let receiver = daemon
            .browse(YLX_CAPTURE_SERVICE_TYPE)
            .map_err(|e| MdnsDiscoveryError::Operation(e.to_string()))?;
        Ok(Self::with_transport(DaemonTransport {
            daemon,
            receiver,
            service_type: YLX_CAPTURE_SERVICE_TYPE.to_string(),
        }))
    }
}

impl<T: BrowseTransport> MdnsDiscovery<T> {
    /// Wraps an already-started browse. Primarily the seam that lets the
    /// lifecycle be tested without multicast.
    pub fn with_transport(transport: T) -> Self {
        Self {
            guard: BrowseGuard::new(transport),
            candidates: HashMap::new(),
        }
    }

    /// Drains every currently-pending mDNS event (non-blocking) and
    /// updates the internal candidate table: `ServiceResolved` inserts/
    /// replaces the entry for that `fullname`; `ServiceRemoved` deletes
    /// it. Other event kinds (`SearchStarted`/`ServiceFound` without a
    /// resolution yet/`SearchStopped`) are observed but do not change the
    /// candidate table -- `ServiceFound` in particular is *not* enough
    /// information yet (`mdns-sd` still needs to resolve host/port/TXT),
    /// so surfacing it as a candidate would be premature.
    ///
    /// See [`PollOutcome`] for how "nothing pending" and "the browser is
    /// dead" are told apart.
    pub fn poll_events(&mut self) -> PollOutcome {
        let mut processed = 0;
        loop {
            match self.guard.transport.try_recv() {
                BrowseRecv::Event(event) => {
                    processed += 1;
                    self.apply_event(*event);
                }
                BrowseRecv::Empty => break,
                BrowseRecv::Disconnected => return PollOutcome::Disconnected { processed },
            }
        }
        if processed == 0 {
            PollOutcome::Idle
        } else {
            PollOutcome::Events { processed }
        }
    }

    /// Blocks up to `timeout` waiting for at least one more mDNS event,
    /// then drains everything else pending (same update semantics as
    /// [`Self::poll_events`]). Useful for tests/short-lived callers that
    /// want a bounded wait rather than a tight non-blocking poll loop.
    pub fn poll_events_blocking(&mut self, timeout: Duration) -> PollOutcome {
        match self.guard.transport.recv_timeout(timeout) {
            BrowseRecv::Event(event) => {
                self.apply_event(*event);
                match self.poll_events() {
                    PollOutcome::Idle => PollOutcome::Events { processed: 1 },
                    PollOutcome::Events { processed } => PollOutcome::Events {
                        processed: processed + 1,
                    },
                    PollOutcome::Disconnected { processed } => PollOutcome::Disconnected {
                        processed: processed + 1,
                    },
                }
            }
            BrowseRecv::Empty => PollOutcome::Idle,
            BrowseRecv::Disconnected => PollOutcome::Disconnected { processed: 0 },
        }
    }

    /// Event count only -- kept so pre-[`PollOutcome`] call sites still
    /// compile. Prefer [`Self::poll_events`]: this return value cannot
    /// distinguish "idle" from "the browse channel is gone", which is what
    /// makes a `loop { poll(); sleep(); }` spin forever on a dead daemon.
    pub fn poll(&mut self) -> usize {
        self.poll_events().processed()
    }

    /// Event count only; see [`Self::poll`] for why
    /// [`Self::poll_events_blocking`] is preferred.
    pub fn poll_blocking(&mut self, timeout: Duration) -> usize {
        self.poll_events_blocking(timeout).processed()
    }

    fn apply_event(&mut self, event: ServiceEvent) {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let candidate = candidate_from_service_info(&info);
                self.candidates
                    .insert(candidate.fullname.clone(), candidate);
            }
            ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                self.candidates.remove(&fullname);
            }
            ServiceEvent::SearchStarted(_)
            | ServiceEvent::ServiceFound(_, _)
            | ServiceEvent::SearchStopped(_) => {}
        }
    }

    /// The current candidate snapshot, as of the last poll call. Order is
    /// unspecified.
    pub fn candidates(&self) -> Vec<MdnsCandidate> {
        self.candidates.values().cloned().collect()
    }

    /// Stops browsing and shuts down the daemon thread, returning any
    /// teardown failure to the caller. Not required for correctness --
    /// dropping the discovery tears the browse down the same way (see
    /// [`BrowseGuard`]) -- this exists so a caller that *wants* to see a
    /// teardown error gets it as a value instead of a stderr line.
    pub fn stop(mut self) -> Result<(), MdnsDiscoveryError> {
        self.guard.stop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// Builds a `ServiceInfo` the same way PI-06's advertiser would (same
    /// crate, same constructor), purely in-memory -- no network involved.
    /// This is what lets [`candidate_from_service_info`] be tested for
    /// real without needing a real multicast round trip.
    fn fake_resolved_service_info() -> ServiceInfo {
        ServiceInfo::new(
            YLX_CAPTURE_SERVICE_TYPE,
            "ylx-pi-01",
            "ylx-pi-01.local.",
            "192.168.1.42",
            8080,
            &[("device_id", "DEV00001"), ("display_name", "YLX Capture")][..],
        )
        .expect("valid ServiceInfo constructs")
    }

    fn service_info_with_addresses(addrs: &str) -> ServiceInfo {
        ServiceInfo::new(
            YLX_CAPTURE_SERVICE_TYPE,
            "ylx-pi-01",
            "ylx-pi-01.local.",
            addrs,
            8080,
            &[("device_id", "DEV00001")][..],
        )
        .expect("valid ServiceInfo constructs")
    }

    /// Shared record of what a [`FakeTransport`] was asked to do, readable
    /// after the transport itself has been dropped (which is exactly when
    /// the RAII teardown assertions need to look at it).
    #[derive(Default)]
    struct TransportLog {
        stop_calls: usize,
    }

    struct FakeTransport {
        events: RefCell<VecDeque<BrowseRecv>>,
        /// Yielded once `events` runs dry.
        tail: BrowseRecv,
        stop_result: Result<(), MdnsDiscoveryError>,
        log: Rc<RefCell<TransportLog>>,
    }

    impl FakeTransport {
        fn new(events: Vec<BrowseRecv>, tail: BrowseRecv) -> (Self, Rc<RefCell<TransportLog>>) {
            let log = Rc::new(RefCell::new(TransportLog::default()));
            (
                Self {
                    events: RefCell::new(events.into()),
                    tail,
                    stop_result: Ok(()),
                    log: log.clone(),
                },
                log,
            )
        }

        fn failing_stop(mut self, message: &str) -> Self {
            self.stop_result = Err(MdnsDiscoveryError::Operation(message.to_string()));
            self
        }

        fn next(&self) -> BrowseRecv {
            match self.events.borrow_mut().pop_front() {
                Some(recv) => recv,
                None => match &self.tail {
                    BrowseRecv::Disconnected => BrowseRecv::Disconnected,
                    _ => BrowseRecv::Empty,
                },
            }
        }
    }

    impl BrowseTransport for FakeTransport {
        fn try_recv(&self) -> BrowseRecv {
            self.next()
        }

        fn recv_timeout(&self, _timeout: Duration) -> BrowseRecv {
            self.next()
        }

        fn stop_browse(&mut self) -> Result<(), MdnsDiscoveryError> {
            self.log.borrow_mut().stop_calls += 1;
            self.stop_result.clone()
        }
    }

    fn resolved(info: ServiceInfo) -> BrowseRecv {
        event(ServiceEvent::ServiceResolved(info))
    }

    fn event(event: ServiceEvent) -> BrowseRecv {
        BrowseRecv::Event(Box::new(event))
    }

    #[test]
    fn candidate_from_service_info_maps_address_port_and_txt() {
        let info = fake_resolved_service_info();
        let candidate = candidate_from_service_info(&info);

        assert!(candidate.fullname.starts_with("ylx-pi-01."));
        assert_eq!(candidate.port, 8080);
        assert!(
            candidate
                .addresses
                .contains(&"192.168.1.42".parse::<IpAddr>().unwrap()),
            "addresses was {:?}",
            candidate.addresses
        );
        assert_eq!(
            candidate.txt.get("device_id").map(String::as_str),
            Some("DEV00001")
        );
        assert_eq!(
            candidate.txt.get("display_name").map(String::as_str),
            Some("YLX Capture")
        );
    }

    // --- requirement 3: IPv6 candidates + URL literals -----------------

    /// Old behaviour used `get_addresses_v4()`, so a v6-only advertiser
    /// produced a candidate with an empty address list (silently
    /// undiscoverable).
    #[test]
    fn candidate_keeps_ipv6_addresses() {
        let info = service_info_with_addresses("2001:db8::42");
        let candidate = candidate_from_service_info(&info);
        assert_eq!(
            candidate.addresses,
            vec!["2001:db8::42".parse::<IpAddr>().unwrap()]
        );
    }

    /// Dual-stack: both families survive, and the ordering keeps IPv4
    /// first so `addresses.first()` callers behave as before.
    #[test]
    fn candidate_keeps_both_families_ipv4_first() {
        let info = service_info_with_addresses("2001:db8::42,192.168.1.42");
        let candidate = candidate_from_service_info(&info);
        assert_eq!(
            candidate.addresses,
            vec![
                "192.168.1.42".parse::<IpAddr>().unwrap(),
                "2001:db8::42".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn url_host_literal_passes_ipv4_through() {
        assert_eq!(url_host_literal("192.168.1.42").unwrap(), "192.168.1.42");
    }

    #[test]
    fn url_host_literal_brackets_global_ipv6() {
        assert_eq!(url_host_literal("2001:db8::42").unwrap(), "[2001:db8::42]");
    }

    #[test]
    fn url_host_literal_percent_encodes_link_local_zone_id() {
        assert_eq!(
            url_host_literal("fe80::1%eth0").unwrap(),
            "[fe80::1%25eth0]"
        );
    }

    #[test]
    fn url_host_literal_rejects_malformed_addresses() {
        for host in [
            "",
            "not-an-ip",
            "ylx-pi-01.local.",
            "192.168.1.42%eth0", // zone ids are IPv6-only
            "fe80::1%",          // empty zone id
            "fe80::1%eth 0",     // zone id must not need escaping
            "[2001:db8::42]",    // already bracketed: caller passes raw
            "2001:db8::42:",
        ] {
            assert!(
                matches!(
                    url_host_literal(host),
                    Err(MdnsDiscoveryError::InvalidAddress(_))
                ),
                "expected {host:?} to be rejected, got {:?}",
                url_host_literal(host)
            );
        }
    }

    #[test]
    fn candidate_url_composes_each_address_family() {
        assert_eq!(
            candidate_url("http", "192.168.1.42", 8080, "/api/v4").unwrap(),
            "http://192.168.1.42:8080/api/v4"
        );
        assert_eq!(
            candidate_url("https", "2001:db8::42", 8443, "api/v1").unwrap(),
            "https://[2001:db8::42]:8443/api/v1"
        );
        assert_eq!(
            candidate_url("http", "fe80::1%eth0", 8080, "/api/v1").unwrap(),
            "http://[fe80::1%25eth0]:8080/api/v1"
        );
        assert!(candidate_url("http", "nope", 8080, "/").is_err());
    }

    #[test]
    fn candidate_url_helper_uses_first_address() {
        let candidate = candidate_from_service_info(&service_info_with_addresses("2001:db8::42"));
        assert_eq!(
            candidate.url("http", "/api/v4").unwrap().unwrap(),
            "http://[2001:db8::42]:8080/api/v4"
        );

        let empty = MdnsCandidate {
            fullname: "x".into(),
            hostname: "x.local.".into(),
            addresses: vec![],
            port: 1,
            txt: HashMap::new(),
        };
        assert!(empty.url("https", "/").is_none());
    }

    // --- requirement 1: tagged poll outcomes ---------------------------

    #[test]
    fn poll_reports_idle_when_no_event_is_pending() {
        let (transport, _log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let mut discovery = MdnsDiscovery::with_transport(transport);
        assert_eq!(discovery.poll_events(), PollOutcome::Idle);
        assert!(!discovery.poll_events().is_disconnected());
    }

    #[test]
    fn poll_reports_events_and_updates_candidates() {
        let info = fake_resolved_service_info();
        let fullname = info.get_fullname().to_string();
        let (transport, _log) = FakeTransport::new(
            vec![
                event(ServiceEvent::SearchStarted(
                    YLX_CAPTURE_SERVICE_TYPE.to_string(),
                )),
                resolved(info),
            ],
            BrowseRecv::Empty,
        );
        let mut discovery = MdnsDiscovery::with_transport(transport);

        assert_eq!(
            discovery.poll_events(),
            PollOutcome::Events { processed: 2 }
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].fullname, fullname);
    }

    #[test]
    fn poll_removes_candidate_on_removal_event() {
        let info = fake_resolved_service_info();
        let fullname = info.get_fullname().to_string();
        let (transport, _log) = FakeTransport::new(
            vec![
                resolved(info),
                event(ServiceEvent::ServiceRemoved(
                    YLX_CAPTURE_SERVICE_TYPE.to_string(),
                    fullname,
                )),
            ],
            BrowseRecv::Empty,
        );
        let mut discovery = MdnsDiscovery::with_transport(transport);

        assert_eq!(
            discovery.poll_events(),
            PollOutcome::Events { processed: 2 }
        );
        assert!(discovery.candidates().is_empty());
    }

    /// The bug this commit exists for: a dead browse channel used to be
    /// indistinguishable from a quiet one (both `poll() == 0`), so a
    /// polling caller span forever. It must now be a distinct, terminal
    /// outcome -- on every subsequent call too.
    #[test]
    fn poll_reports_disconnected_instead_of_looking_idle() {
        let (transport, _log) = FakeTransport::new(vec![], BrowseRecv::Disconnected);
        let mut discovery = MdnsDiscovery::with_transport(transport);

        let outcome = discovery.poll_events();
        assert_eq!(outcome, PollOutcome::Disconnected { processed: 0 });
        assert!(outcome.is_disconnected());
        assert_ne!(outcome, PollOutcome::Idle);
        assert!(discovery.poll_events().is_disconnected());
    }

    /// Buffered events are still applied before the disconnect is
    /// reported, so a final resolution is not lost when the daemon dies.
    #[test]
    fn poll_drains_buffered_events_before_reporting_disconnect() {
        let info = fake_resolved_service_info();
        let (transport, _log) = FakeTransport::new(vec![resolved(info)], BrowseRecv::Disconnected);
        let mut discovery = MdnsDiscovery::with_transport(transport);

        assert_eq!(
            discovery.poll_events(),
            PollOutcome::Disconnected { processed: 1 }
        );
        assert_eq!(discovery.candidates().len(), 1);
    }

    #[test]
    fn blocking_poll_distinguishes_timeout_from_disconnect() {
        let (idle_transport, _log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let mut idle = MdnsDiscovery::with_transport(idle_transport);
        assert_eq!(
            idle.poll_events_blocking(Duration::from_millis(1)),
            PollOutcome::Idle
        );

        let (dead_transport, _log) = FakeTransport::new(vec![], BrowseRecv::Disconnected);
        let mut dead = MdnsDiscovery::with_transport(dead_transport);
        assert_eq!(
            dead.poll_events_blocking(Duration::from_millis(1)),
            PollOutcome::Disconnected { processed: 0 }
        );
    }

    #[test]
    fn blocking_poll_counts_first_event_plus_drained_tail() {
        let info = fake_resolved_service_info();
        let (transport, _log) = FakeTransport::new(
            vec![
                resolved(info),
                event(ServiceEvent::SearchStopped(
                    YLX_CAPTURE_SERVICE_TYPE.to_string(),
                )),
            ],
            BrowseRecv::Empty,
        );
        let mut discovery = MdnsDiscovery::with_transport(transport);
        assert_eq!(
            discovery.poll_events_blocking(Duration::from_millis(1)),
            PollOutcome::Events { processed: 2 }
        );
    }

    /// The legacy `usize` surface still compiles and still counts events,
    /// so existing call sites keep working while they migrate.
    #[test]
    fn legacy_poll_returns_event_count() {
        let info = fake_resolved_service_info();
        let (transport, _log) = FakeTransport::new(vec![resolved(info)], BrowseRecv::Empty);
        let mut discovery = MdnsDiscovery::with_transport(transport);
        assert_eq!(discovery.poll(), 1);
        assert_eq!(discovery.poll(), 0);
    }

    // --- requirement 2: RAII teardown ----------------------------------

    #[test]
    fn dropping_discovery_stops_the_browse() {
        let (transport, log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        {
            let mut discovery = MdnsDiscovery::with_transport(transport);
            let _ = discovery.poll_events();
        }
        assert_eq!(log.borrow().stop_calls, 1, "drop must stop the browse");
    }

    #[test]
    fn panicking_poll_loop_still_stops_the_browse() {
        let (transport, log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut discovery = MdnsDiscovery::with_transport(transport);
            let _ = discovery.poll_events();
            panic!("caller's poll loop blew up");
        }));
        assert!(result.is_err());
        assert_eq!(
            log.borrow().stop_calls,
            1,
            "unwinding must still tear the browse down"
        );
    }

    /// A failing `stop_browse` must be surfaced to the caller, and must
    /// not leave the guard armed to retry (and re-report) from `Drop`.
    #[test]
    fn explicit_stop_returns_teardown_failure_exactly_once() {
        let (transport, log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let transport = transport.failing_stop("stop_browse exploded");
        let discovery = MdnsDiscovery::with_transport(transport);

        let error = discovery.stop().expect_err("teardown failure is returned");
        assert!(
            error.to_string().contains("stop_browse exploded"),
            "error was {error}"
        );
        assert_eq!(log.borrow().stop_calls, 1);
    }

    /// Even when the browse cannot be stopped cleanly, `Drop` still runs
    /// the attempt (old code returned early from `stop()` on the
    /// `stop_browse` error and never shut the daemon down).
    #[test]
    fn drop_attempts_teardown_even_when_it_fails() {
        let (transport, log) = FakeTransport::new(vec![], BrowseRecv::Disconnected);
        let transport = transport.failing_stop("stop_browse exploded");
        drop(MdnsDiscovery::with_transport(transport));
        assert_eq!(log.borrow().stop_calls, 1);
    }

    #[test]
    fn explicit_stop_is_not_repeated_by_drop() {
        let (transport, log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let discovery = MdnsDiscovery::with_transport(transport);
        discovery.stop().expect("clean stop");
        assert_eq!(log.borrow().stop_calls, 1, "drop must not stop twice");
    }

    /// Real daemon, real `browse()` call, run manually only -- see module
    /// doc comment's "Real multicast mDNS" section for exactly what this
    /// does and does not prove (it proves `mdns-sd` can start and issue a
    /// browse call in this sandbox; it does NOT prove a real
    /// `_ylx-capture._tcp.local.` advertiser was found and resolved, since
    /// none was running alongside this test).
    #[test]
    #[ignore = "requires real multicast networking; run manually with --ignored"]
    fn real_daemon_starts_and_can_be_stopped() {
        let mut discovery = MdnsDiscovery::start().expect("real mdns-sd daemon starts");
        let outcome = discovery.poll_events_blocking(Duration::from_secs(2));
        eprintln!("real_daemon_starts_and_can_be_stopped: outcome {outcome:?} after 2s");
        discovery.stop().expect("daemon stops cleanly");
    }
}
