//! mDNS candidate browser for `_ylx-capture._tcp.local.`.
//!
//! # Scope
//!
//! This module owns the lossless conversion from `mdns-sd` browse events into
//! deterministic endpoint candidates and lifecycle changes. It preserves the
//! advertised port, every address, the interface that received each address,
//! and the scope required by IPv6 link-local connections. It does not probe a
//! Device API endpoint or decide that an unauthenticated service is a device.
//!
//! `mdns-sd` emits the same `ServiceRemoved` event for an explicit goodbye and
//! for cache/TTL expiry. [`MdnsLossReason::RemovedOrExpired`] deliberately
//! preserves that uncertainty instead of inventing a local explanation. Browse
//! restart recovery and endpoint health are caller concerns; this module only
//! supplies ordered events and a generation/sequence cursor so late work from
//! an older browse cannot overwrite newer state.
//! It does not restart a stopped browse or recover interrupted operations.
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
//! non-`#[ignore]`d unit tests of the pure `ResolvedService` -> [`MdnsCandidate`]
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

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mdns_sd::{InterfaceId, ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent};

/// The Conductor Device API's mDNS service type.
pub const YLX_CAPTURE_SERVICE_TYPE: &str = "_ylx-capture._tcp.local.";

static NEXT_DISCOVERY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Case-normalised DNS-SD service identity. DNS names are case-insensitive;
/// retaining a canonical key prevents a casing-only re-announcement from
/// creating another service entry. The original spelling remains available in
/// [`MdnsCandidate::fullname`] and [`MdnsServiceLoss::fullname`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MdnsServiceId(String);

impl MdnsServiceId {
    pub fn from_fullname(fullname: &str) -> Self {
        let mut canonical = fullname.trim().to_ascii_lowercase();
        if !canonical.ends_with('.') {
            canonical.push('.');
        }
        Self(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MdnsServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic position of one lifecycle observation. A newly-created browser
/// receives a new `generation`; `sequence` increases for every resolved,
/// removed, stopped, or disconnected transition within that browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MdnsEventCursor {
    pub generation: u64,
    pub sequence: u64,
}

/// Interface on which an address was learned. `index` is the Windows IPv6
/// zone identifier; `name` is the conventional Unix URL zone identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MdnsInterface {
    pub name: String,
    pub index: u32,
}

impl MdnsInterface {
    fn from_mdns(value: &InterfaceId) -> Option<Self> {
        if value.name.is_empty() && value.index == 0 {
            None
        } else {
            Some(Self {
                name: value.name.clone(),
                index: value.index,
            })
        }
    }

    fn matches(&self, other: &Self) -> bool {
        (self.index != 0 && other.index != 0 && self.index == other.index)
            || (!self.name.is_empty() && !other.name.is_empty() && self.name == other.name)
    }
}

/// Which OS representation to use for an IPv6 link-local zone identifier.
/// Exposed so both Windows numeric-scope and Unix interface-name formatting
/// can be covered on every CI host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsScopeStyle {
    InterfaceName,
    InterfaceIndex,
}

/// One scoped address advertised for a service instance. IPv4 addresses can
/// appear once per receiving interface; keeping those rows separate lets the
/// caller prefer its active interface without discarding alternate routes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MdnsEndpoint {
    pub address: IpAddr,
    pub interface: Option<MdnsInterface>,
}

impl MdnsEndpoint {
    pub fn is_connectable(&self) -> bool {
        if self.address.is_unspecified() || self.address.is_multicast() {
            return false;
        }
        match self.address {
            IpAddr::V6(address) if is_ipv6_link_local(&address) => self.interface.is_some(),
            _ => true,
        }
    }

    /// Raw host passed to the Device API probe. Only IPv6 link-local literals
    /// carry a zone; global IPv6 and IPv4 literals never do.
    pub fn host_with_scope_style(
        &self,
        style: MdnsScopeStyle,
    ) -> Result<String, MdnsDiscoveryError> {
        match self.address {
            IpAddr::V6(address) if is_ipv6_link_local(&address) => {
                let interface = self
                    .interface
                    .as_ref()
                    .ok_or_else(|| MdnsDiscoveryError::MissingIpv6Scope(address.to_string()))?;
                let zone = match style {
                    MdnsScopeStyle::InterfaceName if !interface.name.is_empty() => {
                        Some(interface.name.clone())
                    }
                    MdnsScopeStyle::InterfaceName if interface.index != 0 => {
                        Some(interface.index.to_string())
                    }
                    MdnsScopeStyle::InterfaceIndex if interface.index != 0 => {
                        Some(interface.index.to_string())
                    }
                    _ => None,
                }
                .ok_or_else(|| MdnsDiscoveryError::MissingIpv6Scope(address.to_string()))?;
                Ok(format!("{address}%{zone}"))
            }
            _ => Ok(self.address.to_string()),
        }
    }

    pub fn host(&self) -> Result<String, MdnsDiscoveryError> {
        #[cfg(windows)]
        let style = MdnsScopeStyle::InterfaceIndex;
        #[cfg(not(windows))]
        let style = MdnsScopeStyle::InterfaceName;
        self.host_with_scope_style(style)
    }

    pub fn url(&self, scheme: &str, port: u16, path: &str) -> Result<String, MdnsDiscoveryError> {
        candidate_url(scheme, &self.host()?, port, path)
    }
}

fn is_ipv6_link_local(address: &std::net::Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

/// One unauthenticated mDNS candidate. See module doc comment's
/// ADR-DISC-001 section -- nothing here is trusted on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsCandidate {
    /// The mDNS instance's full service name (`<instance>.{service_type}`),
    /// used as the stable key for update/removal tracking -- not a trusted
    /// device identifier.
    pub fullname: String,
    /// Canonical identity used for update/removal/reappearance matching.
    pub service_id: MdnsServiceId,
    pub hostname: String,
    /// Deduplicated, scope-free compatibility projection of every IPv4/IPv6
    /// address. It is sorted but must not drive connection attempts because an
    /// `IpAddr` cannot represent an IPv6 zone; use [`Self::ordered_endpoints`].
    pub addresses: Vec<IpAddr>,
    /// Every address/interface pair, deterministically sorted. Callers should
    /// probe this collection instead of selecting `addresses.first()`.
    pub endpoints: Vec<MdnsEndpoint>,
    pub port: u16,
    pub txt: HashMap<String, String>,
    pub cursor: MdnsEventCursor,
}

impl MdnsCandidate {
    /// Composes a URL against this candidate's first default-ordered endpoint,
    /// bracketing IPv6 literals correctly. `None` when the candidate advertised no endpoint;
    /// `Err` when the address cannot be expressed as a URL host (which
    /// should not happen for daemon-produced candidates, but is surfaced
    /// rather than silently papered over).
    pub fn url(&self, scheme: &str, path: &str) -> Option<Result<String, MdnsDiscoveryError>> {
        let endpoints = self.ordered_endpoints(None);
        let endpoint = endpoints.first()?;
        Some(endpoint.url(scheme, self.port, path))
    }

    /// Returns a stable probe order. Connectable endpoints come first, then an
    /// optional active interface preference, then IPv4/global-IPv6/scoped
    /// link-local, address bytes, and interface identity. No port is invented:
    /// every returned endpoint uses [`Self::port`].
    pub fn ordered_endpoints(
        &self,
        preferred_interface: Option<&MdnsInterface>,
    ) -> Vec<MdnsEndpoint> {
        let mut endpoints = self.endpoints.clone();
        endpoints.sort_by_key(|endpoint| endpoint_sort_key(endpoint, preferred_interface));
        endpoints
    }
}

fn endpoint_sort_key(
    endpoint: &MdnsEndpoint,
    preferred_interface: Option<&MdnsInterface>,
) -> (u8, u8, u8, IpAddr, Option<MdnsInterface>) {
    let connectability = u8::from(!endpoint.is_connectable());
    let preferred = match (preferred_interface, endpoint.interface.as_ref()) {
        (None, _) => 0,
        (Some(expected), Some(actual)) if expected.matches(actual) => 0,
        _ => 1,
    };
    let family = match endpoint.address {
        IpAddr::V4(address) if address.is_loopback() => 3,
        IpAddr::V4(_) => 0,
        IpAddr::V6(address) if address.is_loopback() => 3,
        IpAddr::V6(address) if is_ipv6_link_local(&address) => 2,
        IpAddr::V6(_) => 1,
    };
    (
        connectability,
        preferred,
        family,
        endpoint.address,
        endpoint.interface.clone(),
    )
}

fn endpoints_from_scoped(addresses: &std::collections::HashSet<ScopedIp>) -> Vec<MdnsEndpoint> {
    let mut endpoints = BTreeSet::new();
    for scoped in addresses {
        match scoped {
            ScopedIp::V4(address) => {
                if address.interface_ids().is_empty() {
                    endpoints.insert(MdnsEndpoint {
                        address: IpAddr::V4(*address.addr()),
                        interface: None,
                    });
                } else {
                    for interface in address.interface_ids() {
                        endpoints.insert(MdnsEndpoint {
                            address: IpAddr::V4(*address.addr()),
                            interface: MdnsInterface::from_mdns(interface),
                        });
                    }
                }
            }
            ScopedIp::V6(address) => {
                endpoints.insert(MdnsEndpoint {
                    address: IpAddr::V6(*address.addr()),
                    interface: MdnsInterface::from_mdns(address.scope_id()),
                });
            }
            _ => {}
        }
    }
    let mut endpoints: Vec<_> = endpoints.into_iter().collect();
    endpoints.sort_by_key(|endpoint| endpoint_sort_key(endpoint, None));
    endpoints
}

fn candidate_from_resolved(info: &ResolvedService, cursor: MdnsEventCursor) -> MdnsCandidate {
    let endpoints = endpoints_from_scoped(info.get_addresses());
    let addresses = endpoints
        .iter()
        .map(|endpoint| endpoint.address)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let txt = info
        .get_properties()
        .iter()
        .map(|prop| (prop.key().to_string(), prop.val_str().to_string()))
        .collect();
    MdnsCandidate {
        fullname: info.get_fullname().to_string(),
        service_id: MdnsServiceId::from_fullname(info.get_fullname()),
        hostname: info.get_hostname().to_string(),
        addresses,
        endpoints,
        port: info.get_port(),
        txt,
        cursor,
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
    /// A link-local IPv6 address was learned without the receiving interface
    /// needed to form a usable socket/URL zone identifier.
    MissingIpv6Scope(String),
}

impl fmt::Display for MdnsDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonUnavailable(msg) => write!(f, "mdns daemon unavailable: {msg}"),
            Self::Operation(msg) => write!(f, "mdns operation failed: {msg}"),
            Self::InvalidAddress(msg) => write!(f, "invalid mdns address: {msg}"),
            Self::MissingIpv6Scope(msg) => {
                write!(f, "mdns link-local IPv6 address is missing scope: {msg}")
            }
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
    /// Boxed because `ServiceEvent` embeds a whole `ResolvedService`, which
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

/// Why a previously resolved service is no longer advertised. `mdns-sd`
/// intentionally uses one event for a goodbye packet and TTL/cache expiry, so
/// those two causes remain combined here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsLossReason {
    RemovedOrExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsServiceLoss {
    pub service_id: MdnsServiceId,
    pub fullname: String,
    pub cursor: MdnsEventCursor,
    pub reason: MdnsLossReason,
}

/// Terminal reason for one browse generation. The listed service IDs are the
/// final known set for that generation and should be marked stale/offline by
/// the owner; the records themselves remain useful for manual reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsBrowseLossReason {
    SearchStopped,
    ChannelDisconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsBrowseLoss {
    pub generation: u64,
    pub cursor: MdnsEventCursor,
    pub service_ids: Vec<MdnsServiceId>,
    pub reason: MdnsBrowseLossReason,
}

/// State-changing observations from one poll, in wire order. Consumers should
/// compare cursors before applying asynchronous probe results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsChange {
    Resolved(MdnsCandidate),
    Lost(MdnsServiceLoss),
    BrowseLost(MdnsBrowseLoss),
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

/// One atomic drain of the browse channel. Unlike [`PollOutcome`] alone, this
/// carries the exact resolved/removal lifecycle needed to reconcile UI state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsPollBatch {
    pub generation: u64,
    pub outcome: PollOutcome,
    pub changes: Vec<MdnsChange>,
}

impl MdnsPollBatch {
    pub fn is_disconnected(&self) -> bool {
        self.outcome.is_disconnected()
    }
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
/// table of the most recently seen resolution per canonical service ID,
/// updated by calling [`Self::poll_batch`] -- this module does not spawn its own
/// background thread to keep that table current; a caller (e.g. a future
/// PC-02 actor's event loop) is expected to poll periodically, and to stop
/// when [`PollOutcome::is_disconnected`] says so.
pub struct MdnsDiscovery<T: BrowseTransport = DaemonTransport> {
    guard: BrowseGuard<T>,
    candidates: HashMap<MdnsServiceId, MdnsCandidate>,
    generation: u64,
    sequence: u64,
    terminal: bool,
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
        let generation = NEXT_DISCOVERY_GENERATION.fetch_add(1, Ordering::Relaxed);
        Self::with_transport_generation(transport, generation)
    }

    /// Deterministic-generation constructor for fake transports. Production
    /// callers should use [`Self::with_transport`] or [`MdnsDiscovery::start`].
    pub fn with_transport_generation(transport: T, generation: u64) -> Self {
        Self {
            guard: BrowseGuard::new(transport),
            candidates: HashMap::new(),
            generation,
            sequence: 0,
            terminal: false,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn next_cursor(&mut self) -> MdnsEventCursor {
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("mDNS event sequence exhausted u64");
        MdnsEventCursor {
            generation: self.generation,
            sequence: self.sequence,
        }
    }

    /// Drains every currently pending event into an ordered lifecycle batch.
    /// This is the preferred integration API: unlike a candidate snapshot, it
    /// makes removals and terminal browse loss explicit.
    pub fn poll_batch(&mut self) -> MdnsPollBatch {
        let first = if self.terminal {
            BrowseRecv::Disconnected
        } else {
            self.guard.transport.try_recv()
        };
        self.poll_batch_from(first)
    }

    /// Blocking counterpart to [`Self::poll_batch`].
    pub fn poll_batch_blocking(&mut self, timeout: Duration) -> MdnsPollBatch {
        let first = if self.terminal {
            BrowseRecv::Disconnected
        } else {
            self.guard.transport.recv_timeout(timeout)
        };
        self.poll_batch_from(first)
    }

    fn poll_batch_from(&mut self, first: BrowseRecv) -> MdnsPollBatch {
        let mut processed = 0;
        let mut changes = Vec::new();
        let mut next = Some(first);
        loop {
            let received = next
                .take()
                .unwrap_or_else(|| self.guard.transport.try_recv());
            match received {
                BrowseRecv::Event(event) => {
                    processed += 1;
                    if self.apply_event(*event, &mut changes) {
                        return MdnsPollBatch {
                            generation: self.generation,
                            outcome: PollOutcome::Disconnected { processed },
                            changes,
                        };
                    }
                }
                BrowseRecv::Empty => {
                    let outcome = if processed == 0 {
                        PollOutcome::Idle
                    } else {
                        PollOutcome::Events { processed }
                    };
                    return MdnsPollBatch {
                        generation: self.generation,
                        outcome,
                        changes,
                    };
                }
                BrowseRecv::Disconnected => {
                    if !self.terminal {
                        self.mark_browse_lost(
                            MdnsBrowseLossReason::ChannelDisconnected,
                            &mut changes,
                        );
                    }
                    return MdnsPollBatch {
                        generation: self.generation,
                        outcome: PollOutcome::Disconnected { processed },
                        changes,
                    };
                }
            }
        }
    }

    /// Drains every currently-pending mDNS event (non-blocking) and
    /// updates the internal candidate table: `ServiceResolved` inserts/
    /// replaces the entry for that `fullname`; `ServiceRemoved` deletes
    /// it. `SearchStopped` is terminal and clears the live candidate table;
    /// `SearchStarted` and unresolved `ServiceFound` events do not change it.
    /// `ServiceFound` in particular is not enough information yet (`mdns-sd`
    /// still needs to resolve host/port/TXT), so surfacing it as a candidate
    /// would be premature.
    ///
    /// See [`PollOutcome`] for how "nothing pending" and "the browser is
    /// dead" are told apart.
    pub fn poll_events(&mut self) -> PollOutcome {
        self.poll_batch().outcome
    }

    /// Blocks up to `timeout` waiting for at least one more mDNS event,
    /// then drains everything else pending (same update semantics as
    /// [`Self::poll_events`]). Useful for tests/short-lived callers that
    /// want a bounded wait rather than a tight non-blocking poll loop.
    pub fn poll_events_blocking(&mut self, timeout: Duration) -> PollOutcome {
        self.poll_batch_blocking(timeout).outcome
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

    fn apply_event(&mut self, event: ServiceEvent, changes: &mut Vec<MdnsChange>) -> bool {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let cursor = self.next_cursor();
                let candidate = candidate_from_resolved(&info, cursor);
                self.candidates
                    .insert(candidate.service_id.clone(), candidate.clone());
                changes.push(MdnsChange::Resolved(candidate));
                false
            }
            ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                let service_id = MdnsServiceId::from_fullname(&fullname);
                self.candidates.remove(&service_id);
                let cursor = self.next_cursor();
                changes.push(MdnsChange::Lost(MdnsServiceLoss {
                    service_id,
                    fullname,
                    cursor,
                    reason: MdnsLossReason::RemovedOrExpired,
                }));
                false
            }
            ServiceEvent::SearchStopped(_) => {
                self.mark_browse_lost(MdnsBrowseLossReason::SearchStopped, changes);
                true
            }
            ServiceEvent::SearchStarted(_) | ServiceEvent::ServiceFound(_, _) => false,
            _ => false,
        }
    }

    fn mark_browse_lost(&mut self, reason: MdnsBrowseLossReason, changes: &mut Vec<MdnsChange>) {
        let service_ids = self.candidates.keys().cloned().collect::<BTreeSet<_>>();
        let cursor = self.next_cursor();
        self.candidates.clear();
        self.terminal = true;
        changes.push(MdnsChange::BrowseLost(MdnsBrowseLoss {
            generation: self.generation,
            cursor,
            service_ids: service_ids.into_iter().collect(),
            reason,
        }));
    }

    /// The current candidate snapshot, sorted by canonical service identity.
    pub fn candidates(&self) -> Vec<MdnsCandidate> {
        let mut candidates: Vec<_> = self.candidates.values().cloned().collect();
        candidates.sort_by_key(|candidate| candidate.service_id.clone());
        candidates
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
    use mdns_sd::{ScopedIpV4, ServiceInfo};
    use serde_json::json;
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};
    use std::net::Ipv4Addr;
    use std::rc::Rc;

    /// Builds a `ServiceInfo` the same way PI-06's advertiser would (same
    /// crate, same constructor), purely in-memory -- no network involved.
    /// This is what lets [`candidate_from_resolved`] be tested for
    /// real without needing a real multicast round trip.
    fn fake_resolved_service() -> ResolvedService {
        ServiceInfo::new(
            YLX_CAPTURE_SERVICE_TYPE,
            "ylx-pi-01",
            "ylx-pi-01.local.",
            "192.168.1.42",
            8080,
            &[("device_id", "DEV00001"), ("display_name", "YLX Capture")][..],
        )
        .expect("valid ServiceInfo constructs")
        .as_resolved_service()
    }

    fn resolved_service_with_addresses(addrs: &str) -> ResolvedService {
        ServiceInfo::new(
            YLX_CAPTURE_SERVICE_TYPE,
            "ylx-pi-01",
            "ylx-pi-01.local.",
            addrs,
            8080,
            &[("device_id", "DEV00001")][..],
        )
        .expect("valid ServiceInfo constructs")
        .as_resolved_service()
    }

    fn scoped_v6(address: &str, interface_name: &str, interface_index: u32) -> ScopedIp {
        serde_json::from_value(json!({
            "V6": {
                "addr": address,
                "scope_id": {
                    "name": interface_name,
                    "index": interface_index
                }
            }
        }))
        .expect("scoped IPv6 fixture deserializes")
    }

    fn resolved_service_with_scoped_addresses(addresses: HashSet<ScopedIp>) -> ResolvedService {
        let mut service = fake_resolved_service();
        service.addresses = addresses;
        service
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

    fn resolved(info: ResolvedService) -> BrowseRecv {
        event(ServiceEvent::ServiceResolved(Box::new(info)))
    }

    fn event(event: ServiceEvent) -> BrowseRecv {
        BrowseRecv::Event(Box::new(event))
    }

    #[test]
    fn candidate_from_resolved_maps_address_port_and_txt() {
        let info = fake_resolved_service();
        let candidate = candidate_from_resolved(
            &info,
            MdnsEventCursor {
                generation: 7,
                sequence: 1,
            },
        );

        assert!(candidate.fullname.starts_with("ylx-pi-01."));
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
        assert_eq!(candidate.port, 8080, "advertised port must be retained");
        assert_eq!(candidate.hostname, "ylx-pi-01.local.");
        assert_eq!(candidate.cursor.generation, 7);
    }

    // --- requirement 3: IPv6 candidates + URL literals -----------------

    /// Old behaviour used `get_addresses_v4()`, so a v6-only advertiser
    /// produced a candidate with an empty address list (silently
    /// undiscoverable).
    #[test]
    fn candidate_keeps_ipv6_addresses() {
        let info = resolved_service_with_addresses("2001:db8::42");
        let candidate = candidate_from_resolved(
            &info,
            MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
        );
        assert_eq!(
            candidate.addresses,
            vec!["2001:db8::42".parse::<IpAddr>().unwrap()]
        );
    }

    /// Dual-stack: both families survive, and the ordering keeps IPv4
    /// first so `addresses.first()` callers behave as before.
    #[test]
    fn candidate_keeps_both_families_ipv4_first() {
        let info = resolved_service_with_addresses("2001:db8::42,192.168.1.42");
        let candidate = candidate_from_resolved(
            &info,
            MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
        );
        assert_eq!(
            candidate.addresses,
            vec![
                "192.168.1.42".parse::<IpAddr>().unwrap(),
                "2001:db8::42".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn candidate_preserves_each_address_interface_pair() {
        let ethernet = InterfaceId {
            name: "Ethernet 2".into(),
            index: 17,
        };
        let wifi = InterfaceId {
            name: "Wi-Fi".into(),
            index: 23,
        };
        let ipv4 = Ipv4Addr::new(192, 168, 110, 36);
        let info = resolved_service_with_scoped_addresses(HashSet::from([
            ScopedIp::V4(ScopedIpV4::new(ipv4, ethernet.clone())),
            ScopedIp::V4(ScopedIpV4::new(ipv4, wifi.clone())),
            scoped_v6("fe80::36", &ethernet.name, ethernet.index),
            scoped_v6("2001:db8::36", &wifi.name, wifi.index),
        ]));
        let candidate = candidate_from_resolved(
            &info,
            MdnsEventCursor {
                generation: 3,
                sequence: 9,
            },
        );

        assert_eq!(
            candidate.addresses.len(),
            3,
            "plain addresses are deduplicated"
        );
        assert_eq!(
            candidate.endpoints.len(),
            4,
            "interface routes are not deduplicated"
        );
        assert!(candidate.endpoints.contains(&MdnsEndpoint {
            address: IpAddr::V4(ipv4),
            interface: Some(MdnsInterface {
                name: ethernet.name,
                index: ethernet.index,
            }),
        }));
        assert!(candidate.endpoints.contains(&MdnsEndpoint {
            address: "fe80::36".parse().unwrap(),
            interface: Some(MdnsInterface {
                name: "Ethernet 2".into(),
                index: 17,
            }),
        }));
        assert_eq!(candidate.port, 8080);
    }

    #[test]
    fn scoped_link_local_uses_unix_name_and_windows_numeric_index() {
        let endpoint = MdnsEndpoint {
            address: "fe80::36".parse().unwrap(),
            interface: Some(MdnsInterface {
                name: "eth0".into(),
                index: 17,
            }),
        };

        let unix_host = endpoint
            .host_with_scope_style(MdnsScopeStyle::InterfaceName)
            .unwrap();
        let windows_host = endpoint
            .host_with_scope_style(MdnsScopeStyle::InterfaceIndex)
            .unwrap();
        assert_eq!(unix_host, "fe80::36%eth0");
        assert_eq!(windows_host, "fe80::36%17");
        assert_eq!(
            candidate_url("http", &unix_host, 8080, "/api/v4/device").unwrap(),
            "http://[fe80::36%25eth0]:8080/api/v4/device"
        );
        assert_eq!(
            candidate_url("http", &windows_host, 8080, "/api/v4/device").unwrap(),
            "http://[fe80::36%2517]:8080/api/v4/device"
        );
        assert_eq!(
            endpoint.url("http", 8080, "/api/v4/device").unwrap(),
            if cfg!(windows) {
                "http://[fe80::36%2517]:8080/api/v4/device"
            } else {
                "http://[fe80::36%25eth0]:8080/api/v4/device"
            }
        );
    }

    #[test]
    fn unscoped_link_local_is_not_a_connectable_candidate() {
        let endpoint = MdnsEndpoint {
            address: "fe80::36".parse().unwrap(),
            interface: None,
        };
        assert!(!endpoint.is_connectable());
        assert!(matches!(
            endpoint.host(),
            Err(MdnsDiscoveryError::MissingIpv6Scope(_))
        ));
    }

    #[test]
    fn ordered_endpoints_are_stable_and_honor_interface_preference() {
        let ethernet = MdnsInterface {
            name: "Ethernet".into(),
            index: 7,
        };
        let wifi = MdnsInterface {
            name: "Wi-Fi".into(),
            index: 11,
        };
        let candidate = MdnsCandidate {
            fullname: "RP-YLX._ylx-capture._tcp.local.".into(),
            service_id: MdnsServiceId::from_fullname("RP-YLX._ylx-capture._tcp.local."),
            hostname: "rp-ylx.local.".into(),
            addresses: vec![],
            endpoints: vec![
                MdnsEndpoint {
                    address: "192.168.110.36".parse().unwrap(),
                    interface: Some(ethernet),
                },
                MdnsEndpoint {
                    address: "2001:db8::36".parse().unwrap(),
                    interface: Some(wifi.clone()),
                },
                MdnsEndpoint {
                    address: "fe80::36".parse().unwrap(),
                    interface: None,
                },
            ],
            port: 8080,
            txt: HashMap::new(),
            cursor: MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
        };

        let default = candidate.ordered_endpoints(None);
        assert_eq!(
            default[0].address,
            "192.168.110.36".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            default.last().unwrap().address,
            "fe80::36".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            candidate.ordered_endpoints(Some(&wifi))[0].address,
            "2001:db8::36".parse::<IpAddr>().unwrap()
        );
        assert_eq!(default, candidate.ordered_endpoints(None));
    }

    #[test]
    fn service_identity_is_case_insensitive_and_dot_normalized() {
        assert_eq!(
            MdnsServiceId::from_fullname("RP-YLX._YLX-CAPTURE._TCP.LOCAL"),
            MdnsServiceId::from_fullname("rp-ylx._ylx-capture._tcp.local.")
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
            candidate_url("http", "2001:db8::42", 18080, "api/v4").unwrap(),
            "http://[2001:db8::42]:18080/api/v4"
        );
        assert_eq!(
            candidate_url("http", "fe80::1%eth0", 8080, "/api/v4").unwrap(),
            "http://[fe80::1%25eth0]:8080/api/v4"
        );
        assert!(candidate_url("http", "nope", 8080, "/").is_err());
    }

    #[test]
    fn candidate_url_helper_uses_first_address() {
        let candidate = candidate_from_resolved(
            &resolved_service_with_addresses("2001:db8::42"),
            MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
        );
        assert_eq!(
            candidate.url("http", "/api/v4").unwrap().unwrap(),
            "http://[2001:db8::42]:8080/api/v4"
        );

        let empty = MdnsCandidate {
            fullname: "x".into(),
            service_id: MdnsServiceId::from_fullname("x"),
            hostname: "x.local.".into(),
            addresses: vec![],
            endpoints: vec![],
            port: 1,
            txt: HashMap::new(),
            cursor: MdnsEventCursor {
                generation: 1,
                sequence: 1,
            },
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
        let info = fake_resolved_service();
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
    fn candidate_snapshot_is_sorted_by_stable_service_identity() {
        let mut later = fake_resolved_service();
        later.fullname = "z-device._ylx-capture._tcp.local.".into();
        let mut earlier = fake_resolved_service();
        earlier.fullname = "a-device._ylx-capture._tcp.local.".into();
        let (transport, _log) =
            FakeTransport::new(vec![resolved(later), resolved(earlier)], BrowseRecv::Empty);
        let mut discovery = MdnsDiscovery::with_transport(transport);
        assert_eq!(
            discovery.poll_events(),
            PollOutcome::Events { processed: 2 }
        );

        let candidates = discovery.candidates();
        assert_eq!(
            candidates[0].service_id.as_str(),
            "a-device._ylx-capture._tcp.local."
        );
        assert_eq!(
            candidates[1].service_id.as_str(),
            "z-device._ylx-capture._tcp.local."
        );
    }

    #[test]
    fn poll_removes_candidate_on_removal_event() {
        let info = fake_resolved_service();
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

        let batch = discovery.poll_batch();
        assert_eq!(batch.outcome, PollOutcome::Events { processed: 2 });
        assert!(matches!(
            batch.changes.as_slice(),
            [
                MdnsChange::Resolved(_),
                MdnsChange::Lost(MdnsServiceLoss {
                    reason: MdnsLossReason::RemovedOrExpired,
                    ..
                })
            ]
        ));
        assert!(discovery.candidates().is_empty());
    }

    #[test]
    fn removed_or_ttl_expired_then_reappeared_keeps_identity_and_advances_cursor() {
        let info = fake_resolved_service();
        let fullname = info.get_fullname().to_string();
        let service_id = MdnsServiceId::from_fullname(&fullname);
        let mut reappeared_info = info.clone();
        reappeared_info.port = 18080;
        let (transport, _log) = FakeTransport::new(
            vec![
                resolved(info.clone()),
                BrowseRecv::Empty,
                event(ServiceEvent::ServiceRemoved(
                    YLX_CAPTURE_SERVICE_TYPE.to_string(),
                    fullname,
                )),
                BrowseRecv::Empty,
                resolved(reappeared_info),
                BrowseRecv::Empty,
            ],
            BrowseRecv::Empty,
        );
        let mut discovery = MdnsDiscovery::with_transport_generation(transport, 42);

        let first = discovery.poll_batch();
        let first_cursor = match &first.changes[0] {
            MdnsChange::Resolved(candidate) => {
                assert_eq!(candidate.service_id, service_id);
                candidate.cursor
            }
            other => panic!("expected resolved change, got {other:?}"),
        };
        let lost = discovery.poll_batch();
        let lost_cursor = match &lost.changes[0] {
            MdnsChange::Lost(loss) => {
                assert_eq!(loss.service_id, service_id);
                loss.cursor
            }
            other => panic!("expected loss change, got {other:?}"),
        };
        assert!(discovery.candidates().is_empty());
        let reappeared = discovery.poll_batch();
        let reappeared_candidate = match &reappeared.changes[0] {
            MdnsChange::Resolved(candidate) => candidate,
            other => panic!("expected resolved change, got {other:?}"),
        };

        assert_eq!(reappeared_candidate.service_id, service_id);
        assert!(first_cursor < lost_cursor && lost_cursor < reappeared_candidate.cursor);
        assert_eq!(reappeared_candidate.cursor.generation, 42);
        assert_eq!(
            reappeared_candidate.port, 18080,
            "port updates are not pinned"
        );
        assert_eq!(discovery.candidates().len(), 1);
    }

    #[test]
    fn discovery_generations_increase_across_browser_instances() {
        let (first_transport, _log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let (second_transport, _log) = FakeTransport::new(vec![], BrowseRecv::Empty);
        let first = MdnsDiscovery::with_transport(first_transport);
        let second = MdnsDiscovery::with_transport(second_transport);
        assert!(first.generation() < second.generation());
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
        let info = fake_resolved_service();
        let (transport, _log) = FakeTransport::new(vec![resolved(info)], BrowseRecv::Disconnected);
        let mut discovery = MdnsDiscovery::with_transport(transport);

        let batch = discovery.poll_batch();
        assert_eq!(batch.outcome, PollOutcome::Disconnected { processed: 1 });
        assert!(matches!(
            batch.changes.as_slice(),
            [MdnsChange::Resolved(_), MdnsChange::BrowseLost(MdnsBrowseLoss {
                reason: MdnsBrowseLossReason::ChannelDisconnected,
                service_ids,
                ..
            })] if service_ids.len() == 1
        ));
        assert!(discovery.candidates().is_empty());
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
    fn search_stopped_is_terminal_and_carries_known_services() {
        let info = fake_resolved_service();
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
        let batch = discovery.poll_batch_blocking(Duration::from_millis(1));
        assert_eq!(batch.outcome, PollOutcome::Disconnected { processed: 2 });
        assert!(matches!(
            batch.changes.last(),
            Some(MdnsChange::BrowseLost(MdnsBrowseLoss {
                reason: MdnsBrowseLossReason::SearchStopped,
                service_ids,
                ..
            })) if service_ids.len() == 1
        ));
        assert!(discovery.candidates().is_empty());
    }

    /// The legacy `usize` surface still compiles and still counts events,
    /// so existing call sites keep working while they migrate.
    #[test]
    fn legacy_poll_returns_event_count() {
        let info = fake_resolved_service();
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
