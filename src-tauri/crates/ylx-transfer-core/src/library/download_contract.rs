//! Shared [`DownloadSource`] contract suite (issue #1, commit 10).
//!
//! [`crate::library::download::download_file`]'s whole resume state machine
//! is driven by what a [`DownloadSource`] reports: `200` means "restart at
//! zero", `206` means "continue at the requested offset", `412` means "the
//! remote object changed, discard the partial and restart", `416` means
//! "that range no longer exists". A source that collapses any of those into
//! an opaque [`DownloadError::Source`] string makes the corresponding branch
//! of that state machine **unreachable** — which is exactly what the
//! production `PiDownloadSource` used to do for `412`/`416`.
//!
//! So "faithfully reports the transport outcome" is a property of the
//! *seam*, not of any one implementation, and it is asserted here once and
//! run against every implementation:
//!
//! - the in-memory fake used by `library::download`'s own unit tests, and
//! - the production `ylx_transfer_adapters::pi_download_source::
//!   PiDownloadSource` driven by a real loopback HTTP server.
//!
//! Compiled only for test builds (`cfg(test)`) or when the `test-support`
//! feature is enabled, so this scaffolding never ships in the app binary.

use std::io::Read;

use super::download::{
    interpret_range_response, DownloadSource, RangeOutcome, RequestedRange, SourceResponse,
};

/// The ETag every contract harness must report for the current revision of
/// the contract object.
pub const CONTRACT_ETAG: &str = "\"contract-etag-v1\"";

/// A checkpoint validator that is deliberately *stale* — asking for a range
/// with this `If-Match` is what a harness must answer with `412`.
pub const CONTRACT_STALE_ETAG: &str = "\"contract-etag-v0\"";

/// The bytes of the contract object. Small on purpose: this suite proves
/// status/header fidelity, not throughput.
pub const CONTRACT_BODY: &[u8] = b"ylx download source contract body 0123456789abcdef";

/// The offset a resumed (`206`) request asks for.
pub const CONTRACT_RESUME_START: u64 = 16;

/// Total size of [`CONTRACT_BODY`].
#[must_use]
pub fn contract_total() -> u64 {
    CONTRACT_BODY.len() as u64
}

/// One transport outcome every `DownloadSource` implementation must be able
/// to report without lossy re-encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractCase {
    /// `200 OK` — the whole object, from byte 0.
    FullFromZero,
    /// `206 Partial Content` — a resumed tail from [`CONTRACT_RESUME_START`].
    PartialFromOffset,
    /// `412 Precondition Failed` — the object changed since the checkpoint's
    /// validator was recorded.
    PreconditionFailed,
    /// `416 Range Not Satisfiable` — the requested start is past the end.
    RangeNotSatisfiable,
}

impl ContractCase {
    /// Every case, in the order the suite runs them.
    pub const ALL: [ContractCase; 4] = [
        ContractCase::FullFromZero,
        ContractCase::PartialFromOffset,
        ContractCase::PreconditionFailed,
        ContractCase::RangeNotSatisfiable,
    ];

    /// The request the suite issues for this case. Harnesses may key their
    /// scripted answer off it (a real HTTP server naturally does).
    #[must_use]
    pub fn requested_range(self) -> RequestedRange {
        match self {
            ContractCase::FullFromZero => RequestedRange {
                start: 0,
                if_match_etag: None,
            },
            ContractCase::PartialFromOffset => RequestedRange {
                start: CONTRACT_RESUME_START,
                if_match_etag: Some(CONTRACT_ETAG.to_string()),
            },
            ContractCase::PreconditionFailed => RequestedRange {
                start: CONTRACT_RESUME_START,
                if_match_etag: Some(CONTRACT_STALE_ETAG.to_string()),
            },
            ContractCase::RangeNotSatisfiable => RequestedRange {
                start: contract_total(),
                if_match_etag: Some(CONTRACT_ETAG.to_string()),
            },
        }
    }

    /// The HTTP status the harness's server answers with — and therefore the
    /// status the source must hand back verbatim.
    #[must_use]
    pub fn expected_status(self) -> u16 {
        match self {
            ContractCase::FullFromZero => 200,
            ContractCase::PartialFromOffset => 206,
            ContractCase::PreconditionFailed => 412,
            ContractCase::RangeNotSatisfiable => 416,
        }
    }
}

/// Builds the implementation under test, pre-armed to answer
/// [`ContractCase::requested_range`] with `case`'s status.
pub trait DownloadSourceContractHarness {
    /// A human-readable name for this implementation, used in failure
    /// messages.
    fn name(&self) -> &str;

    /// Build a source whose next `fetch_range` answers `case`.
    fn source_for(&self, case: ContractCase) -> Box<dyn DownloadSource>;
}

/// Run the whole suite. Panics (i.e. fails the calling `#[test]`) with a
/// message naming the implementation and the case on the first violation.
pub fn assert_download_source_contract(harness: &dyn DownloadSourceContractHarness) {
    for case in ContractCase::ALL {
        assert_download_source_case(harness, case);
    }
}

/// Run a single case. Exposed so an implementation may narrow a failure to
/// one status without running the rest.
pub fn assert_download_source_case(
    harness: &dyn DownloadSourceContractHarness,
    case: ContractCase,
) {
    let who = harness.name();
    let source = harness.source_for(case);
    let request = case.requested_range();
    let requested_start = request.start;

    let response: SourceResponse = match source.fetch_range(request) {
        Ok(response) => response,
        Err(err) => panic!(
            "{who}/{case:?}: a DownloadSource must report HTTP {} to its caller as a \
             SourceResponse so library::download's state machine can interpret it — \
             squashing it into a transport error ({err:?}) makes that branch unreachable",
            case.expected_status()
        ),
    };

    assert_eq!(
        response.status,
        case.expected_status(),
        "{who}/{case:?}: status must be reported verbatim"
    );

    let outcome = interpret_range_response(
        response.status,
        response.content_range.as_deref(),
        response.content_length,
        requested_start,
    )
    .unwrap_or_else(|err| {
        panic!("{who}/{case:?}: response is not interpretable by library::download: {err}")
    });

    match case {
        ContractCase::FullFromZero => {
            assert_eq!(
                outcome,
                RangeOutcome::FullFromZero {
                    total: Some(contract_total())
                },
                "{who}/{case:?}: a 200 must carry the full Content-Length"
            );
            assert_eq!(
                response.etag.as_deref(),
                Some(CONTRACT_ETAG),
                "{who}/{case:?}: the ETag must be reported verbatim"
            );
            assert_body(who, case, response.body, CONTRACT_BODY);
        }
        ContractCase::PartialFromOffset => {
            assert_eq!(
                outcome,
                RangeOutcome::Partial {
                    start: CONTRACT_RESUME_START,
                    end_inclusive: contract_total() - 1,
                    total: contract_total(),
                },
                "{who}/{case:?}: the Content-Range must survive the source unchanged"
            );
            assert_eq!(
                response.etag.as_deref(),
                Some(CONTRACT_ETAG),
                "{who}/{case:?}: the ETag must be reported verbatim"
            );
            assert_body(
                who,
                case,
                response.body,
                &CONTRACT_BODY[CONTRACT_RESUME_START as usize..],
            );
        }
        ContractCase::PreconditionFailed => {
            assert_eq!(
                outcome,
                RangeOutcome::PreconditionFailed,
                "{who}/{case:?}: a 412 must reach the resume state machine as a \
                 precondition failure, not as an opaque error"
            );
        }
        ContractCase::RangeNotSatisfiable => {
            assert_eq!(
                outcome,
                RangeOutcome::NotSatisfiable {
                    total: Some(contract_total())
                },
                "{who}/{case:?}: a 416's `Content-Range: bytes */total` must survive \
                 the source unchanged"
            );
        }
    }
}

fn assert_body(who: &str, case: ContractCase, mut body: Box<dyn Read + Send>, expected: &[u8]) {
    let mut got = Vec::new();
    body.read_to_end(&mut got)
        .unwrap_or_else(|e| panic!("{who}/{case:?}: reading the response body failed: {e}"));
    assert_eq!(
        got, expected,
        "{who}/{case:?}: the response body must be delivered byte for byte"
    );
}
