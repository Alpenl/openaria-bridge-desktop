# Media application wiring contract

This note is intentionally colocated with the facade. It lists the remaining
composition-root work without moving filesystem, FFmpeg, persistence, or
object-store decisions into Tauri commands.

## Crate root and Tauri lifecycle

1. Add `mod media;` in `src-tauri/src/lib.rs`.
2. Build the concrete port adapters after opening `MediaStore` and the other
   production dependencies. Load one exact `MediaProjectionSet` before any
   watcher or worker can run, then construct and `manage` `MediaApplication`.
3. Call `MediaApplication::start(app.handle().clone())` only after both the
   existing `TransferApplication` and the new media facade are managed.
4. On `RunEvent::Exit`, call `MediaApplication::stop()` before destroying the
   composition. `stop` must wait for scanner watchers, import readers, encoder
   child processes, and upload workers to release their resources.
   The facade serializes the lifecycle start/stop boundary so a recovery that
   loses the epoch race cannot start workers after `stop` returns.
5. Register all functions in `media::commands` in the invoke handler. Their
   Rust names exactly match the command names frozen by the frontend.

## Concrete port mapping

- `MediaScannerPort` maps platform volume discovery plus the bounded scanner.
  Its `source_version` is a process-monotonic observation sequence that never
  resets while the facade is alive. `release_media_handles` drains readers and
  watchers before publishing `handleState=released`; `eject_media` calls the
  platform eject adapter only after that boundary.
- `RecordingIngestorPort` maps core `ingest::RecordingIngestor`. Convert core
  `ImportStartOutcome::{Created,Existing}` and command outcomes into the exact
  projected `ImportJob`. Conflicts become `MediaPortError(OperationConflict)`.
  The returned `MediaEffect` must include a complete import-list projection
  from the same committed store transaction/version as the result.
  Durable import identity must use `ImportNaturalKey::canonical_key()`; do not
  use revision-only display helpers such as `as_str()` as the store key.
- `MediaNormalizerPort` maps core `normalization::MediaNormalizer`. Its
  implementation owns the worker that invokes the blocking FFmpeg adapter.
  The application facade never holds a lock across probe/encode/validate and
  never owns a `Child`. Pause/cancel is successful only after the adapter has
  killed/reaped the full process tree and released files.
- `SessionPipelinePort` maps core `media_pipeline::SessionPipeline` plus its
  durable repository. It translates the pure replay decision into idempotent
  import/derivation/upload enqueue operations and returns every changed full
  projection in one `MediaEffect`. It must not copy child-job state into a
  second aggregate. At start it freezes `PipelineSourceSummary` from the
  admitted candidate so a durable `waiting_for_media` row remains meaningful
  after the scanner correctly removes the unplugged card's live candidate.
- Upload is entered only through `SessionPipelinePort`. The concrete worker
  consumes adapter `derived_upload::DerivedUploadAdapter` with a frozen bundle,
  durable `UploadBundleCheckpoint`, `LocalArtifactSource` protected by a shared
  revision lease, and `UploadCheckpointSink`. It publishes
  `object_store_verified` only from `DerivedUploadReceipt`; V1 source archival
  remains disabled and must never be inferred from derivative verification.
- `MediaLifecyclePort::recover` replays media-store jobs/outboxes and returns
  exact full projections. `start` installs volume/job observers only after
  recovery. Every callback is made after the owning transaction commits and
  contains complete replacement values, not row/progress patches.

## Projection versions

Every `Observed<T>::source_version` is the authoritative owner's monotonic
version, separate from the facade's WebView revision. For durable resources,
use a media-store commit/projection version. For scan state, use the scanner
observation sequence. Versions must be strictly increasing when a value
changes and must survive read/mutation races. A late value at an older or equal
source version is deliberately ignored by the facade.

The media-store adapter must use the collection watermarks returned by the
store, not a per-row maximum:

- `MediaStore::import_projection()` supplies the complete import list and its
  `RevisionedCollection::revision`.
- `MediaStore::derivation_projection()` supplies the complete derivation list
  and its collection revision.
- `MediaStore::pipeline_projection()` supplies the complete pipeline snapshot
  list and its collection revision.

Map each collection revision directly to the corresponding
`Observed<T>::source_version`. Every list-visible create, CAS/transition,
terminal completion, or other replacement must increment that revision inside
the same SQLite transaction that commits the row. Never substitute
`max(job.version)`: a newly-created version-1 job must still supersede a stale
projection containing an older job at version 10.

Pipeline persistence has one authoritative typed aggregate. Use
`create_session_pipeline` for admission and `replace_pipeline_projection` for
expected-version updates; use `pipeline_snapshot`/`pipeline_projection` to
recover the complete `SessionPipeline`. `source_key` and the dependency rows
are normalized indexes and consistency checks only. They must agree with the
serialized `pipeline_json` but must never replace it as the recovery source of
candidate, session, schema, media, or provenance facts.

One `MediaProjectionDelta` may carry imports, derivations, and pipelines from
the same orchestration step. The facade updates accepted values under one lock
and assigns them one wire revision, then releases the lock before serialization
and event delivery. A sink failure never rolls back durable state or the cache.

Port `Err` is reserved for an operation that did not commit a visible durable
mutation. Once a job/pipeline transition commits, return `Ok(MediaEffect)` with
the resulting complete projection even when that projection is a typed failed
job state. Later worker failures are published through `MediaProjectionSink`.
Batch results keep per-item failures in their tagged `results` array and a
cross-item/preflight failure only in the separate mandatory `operationError`
field; adapters must never copy one operation error into every item.

## Core-to-wire distinctions

- Core `SourceKind::LegacyRemovableMedia` maps to
  `legacy_removable_media`; do not collapse it into generic removable media.
- Core `SourceSchema::CompleteUnpublishedV6` maps to
  `complete_unpublished_v6` and remains locally validated unsigned.
- Core desired states `Running`, `Paused`, and `Cancelled` map to wire values
  `run`, `paused`, and `cancelled`.
- Core provenance variants map structurally to the wire discriminated union.
  Never construct `DeviceSigned` from an unsigned validation report.
- Pipeline source, derived, and remote layers are independently projected.
  Do not synthesize an aggregate percentage or an `uploaded`/`backedUp` flag.
- `SourceLayer.retentionState` comes from current receipt/artifact evidence.
  A stable `sourceId` alone never proves the local immutable source tree is
  still retained.
- The frontend uses JavaScript safe integers. Mapping code must reject or
  explicitly represent any byte/frame count above `Number.MAX_SAFE_INTEGER`;
  it must not silently round a `u64`.

## Stable commands and events

Commands:

- `media_read_snapshot`
- `media_read_scan_candidates`
- `media_read_import_jobs`
- `media_read_derivation_jobs`
- `media_read_pipeline_sessions`
- `media_scan`
- `media_start_import`
- `media_start_import_batch`
- `media_start_derivation`
- `media_start_pipeline`
- `media_start_pipeline_batch`
- `media_command_import`
- `media_command_derivation`
- `media_command_pipeline`
- `media_release_handles`
- `media_eject`

Events:

- `media:scan:update`
- `media:imports:update`
- `media:derivations:update`
- `media:pipelines:update`
