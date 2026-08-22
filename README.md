# Open Aria Bridge / Desktop

Open Aria Bridge / Desktop is the graphical client for discovering Open Aria
capture devices, importing verified recording sessions, recovering interrupted
transfers, maintaining a local library, and publishing selected recordings to
an S3-compatible object store.

The application is built with Tauri 2, Rust, and TypeScript. Production builds
use the real mDNS, HTTPS, removable-media, filesystem, SQLite, OS keyring, and
object-store adapters. Simulation code is available only through the explicit
Rust `demo` feature.

## Product boundary

The desktop client owns the human-operated Bridge workflow:

- discover or manually add a device and pin its TLS identity;
- pair, list sessions, and download a full session or selected files;
- validate signed publication material, paths, sizes, and SHA-256 claims;
- pause, cancel, retry, and recover durable transfers after a restart;
- import supported removable-media layouts without writing to the source;
- publish verified local recordings with resumable multipart upload; and
- keep object-store credentials in the operating-system credential vault.

Device capture and Device API authority belong to
[Open Aria Conductor](https://github.com/Alpenl/openaria-conductor). This
repository contains only the desktop client and its local test fixtures.

## Compatibility

The public product name is **Open Aria Bridge**. The 0.5 codebase intentionally
retains several `ylx-transfer` package, crate, executable, state-directory, and
wire identifiers so existing installations and recorded data continue to
work. Those identifiers are compatibility surfaces, not a second product.

## Prerequisites

- Node.js 22 or newer
- npm
- stable Rust with `rustfmt` and `clippy`
- the native libraries required by Tauri 2 on the target platform

On Debian or Ubuntu, the usual build dependencies are:

```bash
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
  libayatana-appindicator3-dev patchelf build-essential curl wget file libssl-dev
```

## Development

Install the locked frontend dependencies and start the desktop application:

```bash
npm ci
npm run tauri dev
```

The default build contains no object-store secret. Configure credentials in the
application, inject them through the documented build environment, or supply a
runtime bootstrap file outside the repository. Never commit credential files.

## Verification

Frontend and contract checks:

```bash
npm test
npm run contracts:check
npm run format:check
npm run lint
npm run typecheck
npm run build
npm audit
```

Rust checks:

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml \
  --workspace --all-targets --all-features
```

Build platform installers:

```bash
npm run tauri build
```

CI additionally runs a pinned MinIO contract and the filesystem recovery suite
on Ubuntu, macOS, and Windows. Cross-repository tests that require unpublished
source are deliberately excluded from this public repository; integration
against Conductor must use public fixtures or a deployed Device API.

## Architecture

The root Rust workspace is `src-tauri/Cargo.toml`:

```text
src/
  app/             workflow controllers and operation lifetimes
  runtime/         Tauri backend adapter, snapshots, events, reducer
  ui/              screens and DOM rendering
src-tauri/src/
  application.rs   application protocol and revisioned projections
  composition.rs   production adapters and lifecycle
  commands.rs      validated Tauri RPC boundary
  state.rs         boot, migration, and application state
src-tauri/crates/ylx-transfer-core/
  domain/          identities and verified publication material
  device/          device actors, fleet state, and fencing
  transfer/        state machine, coordinator, and recovery
  persistence/     durable application and transfer stores
src-tauri/crates/ylx-transfer-adapters/
  device, media, keyring, and S3-compatible adapters
fixtures/
  public RPC, removable-media, and Device Session conformance inputs
```

`TransferStore` is the durable authority for transfer identity, immutable job
specifications, state versions, checkpoints, retry lineage, upload receipts,
and terminal outbox delivery. Credentials never enter its SQLite schema.

## Security notes

- Device identities use full certificate fingerprints; short labels are for
  display and legacy lookup only.
- Session and publication JSON is parsed strictly and fails closed on unknown
  or malformed contract input.
- Download publication is staged and atomically committed only after artifact
  verification.
- Removable media is treated as read-only evidence.
- Object-store access keys are write-only UI input and are stored in the OS
  keyring, not frontend state or SQLite.
- Build-time credentials, when deliberately supplied, are extractable from the
  binary and must be narrowly scoped.

## License

See [LICENSE](LICENSE).
