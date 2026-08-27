# Open Aria Bridge / Desktop

Open Aria Bridge / Desktop is the graphical client for discovering Open Aria
capture devices over the LAN, importing verified recording sessions,
maintaining a local library, and publishing selected recordings to
an S3-compatible object store.

The application is built with Tauri 2, Rust, and TypeScript. Production builds
use the real mDNS, HTTPS, filesystem, SQLite, OS keyring, and object-store
adapters. Simulation code is available only through the explicit Rust `demo`
feature.

## Product boundary

The desktop client owns the human-operated Bridge workflow:

- discover or manually add a device and pin its TLS identity;
- pair, list sessions, and download a full session or selected files;
- validate signed publication material, paths, sizes, and SHA-256 claims;
- cancel or explicitly retry a transfer during normal operation;
- publish verified local recordings with multipart upload; and
- keep object-store credentials in the operating-system credential vault.

[Score D-049](https://github.com/mirrorbloom/openaria-score/blob/main/docs/DECISIONS.md#d-049-fixed-storage-and-lan-only-delivery-removable-and-interruption-workflows-retired)
sets the current 0.5 route to LAN only. Production assembly does not construct
the removable-media backend, render its workspace, or expose a media navigation
item. Physical cards, safe swap, and recovery after power, process, network, or
operation interruption are not current product promises or release gates.

Device capture and Device API authority belong to
[Open Aria Conductor](https://github.com/Alpenl/openaria-conductor). This
repository contains only the desktop client and its local test fixtures.

## Compatibility

The public product name is **Open Aria Bridge**. The 0.5 codebase intentionally
retains several `ylx-transfer` package, crate, executable, state-directory, and
wire identifiers so existing installations and recorded data continue to
work. Those identifiers are compatibility surfaces, not a second product.

The repository also retains removable-media readers, commands, fixtures, and
recovery machinery as frozen compatibility code. They remain testable in
explicit legacy harnesses, but are not mounted by `src/main.ts`, advertised in
the product UI, shipped as a supported 0.5 route, or used to infer a recovery
guarantee.

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

## In-app updates

Open Aria Bridge checks the public GitHub Release update manifest from inside
the app and downloads updater packages through Tauri's signed updater. Users do
not need to open GitHub or choose an installer manually.

The release workflow enables Tauri updater artifacts only for release builds,
signs them with the repository `TAURI_SIGNING_PRIVATE_KEY` secret, publishes the
signed updater archives and `.sig` files, and writes `latest.json` to the
GitHub Release. The updater public key is compiled into
`src-tauri/tauri.conf.json`; losing the matching private key breaks future
in-app updates for already shipped builds.

CI may continue to run pinned MinIO and legacy filesystem/recovery regressions
on Ubuntu, macOS, and Windows to keep retained readers from corrupting old
data; those regressions are compatibility checks, not current product
acceptance. Cross-repository tests that require unpublished
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
  device, compatibility media, keyring, and S3-compatible adapters
fixtures/
  public RPC, compatibility-media, and Device Session conformance inputs
```

`TransferStore` retains durable transfer identity, immutable job specifications,
state versions, checkpoints, retry lineage, upload receipts, and terminal
outbox delivery. These internal records prevent false success and preserve
compatibility; D-049 does not promise automatic continuation after an
interruption. Credentials never enter its SQLite schema.

## Security notes

- Device identities use full certificate fingerprints; short labels are for
  display and legacy lookup only.
- Session and publication JSON is parsed strictly and fails closed on unknown
  or malformed contract input.
- Download publication is staged and atomically committed only after artifact
  verification.
- Frozen removable-media readers treat historical sources as read-only evidence
  and are not reachable from the current production UI.
- Object-store access keys are write-only UI input and are stored in the OS
  keyring, not frontend state or SQLite.
- Build-time credentials, when deliberately supplied, are extractable from the
  binary and must be narrowly scoped.

## License

See [LICENSE](LICENSE).
