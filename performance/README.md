# Session refresh performance regression

This harness is the reproducible software-only evidence for
[`mirrorbloom/openaria-score#32`](https://github.com/mirrorbloom/openaria-score/issues/32).
It exercises the production SQLite batch query used to project transfer state
onto the current session page. The benchmark feature is opt-in and is not
linked into the desktop application.

## Fixed workload

Every run creates a new temporary SQLite database and verifies the rows it
actually stored before measuring:

| Input              |       Count |
| ------------------ | ----------: |
| Sessions           |         500 |
| Download jobs      |      10,000 |
| Completion records |      10,000 |
| Artifact records   |      50,000 |
| Visible page       | 50 sessions |

The report includes observations for first entry, manual refresh, background
refresh, and opening one detail view. It also measures the batch query with 0,
50, 500, and 1,000 requested session identities.

## Regression gate

The following are hard failures:

- A page or detail trace executes other than one catalog request and one
  transfer-state SQL statement.
- A list trace performs any artifact metadata operation. Detail may inspect
  one canonical processed asset.
- SQL or metadata counts change as the requested identity set grows from 0 to
  1,000.
- The current page refresh p95 is less than 5x faster than the deterministic
  pre-batch reference in the same process.

The JSON report records p50 and p95 nanoseconds for every trace and the legacy
reference. Absolute time is evidence for trend analysis, not a hard threshold,
because GitHub-hosted runner hardware can vary. Query and metadata counters are
deterministic hard gates; the broad timing gate is a same-run ratio over the
same fixed fixture.

The list path never substitutes a stale cache for the current transfer-store
snapshot. Existing revision/generation fences and the navigation single-flight
controller remain the product mechanisms. The normal frontend CI tests also
verify that first paint precedes native refresh and repeated same-device focus
shares one in-flight request.

## Run locally

Linux or macOS:

```bash
cargo run --manifest-path src-tauri/Cargo.toml \
  -p ylx-transfer-core --release \
  --features performance-benchmark \
  --bin session-refresh-benchmark -- \
  --warmup 2 --samples 11 \
  --output performance-results/session-refresh.json
```

Windows PowerShell:

```powershell
cargo run --manifest-path src-tauri/Cargo.toml `
  -p ylx-transfer-core --release `
  --features performance-benchmark `
  --bin session-refresh-benchmark -- `
  --warmup 2 --samples 11 `
  --output performance-results/session-refresh.json
```

The command writes the same machine-readable report to the requested path and
stdout. Exit code `3` means the report was written but a performance gate
failed; other benchmark or argument failures use exit code `2`.

## CI and Windows boundary

The dedicated workflow runs the Release-mode core benchmark on both Linux and
Windows and retains each JSON report for 30 days. This covers the native
Windows Rust/SQLite query path without requiring a device.

It does not claim an installed Tauri GUI trace on a stable physical Windows
reference machine, a real user's library/disk, or device network latency. That
final packaged-application trace remains a manual acceptance boundary. Device
hardware, removable media, ENOSPC, power loss, process interruption, and
recovery scenarios are intentionally outside this benchmark.

## Frontend snapshots and lists

Run the deterministic frontend fixture with Node 22:

```bash
node --import ./src/test-support/register-loader.mjs performance/frontend-benchmark.mjs
```

The fixture has 500 library rows with 10 files each. It alternates the old and
current implementation, warms both, and reports medians from 11 samples of
50 iterations. The selection reference retains the old date-parsing comparator
and key projection. These are CPU measurements, not device or disk latency.

A local Linux / Node 22.22.2 run on 2026-09-08 measured:

| Operation             |  Before |     After |
| --------------------- | ------: | --------: |
| Equal cloned snapshot | 1.80 ms |   0.87 ms |
| Changed first row     | 1.77 ms | 0.0017 ms |
| Library selection     | 1.25 ms |   0.27 ms |

The changed-prefix case benefits from early exit; changes at the end must still
visit preceding values. Timings vary by machine and are not CI thresholds.

## Transfer tray browser regression

Start Vite with `npm run dev`, open its URL in Chromium, then run this in the
browser console:

```js
const regression = await import("/performance/tray-browser-regression.mjs");
regression.runTrayBrowserRegression();
```

This replaces the page with a synthetic queue. The checks exercise 100 progress
updates, stable row and focused-control identities, task retirement, escaped
errors, ordering, delegated commands, terminal controls, and closing/reopening
the queue. It uses the production selector and DOM renderer without a Tauri
bridge or a device. The local Chromium run passed all 17 assertions.
