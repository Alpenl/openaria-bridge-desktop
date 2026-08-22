// Assembly and mounting.
//
// This module owns no state, renders nothing and talks to no transport. It
// chooses the concrete adapters — the Tauri backend, the system clock, the DOM
// view, the toast surface — hands them to `TransferApp`, starts it, and makes
// sure it is disposed on unload and on hot reload. Everything else lives behind
// those two seams: `app/transferApp.ts` for behaviour, `ui/views/*` for pixels.

import "./styles/app.css";

import { createTransferApp } from "./app/transferApp";
import { systemClock } from "./runtime/clock";
import { createTauriBackend } from "./runtime/tauriBackend";
import { createTauriMediaBackend } from "./runtime/media/tauriTransport";
import { createDomAppView } from "./ui/views/appDom";
import { toast } from "./ui/toast";

const app = createTransferApp({
  backend: createTauriBackend(),
  mediaBackend: createTauriMediaBackend(),
  clock: systemClock,
  toast,
  view: createDomAppView,
});

/** Idempotent: shutdown, hot reload and tests may all call it. */
function shutdown(): void {
  app.dispose();
}

window.addEventListener("beforeunload", shutdown);
// Vite injects `import.meta.hot` only in dev; typed locally so the production
// build does not need the vite/client ambient types.
const hot = (import.meta as ImportMeta & { hot?: { dispose: (cb: () => void) => void } }).hot;
hot?.dispose(shutdown);

// A filesystem reconciliation is a background refresh, so it is triggered by
// the window's own lifecycle rather than by anything the user clicked.
window.addEventListener("focus", () => app.dispatch({ kind: "library/reconcile", force: false }));
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") app.dispatch({ kind: "library/reconcile", force: false });
});

void app.start();
