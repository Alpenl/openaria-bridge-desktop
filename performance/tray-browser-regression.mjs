/* global document, MutationObserver, structuredClone */
import { createTrayScreen } from "../src/ui/views/trayScreen.ts";
import { selectTray } from "../src/ui/traySelector.ts";

// Run in a browser served by Vite. No Tauri bridge or live device is required.
export function runTrayBrowserRegression() {
  document.body.innerHTML =
    '<section id="tray"><span id="trayCount"></span><button id="trayToggleBtn"></button><div id="trayBody"></div></section>';
  const actions = [];
  const checks = [];
  const screen = createTrayScreen((action) => actions.push(action));
  const body = document.getElementById("trayBody");
  function check(condition, name) {
    if (!condition) throw new Error(name);
    checks.push(name);
  }
  function job(jobId, transferredBytes = 10, state = { state: "transferring" }) {
    return {
      jobId,
      deviceId: "device-1",
      deviceDisplayId: "Device 1",
      sessionId: jobId,
      state,
      desiredRunState: "running",
      transferredBytes,
      totalBytes: 1000,
      filesDone: 0,
      filesTotal: 2,
    };
  }
  const render = (jobs, resource = { error: null, loading: false }) =>
    screen.render(selectTray([], jobs, false, resource));
  const first = job("take-1");
  const second = job("take-2");
  render([first, second]);
  const firstRow = body.children[0];
  const secondRow = body.children[1];
  const button = secondRow.querySelector('[data-action="pause-transfer-job"]');
  button.focus();
  const observer = new MutationObserver(() => {});
  observer.observe(body, { subtree: true, childList: true });
  try {
    render([structuredClone(first), structuredClone(second)]);
    check(observer.takeRecords().length === 0, "identical snapshots do not mutate tray children");
    for (let tick = 1; tick <= 100; tick++) render([job("take-1", tick), job("take-2", tick)]);
    check(body.children[0] === firstRow && body.children[1] === secondRow, "progress retains row identity");
    check(document.activeElement === button && button.isConnected, "progress retains the focused control");
    check(secondRow.querySelector(".transfer-stats").textContent.includes("10%"), "progress text is current");
    const progressMutations = observer.takeRecords().length;
    render([job("take-1", 1000, { state: "succeeded" }), job("take-2", 100)]);
    check(body.children.length === 1 && body.children[0] === secondRow, "retired rows are removed");
    check(document.activeElement === button, "retiring the preceding job preserves focus");
    render([job("take-2", 100)], { error: "<offline>", loading: false });
    check(body.firstElementChild.textContent.includes("<offline>"), "errors are escaped and inserted ahead of jobs");
    check(body.querySelector("offline") === null, "error content cannot inject markup");
    render([job("take-2", 100)]);
    check(body.children.length === 1 && body.children[0] === secondRow, "clearing an error retains job identity");
    check(document.activeElement === button, "clearing an error preserves control focus");
    render([job("take-2", 100), first]);
    check(body.children[0] === secondRow, "appending jobs retains preceding rows");
    render([first, job("take-2", 100)]);
    check(
      body.children[0].dataset.trayKey === "job:take-1" && body.children[1] === secondRow,
      "backend ordering is respected",
    );
    button.click();
    check(
      actions.length === 1 && actions[0].command.jobId === "take-2",
      "delegated controls use the current typed identity",
    );
    render([job("take-2", 100, { state: "failed", code: "network", retryable: true })]);
    check(body.querySelector('[data-action="retry-transfer"]') !== null, "terminal failures replace live controls");
    check(body.querySelector('[data-action="pause-transfer-job"]') === null, "obsolete controls are removed");
    render([]);
    check(body.children.length === 0, "empty queues clear retired DOM");
    render([first, second]);
    check(body.children.length === 2, "queues can reopen after clearing");
    return { checks, progressMutations };
  } finally {
    observer.disconnect();
    screen.dispose();
  }
}
