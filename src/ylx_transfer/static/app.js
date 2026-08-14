const $ = (selector) => document.querySelector(selector);
const state = { sources: [], sessions: [], local_sessions: [], tasks: [], publications: [] };

const labels = {
  device: "设备",
  media: "介质",
  import: "导入",
  download: "下载",
  upload: "上传",
  publish: "发布",
  queued: "等待中",
  running: "进行中",
  pause_requested: "正在暂停",
  paused: "已暂停",
  cancel_requested: "正在取消",
  cancelled: "已取消",
  failed: "失败",
  succeeded: "已完成",
  online: "在线",
  offline: "离线",
};

async function request(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || "请求失败");
  return payload;
}

function showMessage(text, success = false) {
  const element = $("#message");
  element.textContent = text;
  element.classList.toggle("success", success);
  element.hidden = false;
  window.clearTimeout(showMessage.timer);
  showMessage.timer = window.setTimeout(() => { element.hidden = true; }, 5000);
}

function cell(text, className = "") {
  const element = document.createElement("td");
  element.textContent = text ?? "-";
  if (className) element.className = className;
  return element;
}

function badge(value) {
  const element = document.createElement("span");
  element.className = `badge ${value}`;
  element.textContent = labels[value] || value;
  return element;
}

function emptyRow(target, columns, text) {
  const row = document.createElement("tr");
  const value = cell(text, "empty-cell");
  value.colSpan = columns;
  row.append(value);
  target.replaceChildren(row);
}

function dateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

function bytes(value) {
  if (!Number.isFinite(Number(value))) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = Number(value);
  let index = 0;
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
  return `${current >= 10 || index === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[index]}`;
}

function renderSources() {
  const rows = $("#source-rows");
  $("#source-count").textContent = state.sources.length;
  if (!state.sources.length) { emptyRow(rows, 5, "暂无来源"); return; }
  rows.replaceChildren(...state.sources.map((source) => {
    const row = document.createElement("tr");
    row.append(cell(source.display_name));
    row.append(cell(labels[source.kind] || source.kind));
    row.append(cell(source.stable_id, "mono"));
    const location = cell("");
    const text = document.createElement("span");
    text.className = "truncate mono";
    text.title = source.locations.map((item) => item.location).join("\n");
    text.textContent = source.locations.find((item) => item.availability === "online")?.location || source.locations[0]?.location || "-";
    location.append(text);
    row.append(location);
    const status = cell(""); status.append(badge(source.availability)); row.append(status);
    return row;
  }));
}

function renderSourceSessions() {
  const rows = $("#source-session-rows");
  $("#source-session-count").textContent = state.sessions.length;
  const sourceMap = new Map(state.sources.map((source) => [source.source_id, source]));
  if (!state.sessions.length) { emptyRow(rows, 5, "暂无来源会话"); return; }
  rows.replaceChildren(...state.sessions.map((session) => {
    const source = sourceMap.get(session.source_id);
    const row = document.createElement("tr");
    row.append(cell(session.label || session.session_id));
    row.append(cell(source?.display_name || session.source_id));
    row.append(cell(dateTime(session.created_at)));
    const status = cell(""); status.append(badge(session.availability)); row.append(status);
    const actions = cell("");
    if (["device", "media"].includes(source?.kind) && session.availability === "online") {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "导入";
      button.dataset.import = session.record_id;
      actions.append(button);
    } else {
      actions.textContent = "-";
      actions.classList.add("muted");
    }
    row.append(actions);
    return row;
  }));
}

function renderLocal() {
  const rows = $("#local-rows");
  $("#local-count").textContent = state.local_sessions.length;
  if (!state.local_sessions.length) { emptyRow(rows, 6, "暂无本地会话"); return; }
  rows.replaceChildren(...state.local_sessions.map((session) => {
    const row = document.createElement("tr");
    row.append(cell(session.session_id));
    row.append(cell(session.revision.slice(0, 12), "mono"));
    row.append(cell(bytes(session.total_bytes)));
    row.append(cell(dateTime(session.imported_at)));
    const path = cell("");
    const value = document.createElement("span");
    value.className = "truncate mono";
    value.title = session.path;
    value.textContent = session.path;
    path.append(value); row.append(path);
    const actions = cell("");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "发布";
    button.dataset.publish = session.local_session_id;
    actions.append(button);
    row.append(actions);
    return row;
  }));
}

function taskControls(task) {
  const container = document.createElement("div");
  container.className = "task-actions";
  const add = (action, label, secondary = false) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.dataset.task = task.task_id;
    button.dataset.action = action;
    if (secondary) button.className = "secondary";
    container.append(button);
  };
  if (task.state === "running") {
    if (["download", "upload"].includes(task.kind)) add("pause", "暂停", true);
    add("cancel", "取消", true);
  } else if (task.state === "queued") {
    add("cancel", "取消", true);
  } else if (task.state === "paused") {
    add("resume", "继续");
    add("cancel", "取消", true);
  } else if (["failed", "cancelled"].includes(task.state)) {
    add("retry", "重试");
  }
  if (!container.childElementCount) container.textContent = "-";
  return container;
}

function renderTasks() {
  const rows = $("#task-rows");
  $("#task-count").textContent = state.tasks.length;
  if (!state.tasks.length) { emptyRow(rows, 5, "暂无任务"); return; }
  rows.replaceChildren(...state.tasks.map((task) => {
    const row = document.createElement("tr");
    const identity = cell("");
    const kind = document.createElement("strong"); kind.textContent = labels[task.kind] || task.kind;
    const id = document.createElement("span"); id.className = "mono muted"; id.textContent = ` ${task.task_id.slice(0, 8)}`;
    identity.append(kind, id); row.append(identity);
    const status = cell(""); status.append(badge(task.state)); row.append(status);
    const progressCell = cell("");
    const total = task.progress.total || 0;
    const current = Math.min(task.progress.current || 0, total || task.progress.current || 0);
    const ratio = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : 0;
    const progress = document.createElement("div"); progress.className = "progress";
    const track = document.createElement("div"); track.className = "progress-track";
    const bar = document.createElement("div"); bar.className = "progress-bar"; bar.style.width = `${ratio}%`;
    const label = document.createElement("span"); label.className = "progress-label";
    label.textContent = total > 0 ? `${bytes(current)} / ${bytes(total)} · ${ratio}%` : "等待任务信息";
    track.append(bar); progress.append(track, label); progressCell.append(progress); row.append(progressCell);
    const result = cell("");
    if (task.error) {
      const detail = document.createElement("div"); detail.className = "error-detail";
      const code = document.createElement("strong"); code.textContent = task.error.code;
      const message = document.createElement("span"); message.textContent = `${task.error.message} ${task.error.recovery_action || ""}`;
      detail.append(code, message); result.append(detail);
    } else {
      result.textContent = task.state === "succeeded" ? "已验证完成" : dateTime(task.updated_at);
      result.classList.add("muted");
    }
    row.append(result);
    const actions = cell(""); actions.append(taskControls(task)); row.append(actions);
    return row;
  }));
}

function render() {
  renderSources();
  renderSourceSessions();
  renderLocal();
  renderTasks();
  $("#metric-sources").textContent = state.sources.filter((item) => item.availability === "online").length;
  $("#metric-sessions").textContent = state.local_sessions.length;
  $("#metric-tasks").textContent = state.tasks.filter((item) => ["queued", "running", "pause_requested", "cancel_requested"].includes(item.state)).length;
}

async function refresh() {
  try {
    const [health, snapshot] = await Promise.all([request("/api/health"), request("/api/state")]);
    Object.assign(state, snapshot);
    const element = $("#health");
    element.textContent = health.sdk === "ready" ? "服务与 SDK 正常" : "服务正常 · SDK 未连接";
    element.className = `status ${health.sdk === "ready" ? "online" : "warning"}`;
    render();
  } catch (error) {
    $("#health").textContent = "本地服务已断开";
    $("#health").className = "status";
    showMessage(error.message);
  }
}

document.addEventListener("click", async (event) => {
  const open = event.target.closest("[data-open]");
  if (open) { $(`#${open.dataset.open}`).showModal(); return; }
  const close = event.target.closest("[data-close]");
  if (close) { close.closest("dialog").close(); return; }
  const tab = event.target.closest("[data-tab]");
  if (tab) {
    document.querySelectorAll("[role=tab]").forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
    document.querySelectorAll(".tab-panel").forEach((panel) => { panel.hidden = panel.id !== `panel-${tab.dataset.tab}`; });
    return;
  }
  const importButton = event.target.closest("[data-import]");
  if (importButton) {
    importButton.disabled = true;
    try {
      await request("/api/imports", { method: "POST", body: JSON.stringify({ source_session_record_id: importButton.dataset.import }) });
      showMessage("导入任务已创建", true); await refresh();
    } catch (error) { showMessage(error.message); }
    return;
  }
  const publishButton = event.target.closest("[data-publish]");
  if (publishButton) {
    $("#publication-local-session-id").value = publishButton.dataset.publish;
    $("#publication-dialog").showModal();
    return;
  }
  const taskButton = event.target.closest("[data-task][data-action]");
  if (taskButton) {
    taskButton.disabled = true;
    try {
      await request(`/api/tasks/${taskButton.dataset.task}/${taskButton.dataset.action}`, { method: "POST", body: "{}" });
      await refresh();
    } catch (error) { showMessage(error.message); }
  }
});

$("#refresh").addEventListener("click", refresh);

$("#device-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const payload = { endpoint: form.get("endpoint") };
  const credentialRef = String(form.get("credential_ref") || "").trim();
  const pinValue = String(form.get("tls_pin_value") || "").trim();
  if (credentialRef) payload.credential_ref = credentialRef;
  if (pinValue) {
    payload.tls_pin = {
      target: String(form.get("tls_pin_target") || "").trim(),
      algorithm: String(form.get("tls_pin_algorithm") || "").trim(),
      encoding: String(form.get("tls_pin_encoding") || "").trim(),
      value: pinValue,
    };
  }
  try {
    const result = await request("/api/sources/device", { method: "POST", body: JSON.stringify(payload) });
    formElement.closest("dialog").close();
    showMessage(`设备已连接，发现 ${result.sessions} 个会话`, true); await refresh();
  } catch (error) { showMessage(error.message); }
});

$("#media-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  try {
    const result = await request("/api/sources/media", { method: "POST", body: JSON.stringify({ path: form.get("path") }) });
    formElement.closest("dialog").close();
    showMessage(`介质扫描完成，发现 ${result.sessions} 个会话`, true); await refresh();
  } catch (error) { showMessage(error.message); }
});

$("#transfer-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = Object.fromEntries(new FormData(formElement));
  form.total_size = Number(form.total_size);
  form.chunk_size = Number(form.chunk_size);
  try {
    await request("/api/transfers", { method: "POST", body: JSON.stringify(form) });
    formElement.closest("dialog").close();
    showMessage("传输任务已创建", true); await refresh();
  } catch (error) { showMessage(error.message); }
});

$("#publication-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = Object.fromEntries(new FormData(formElement));
  if (!form.endpoint_url) delete form.endpoint_url;
  if (!form.region_name) delete form.region_name;
  if (!form.credential_ref) delete form.credential_ref;
  try {
    await request("/api/publications", { method: "POST", body: JSON.stringify(form) });
    formElement.closest("dialog").close();
    showMessage("发布任务已创建", true); await refresh();
  } catch (error) { showMessage(error.message); }
});

refresh();
window.setInterval(() => { if (!document.hidden) refresh(); }, 2000);
