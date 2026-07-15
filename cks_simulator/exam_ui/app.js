"use strict";

const base = new URL("./", window.location.href);
const state = { session: null, selected: null, timer: null, serverOffset: 0 };
const $ = (id) => document.getElementById(id);

function api(path, options = {}) {
  return fetch(new URL(path, base), {
    cache: "no-store",
    credentials: "omit",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  }).then(async (response) => {
    const value = await response.json();
    if (!response.ok) throw new Error(value.detail || value.error || "Exam operation failed");
    return value;
  });
}

function progressFor(id) {
  return state.session.progress.find((item) => item.id === id);
}

function selectedTask() {
  return state.session.tasks.find((item) => item.id === state.selected);
}

function formatTime(seconds) {
  const safe = Math.max(0, Math.floor(seconds));
  const hours = String(Math.floor(safe / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((safe % 3600) / 60)).padStart(2, "0");
  const secs = String(safe % 60).padStart(2, "0");
  return `${hours}:${minutes}:${secs}`;
}

function tick() {
  if (!state.session || state.session.status !== "active") return;
  const now = Date.now() + state.serverOffset;
  const remaining = Math.max(0, (Date.parse(state.session.deadline_at) - now) / 1000);
  $("timer").textContent = formatTime(remaining);
  $("timer").closest(".timer").classList.toggle("urgent", remaining <= 300);
  if (remaining <= 0) refresh();
}

function renderTaskList() {
  const list = $("task-list");
  list.replaceChildren();
  state.session.tasks.forEach((task) => {
    const progress = progressFor(task.id);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "task-link";
    button.classList.toggle("selected", task.id === state.selected);
    button.classList.toggle("complete", progress.completed);
    button.classList.toggle("flagged", progress.flagged);
    button.setAttribute("aria-current", task.id === state.selected ? "step" : "false");
    const number = document.createElement("span");
    number.className = "task-index";
    number.textContent = task.id;
    const details = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = task.title;
    const meta = document.createElement("small");
    meta.textContent = `${task.weight}% · ${progress.flagged ? "Review" : progress.completed ? "Complete" : progress.visited ? "Visited" : "Not visited"}`;
    details.append(title, meta);
    button.append(number, details);
    button.addEventListener("click", () => selectTask(task.id));
    const item = document.createElement("li");
    item.append(button);
    list.append(item);
  });
  const complete = state.session.progress.filter((item) => item.completed).length;
  $("progress-summary").textContent = `${complete} of ${state.session.tasks.length} complete`;
}

function renderQuestion() {
  const task = selectedTask();
  const progress = progressFor(task.id);
  $("task-number").textContent = `Task ${task.id} of ${state.session.tasks.length}`;
  $("task-weight").textContent = `${task.weight}%`;
  $("task-title").textContent = task.title;
  $("task-domain").textContent = task.domain;
  $("host-command").textContent = `ssh ${task.host}`;
  $("workdir").textContent = task.workdir;
  $("task-prompt").textContent = task.prompt;
  $("flag-task").textContent = progress.flagged ? "Remove review flag" : "Flag for review";
  $("flag-task").classList.toggle("active", progress.flagged);
  $("complete-task").textContent = progress.completed ? "Completed ✓" : "Mark complete";
  $("complete-task").classList.toggle("done", progress.completed);
  $("previous-task").disabled = task.id === state.session.tasks[0].id;
  $("next-task").disabled = task.id === state.session.tasks[state.session.tasks.length - 1].id;
  $("check-task").hidden = !state.session.can_check;
  $("check-result").hidden = true;
}

function renderDesktop() {
  const frame = $("desktop-frame");
  const empty = $("desktop-empty");
  if (state.session.desktop_url && state.session.status === "active") {
    if (frame.src !== state.session.desktop_url) frame.src = state.session.desktop_url;
    frame.hidden = false;
    empty.hidden = true;
    $("desktop-status").textContent = "Connected through an owner-verified local tunnel";
  } else {
    frame.removeAttribute("src");
    frame.hidden = true;
    empty.hidden = false;
    $("desktop-status").textContent = "Session closed";
  }
}

function renderResult() {
  if (state.session.status !== "submitted" || !state.session.result) return;
  const result = state.session.result;
  $("result-score").textContent = `${Number(result.score).toFixed(1)} / 100`;
  $("result-status").textContent = result.passed ? "Pass" : result.status.split("_").join(" ");
  $("result-summary").textContent = `Required score: ${result.pass_score}. Every declared task remained in the denominator.`;
  const container = $("result-tasks");
  container.replaceChildren();
  result.tasks.forEach((task) => {
    const row = document.createElement("div");
    const label = document.createElement("span");
    label.textContent = `${task.id} · ${task.title}`;
    const score = document.createElement("strong");
    score.textContent = `${Number(task.score).toFixed(0)}%`;
    row.append(label, score);
    container.append(row);
  });
  if (!$("result-dialog").open) $("result-dialog").showModal();
}

function render() {
  state.selected = state.selected || state.session.selected_task_id;
  state.serverOffset = Date.parse(state.session.server_now) - Date.now();
  $("mode-label").textContent = state.session.mode === "exam" ? "Timed exam mode · no interim feedback" : "Practice mode · trusted checks enabled";
  $("submit-button").disabled = !state.session.can_submit;
  $("app").setAttribute("aria-busy", "false");
  renderTaskList();
  renderQuestion();
  renderDesktop();
  renderResult();
  clearInterval(state.timer);
  tick();
  state.timer = setInterval(tick, 1000);
}

async function refresh() {
  try {
    state.session = await api("api/session");
    render();
  } catch (error) {
    toast(error.message, true);
  }
}

async function mutateProgress(id, value) {
  state.session = await api(`api/tasks/${id}/progress`, {
    method: "POST",
    body: JSON.stringify(value),
  });
  render();
}

async function selectTask(id) {
  state.selected = id;
  await mutateProgress(id, { selected: true, visited: true });
}

function adjacent(offset) {
  const index = state.session.tasks.findIndex((item) => item.id === state.selected);
  const task = state.session.tasks[index + offset];
  if (task) selectTask(task.id);
}

async function checkTask() {
  const panel = $("check-result");
  panel.hidden = false;
  panel.textContent = "Collecting trusted observations…";
  try {
    const result = await api(`api/tasks/${state.selected}/check`, { method: "POST", body: "{}" });
    panel.textContent = `${result.status} · ${Number(result.score).toFixed(1)} / 100`;
  } catch (error) {
    panel.textContent = error.message;
  }
}

async function submitExam() {
  $("submit-dialog").close();
  $("confirm-submit").disabled = true;
  toast("Desktop locked. Trusted final grading is running…");
  try {
    state.session = await api("api/submit", { method: "POST", body: "{}" });
    $("toast").hidden = true;
    render();
  } catch (error) {
    toast(error.message, true);
    await refresh();
  } finally {
    $("confirm-submit").disabled = false;
  }
}

function toast(message, isError = false) {
  const node = $("toast");
  node.textContent = message;
  node.classList.toggle("error", isError);
  node.hidden = false;
  clearTimeout(node._timeout);
  node._timeout = setTimeout(() => { node.hidden = true; }, 5000);
}

document.addEventListener("DOMContentLoaded", () => {
  $("previous-task").addEventListener("click", () => adjacent(-1));
  $("next-task").addEventListener("click", () => adjacent(1));
  $("flag-task").addEventListener("click", () => {
    const item = progressFor(state.selected);
    mutateProgress(state.selected, { flagged: !item.flagged });
  });
  $("complete-task").addEventListener("click", () => {
    const item = progressFor(state.selected);
    mutateProgress(state.selected, { completed: !item.completed, visited: true });
  });
  $("check-task").addEventListener("click", checkTask);
  $("submit-button").addEventListener("click", () => $("submit-dialog").showModal());
  $("confirm-submit").addEventListener("click", (event) => { event.preventDefault(); submitExam(); });
  $("collapse-tasks").addEventListener("click", () => document.body.classList.toggle("tasks-collapsed"));
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText($(button.dataset.copy).textContent);
      toast("Copied to clipboard");
    });
  });
  document.addEventListener("keydown", (event) => {
    if (!event.altKey) return;
    if (event.key === "ArrowLeft") adjacent(-1);
    if (event.key === "ArrowRight") adjacent(1);
  });
  refresh();
  setInterval(refresh, 15000);
});
