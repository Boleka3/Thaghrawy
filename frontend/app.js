const state = {
  engagementId: null,
  target: "",
  socket: null,
  socketRetryCount: 0,
  socketRetryTimer: null,
};

const chatLog = document.getElementById("chat-log");
const chatInput = document.getElementById("chat-input");
const connStatus = document.getElementById("conn-status");
const engagementLabel = document.getElementById("engagement-label");
const activeList = document.getElementById("active-engagements");
const pastList = document.getElementById("past-engagements");
const findingsList = document.getElementById("findings-list");
const reportsList = document.getElementById("reports-list");
const phaseBanner = document.getElementById("phase-banner");

// Modal state
let _modalResolve = null;

// ── Toast system ─────────────────────────────────────────────────────────────

function showToast(message, type) {
  type = type || "info";
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = message;
  el.addEventListener("click", () => { el.remove(); });
  container.appendChild(el);
  setTimeout(() => {
    if (el.parentNode) { el.style.transition = "opacity 300ms"; el.style.opacity = "0"; }
    setTimeout(() => { if (el.parentNode) el.remove(); }, 300);
  }, 4000);
}

// ── Modal system ─────────────────────────────────────────────────────────────

function closeModal() {
  const overlay = document.getElementById("modal-overlay");
  overlay.classList.add("hidden");
  document.getElementById("modal-body").innerHTML = "";
  document.getElementById("modal-actions").innerHTML = "";
  if (_modalResolve) { _modalResolve(null); _modalResolve = null; }
}

function showModal(title, bodyHTML, actions) {
  return new Promise((resolve) => {
    _modalResolve = resolve;
    document.getElementById("modal-title").textContent = title;
    document.getElementById("modal-body").innerHTML = bodyHTML;
    const actionsDiv = document.getElementById("modal-actions");
    actionsDiv.innerHTML = "";
    (actions || []).forEach((a) => {
      const btn = document.createElement("button");
      btn.className = a.cls || "";
      btn.textContent = a.label;
      btn.addEventListener("click", () => {
        const val = a.value ? a.value() : true;
        if (val !== false) { closeModal(); resolve(val); }
      });
      actionsDiv.appendChild(btn);
    });
    document.getElementById("modal-overlay").classList.remove("hidden");
    // Focus first input if any
    const firstInput = document.querySelector("#modal-body input, #modal-body select");
    if (firstInput) setTimeout(() => firstInput.focus(), 100);
  });
}

function showConfirm(title, message) {
  return showModal(title, `<p>${message}</p>`, [
    { label: "Cancel", cls: "cancel-btn", value: () => false },
    { label: "Confirm", cls: "confirm-btn", value: () => true },
  ]);
}

function showPrompt(title, fields) {
  let html = "";
  const ids = [];
  fields.forEach((f, i) => {
    const id = `_prompt_${i}`;
    ids.push(id);
    const opts = f.options
      ? `<select id="${id}" class="${f.required ? "required" : ""}">${f.options.map((o) => `<option value="${o}">${o}</option>`).join("")}</select>`
      : `<input id="${id}" type="${f.type || "text"}" value="${(f.default || "").replace(/"/g, "&quot;")}" placeholder="${f.placeholder || ""}" class="${f.required ? "required" : ""}" />`;
    html += `<div class="field"><label>${f.label}</label>${opts}<div class="error-text">${f.error || "This field is required"}</div></div>`;
  });
  return showModal(title, html, [
    {
      label: "Cancel", cls: "cancel-btn", value: () => {
        document.querySelectorAll("#modal-body .required").forEach((el) => el.classList.remove("invalid"));
        return false;
      },
    },
    {
      label: "OK", cls: "confirm-btn", value: () => {
        const vals = {};
        let valid = true;
        ids.forEach((id, i) => {
          const el = document.getElementById(id);
          const f = fields[i];
          vals[f.key] = el.value;
          if (f.required && !el.value.trim()) {
            el.classList.add("invalid");
            el.parentNode.querySelector(".error-text").classList.add("show");
            valid = false;
          } else {
            el.classList.remove("invalid");
            const et = el.parentNode.querySelector(".error-text");
            if (et) et.classList.remove("show");
          }
        });
        return valid ? vals : false;
      },
    },
  ]);
}

// ── Loading state helper ────────────────────────────────────────────────────

function setLoading(elId, loading) {
  const el = document.getElementById(elId);
  if (el) el.classList.toggle("hidden", !loading);
}

// ── Button state helpers ────────────────────────────────────────────────────

function updateButtonStates(hasEngagement) {
  ["enumerate-btn", "stop-btn", "report-btn", "compact-btn", "interrupt-btn", "add-finding-btn", "generate-reports-btn"].forEach((id) => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = !hasEngagement;
  });
}

// ── API helper ──────────────────────────────────────────────────────────────

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`${response.status} ${text.slice(0, 120)}`);
  }
  return response.json();
}

// ── appendLine ──────────────────────────────────────────────────────────────

let _autoScroll = true;

function _scrollToBottom() {
  if (_autoScroll) chatLog.scrollTop = chatLog.scrollHeight;
}

// Detect user scrolling up
chatLog.addEventListener("scroll", () => {
  const atBottom = chatLog.scrollHeight - chatLog.scrollTop - chatLog.clientHeight < 40;
  const hint = document.getElementById("scroll-lock-hint");
  if (!atBottom && _autoScroll) {
    _autoScroll = false;
    hint.classList.remove("hidden");
  } else if (atBottom && !_autoScroll) {
    _autoScroll = true;
    hint.classList.add("hidden");
  }
});

// Click scroll-lock hint to re-enable auto-scroll
document.getElementById("scroll-lock-hint").addEventListener("click", () => {
  _autoScroll = true;
  document.getElementById("scroll-lock-hint").classList.add("hidden");
  _scrollToBottom();
});

function appendLine(cssClass, tag, text) {
  const line = document.createElement("div");
  line.className = `chat-line ${cssClass}`;
  if (tag) {
    const tagSpan = document.createElement("span");
    tagSpan.className = "tag";
    tagSpan.textContent = `[${tag}]`;
    line.appendChild(tagSpan);
  }
  if (text) line.appendChild(document.createTextNode(text));
  chatLog.appendChild(line);
  _scrollToBottom();
  return line;
}

function appendStreamingAgentLine() {
  return appendLine("agent", "AGENT", "");
}

function setPhase(phase) {
  if (!phase) return;
  phaseBanner.textContent = `PHASE: ${phase.toUpperCase()}`;
  phaseBanner.className = `phase-banner phase-${phase}`;
}

function sendControl(obj) {
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    state.socket.send(JSON.stringify(obj));
  }
}

// ── Engagement CRUD ─────────────────────────────────────────────────────────

async function loadEngagements() {
  setLoading("engagements-loading", true);
  let engagements;
  try {
    engagements = await api("/api/engagements");
  } catch (e) {
    showToast(`Failed to load engagements: ${e.message}`, "error");
    setLoading("engagements-loading", false);
    return;
  }
  setLoading("engagements-loading", false);
  activeList.innerHTML = "";
  pastList.innerHTML = "";
  const active = engagements.filter(e => e.status === "active");
  for (const eng of engagements) {
    const li = document.createElement("li");
    li.dataset.id = eng.id;
    if (eng.id === state.engagementId) li.classList.add("selected");

    const label = document.createElement("span");
    label.className = "finding-label";
    label.textContent = `${eng.name} (${eng.target})`;
    label.addEventListener("click", () => selectEngagement(eng));
    li.appendChild(label);

    const actions = document.createElement("span");
    actions.className = "finding-actions";

    const editBtn = document.createElement("button");
    editBtn.className = "mini";
    editBtn.textContent = "edit";
    editBtn.title = "Rename / change target / scope";
    editBtn.addEventListener("click", (ev) => { ev.stopPropagation(); editEngagement(eng); });

    const delBtn = document.createElement("button");
    delBtn.className = "mini danger";
    delBtn.textContent = "del";
    delBtn.title = "Delete this engagement";
    delBtn.addEventListener("click", (ev) => { ev.stopPropagation(); deleteEngagement(eng); });

    actions.appendChild(editBtn);
    actions.appendChild(delBtn);
    li.appendChild(actions);
    (eng.status === "active" ? activeList : pastList).appendChild(li);
  }
  if (!state.engagementId && active.length > 0) {
    await selectEngagement(active[0]);
  }
}

async function editEngagement(eng) {
  const vals = await showPrompt("Edit Engagement", [
    { key: "name", label: "Engagement name", value: eng.name, required: true, placeholder: eng.name },
    { key: "target", label: "Target", value: eng.target, required: true, placeholder: eng.target },
    { key: "scope", label: "Scope", value: eng.scope || "", placeholder: eng.scope || "" },
  ]);
  if (!vals) return;
  const body = {};
  if (vals.name.trim() && vals.name.trim() !== eng.name) body.name = vals.name.trim();
  if (vals.target.trim() && vals.target.trim() !== eng.target) body.target = vals.target.trim();
  if (vals.scope !== (eng.scope || "")) body.scope = vals.scope;
  if (Object.keys(body).length === 0) return;
  try {
    const updated = await api(`/api/engagements/${eng.id}`, { method: "PATCH", body: JSON.stringify(body) });
    await loadEngagements();
    if (state.engagementId === eng.id) {
      state.target = updated.target || "";
      engagementLabel.textContent = `${updated.name} — ${updated.target}`;
    }
    showToast("Engagement updated", "success");
  } catch (e) {
    showToast(`Update failed: ${e.message}`, "error");
  }
}

async function deleteEngagement(eng) {
  const ok = await showConfirm("Delete Engagement", `Delete engagement <strong>"${eng.name}"</strong> (${eng.target})?<br><br>This removes its findings and chat/session history.`);
  if (!ok) return;
  try {
    await api(`/api/engagements/${eng.id}`, { method: "DELETE" });
    showToast("Engagement deleted", "info");
  } catch (e) {
    showToast(`Delete failed: ${e.message}`, "error");
    return;
  }
  if (state.engagementId === eng.id) {
    if (state.socket) state.socket.close();
    state.engagementId = null;
    state.target = "";
    engagementLabel.textContent = "no engagement selected";
    chatLog.innerHTML = "";
    findingsList.innerHTML = "";
    reportsList.innerHTML = "";
    currentAgentLine = null;
    setPhase("enumeration");
    updateButtonStates(false);
  }
  await loadEngagements();
}

async function selectEngagement(eng) {
  state.engagementId = eng.id;
  state.target = eng.target || "";
  engagementLabel.textContent = `${eng.name} — ${eng.target}`;
  setPhase(eng.phase || "enumeration");
  updateButtonStates(true);
  document.querySelectorAll(".engagement-list li").forEach((li) => {
    li.classList.toggle("selected", li.dataset.id === eng.id);
  });
  chatLog.innerHTML = "";
  currentAgentLine = null;
  await loadChatHistory(eng.id);
  connectSocket();
  await loadFindings(eng.id);
  await loadReports(eng.id);
}

async function loadChatHistory(engagementId) {
  try {
    const events = await api(`/api/engagements/${engagementId}/chat`);
    for (const ev of events) renderEvent(ev);
  } catch (e) {
    console.error("Failed to load chat history", e);
  }
}

// ── Findings ─────────────────────────────────────────────────────────────────

async function loadFindings(engagementId) {
  setLoading("findings-loading", true);
  findingsList.innerHTML = "";
  try {
    const findings = await api(`/api/findings/engagement/${engagementId}`);
    for (const f of findings) { renderFinding(f); }
  } catch (e) {
    console.error("Failed to load findings", e);
  }
  setLoading("findings-loading", false);
}

function renderFinding(f) {
  const meta = f.metadata || {};
  const li = document.createElement("li");
  li.dataset.severity = meta.severity || "info";

  const label = document.createElement("span");
  label.className = "finding-label";
  label.textContent = `${meta.title || f.id} — ${(meta.severity || "?").toUpperCase()} · ${meta.vuln_type || "?"}`;
  label.addEventListener("click", () => showFindingDetail(f));
  li.appendChild(label);

  const actions = document.createElement("span");
  actions.className = "finding-actions";

  const editBtn = document.createElement("button");
  editBtn.className = "mini";
  editBtn.textContent = "edit";
  editBtn.addEventListener("click", (ev) => { ev.stopPropagation(); editFinding(f.id, meta); });

  const fpBtn = document.createElement("button");
  fpBtn.className = "mini danger";
  fpBtn.textContent = "FP";
  fpBtn.title = "Mark false positive (delete)";
  fpBtn.addEventListener("click", (ev) => { ev.stopPropagation(); deleteFinding(f.id); });

  actions.appendChild(editBtn);
  actions.appendChild(fpBtn);
  li.appendChild(actions);
  findingsList.appendChild(li);
}

function showFindingDetail(f) {
  const meta = f.metadata || {};
  const severity = meta.severity || "?";
  const severityColor = { critical: "#ff4444", high: "#ffb300", medium: "#00bfff", low: "#9b59b6", info: "#6b6b6b" }[severity] || "#ffffff";

  const html = `
    <div style="margin-bottom:10px"><strong style="color:${severityColor}">${severity.toUpperCase()}</strong> · ${meta.vuln_type || "?"}</div>
    <h3>Description</h3>
    <p>${(meta.description || "—")}</p>
    <h3>Reproduction</h3>
    <p>${(meta.reproduction_steps || "—")}</p>
    <h3>Technique Used</h3>
    <p>${(meta.technique_used || "—")}</p>
    <h3>Affected Component</h3>
    <p>${(meta.affected_component || "—")}</p>
    <h3>Business Impact</h3>
    <p>${(meta.business_impact || "—")}</p>
    <h3>Remediation</h3>
    <p>${(meta.remediation || "—")}</p>
    <h3>Target</h3>
    <p>${meta.target || "—"}</p>
    <h3>CVSS Score</h3>
    <p>${meta.cvss_score != null ? meta.cvss_score : "—"}</p>
  `;
  showModal(`Finding: ${meta.title || f.id}`, html, [
    { label: "Close", cls: "cancel-btn", value: () => true },
  ]);
}

async function editFinding(id, meta) {
  const vals = await showPrompt("Edit Finding", [
    {
      key: "severity", label: "Severity", required: true, placeholder: "medium",
      options: ["critical", "high", "medium", "low", "info"],
    },
    { key: "vuln_type", label: "Vuln type (must contain the OWASP/DVWA category to score)", value: meta.vuln_type || "", placeholder: "e.g. IDOR, XSS, SSRF" },
  ]);
  if (!vals) return;
  try {
    await api(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify({ severity: vals.severity, vuln_type: vals.vuln_type }) });
    await loadFindings(state.engagementId);
    showToast("Finding updated", "success");
  } catch (e) {
    showToast(`Update failed: ${e.message}`, "error");
  }
}

async function deleteFinding(id) {
  const ok = await showConfirm("Delete Finding", "Delete this finding (mark false positive)?");
  if (!ok) return;
  try {
    await api(`/api/findings/${id}`, { method: "DELETE" });
    await loadFindings(state.engagementId);
    showToast("Finding deleted", "info");
  } catch (e) {
    showToast(`Delete failed: ${e.message}`, "error");
  }
}

async function saveDraftFinding(draft) {
  try {
    await api("/api/findings", { method: "POST", body: JSON.stringify(draft) });
    await loadFindings(state.engagementId);
    showToast("Finding saved", "success");
  } catch (e) {
    showToast(`Save failed: ${e.message}`, "error");
  }
}

async function exportTrainingData() {
  const fmt = document.getElementById("train-format").value;
  try {
    const res = await api(`/api/training/export?format=${fmt}`);
    const count = res.count || 0;
    if (!count) { showToast("No training data to export yet.", "info"); return; }
    const jsonl = (res.examples || []).map(ex => JSON.stringify(ex)).join("\n");
    const blob = new Blob([jsonl], { type: "application/jsonl" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `thaghrawy_training_${fmt}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
    const src = res.sources || {};
    showToast(`Exported ${count} example(s) [${fmt}] (${src.findings||0} findings, ${src.techniques||0} techniques, ${src.decisions||0} decisions)`, "success");
  } catch (e) {
    showToast(`Export failed: ${e.message}`, "error");
  }
}

async function promoteResult(tool, output) {
  try {
    const res = await api("/api/findings/promote", {
      method: "POST",
      body: JSON.stringify({ tool, result: output, engagement_id: state.engagementId, target: state.target }),
    });
    const drafts = res.drafts || [];
    if (!drafts.length) {
      showToast(`No findings derivable from ${tool} output.`, "info");
      return;
    }
    const ok = await showConfirm("Promote Findings", `Promote ${drafts.length} finding(s) from <strong>${tool}</strong>?`);
    if (!ok) return;
    for (const d of drafts) {
      await api("/api/findings", { method: "POST", body: JSON.stringify(d) });
    }
    await loadFindings(state.engagementId);
    showToast(`${drafts.length} finding(s) promoted`, "success");
  } catch (e) {
    showToast(`Promote failed: ${e.message}`, "error");
  }
}

// ── Reports ──────────────────────────────────────────────────────────────────

async function loadReports(engagementId) {
  setLoading("reports-loading", true);
  reportsList.innerHTML = "";
  try {
    const reports = await api(`/api/engagements/${engagementId}/reports`);
    for (const r of reports) {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = `/api/reports/${r.filename}`;
      link.target = "_blank";
      link.textContent = `${r.type.toUpperCase()} (${r.format})`;
      li.appendChild(link);
      reportsList.appendChild(li);
    }
  } catch (e) {
    console.error("Failed to load reports", e);
  }
  setLoading("reports-loading", false);
}

// ── Tool-call approval (pending) ─────────────────────────────────────────────

function appendPendingToolCall(msg) {
  const line = appendLine(`tool-call pending${msg.dangerous ? " dangerous" : ""}`, "APPROVE?", "");
  const desc = document.createElement("span");
  desc.textContent = `${msg.dangerous ? "\u26A0 " : ""}${msg.tool} ${JSON.stringify(msg.arguments || {})}`;
  line.appendChild(desc);

  const controls = document.createElement("span");
  controls.className = "approval-controls";

  const mk = (label, cls, handler) => {
    const b = document.createElement("button");
    b.className = `mini ${cls}`;
    b.textContent = label;
    b.addEventListener("click", () => { handler(); controls.remove(); desc.classList.add("resolved"); });
    return b;
  };

  controls.appendChild(mk("approve", "ok", () => sendControl({ type: "approve", id: msg.id })));
  controls.appendChild(mk("reject", "danger", () => sendControl({ type: "reject", id: msg.id })));
  controls.appendChild(mk("edit", "", () => {
    const raw = prompt("Edit arguments (JSON):", JSON.stringify(msg.arguments || {}));
    if (raw === null) { controls.remove(); return; }
    let parsed;
    try { parsed = JSON.parse(raw); } catch { showToast("Invalid JSON", "error"); return; }
    sendControl({ type: "edit", id: msg.id, arguments: parsed });
  }));

  line.appendChild(controls);
}

// ── Render protocol events ───────────────────────────────────────────────────

let currentAgentLine = null;

function renderEvent(msg) {
  switch (msg.type) {
    case "user":
      appendLine("user", "YOU", msg.text || "");
      break;
    case "agent_message":
      appendLine("agent", "AGENT", typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content));
      break;
    case "memory_hit": {
      const meta = (msg.data && msg.data.metadata) || {};
      appendLine("memory", "MEMORY", `${meta.title || meta.name || msg.data.id} (similarity=${(msg.data.similarity ?? 0).toFixed(2)})`);
      break;
    }
    case "tool_call":
      appendLine("tool-call", "TOOL", `${msg.tool} ${JSON.stringify(msg.command || msg.arguments || {})}`);
      break;
    case "tool_call_pending":
      appendPendingToolCall(msg);
      break;
    case "tool_edited":
      appendLine("tool-call", "EDITED", `${msg.tool} ${JSON.stringify(msg.arguments || {})}`);
      break;
    case "tool_rejected":
      appendLine("memory", "REJECTED", `${msg.tool} declined \u2014 agent will re-plan.`);
      break;
    case "tool_result": {
      const outText = typeof msg.output === "string" ? msg.output : JSON.stringify(msg.output);
      const line = appendLine("tool-result", msg.source === "human" ? "OUT(you)" : "OUT", outText);
      if (msg.output != null) {
        const b = document.createElement("button");
        b.className = "mini promote";
        b.textContent = "\u2192finding";
        b.addEventListener("click", () => promoteResult(msg.tool, msg.output));
        line.appendChild(document.createTextNode(" "));
        line.appendChild(b);
      }
      break;
    }
    case "step":
      appendLine("dim", `STEP ${msg.count}`, msg.tool);
      break;
    case "token":
      if (!currentAgentLine) currentAgentLine = appendStreamingAgentLine();
      currentAgentLine.appendChild(document.createTextNode(msg.content));
      _scrollToBottom();
      break;
    case "assistant_suggestion":
      appendLine("memory", "SUGGEST", typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content));
      break;
    case "finding_draft": {
      const draft = msg.draft || {};
      const note = msg.note || "flag/secret detected";
      const titleText = draft.title || (draft.vuln_type || "finding");
      const line = appendLine("finding-draft", "DRAFT", `${note}: ${titleText}`);
      const controls = document.createElement("span");
      controls.className = "approval-controls";
      const okBtn = document.createElement("button");
      okBtn.className = "mini ok";
      okBtn.textContent = "save finding";
      okBtn.addEventListener("click", async () => {
        await saveDraftFinding(draft);
        okBtn.remove();
        dismissBtn.remove();
        line.classList.add("resolved");
      });
      const dismissBtn = document.createElement("button");
      dismissBtn.className = "mini";
      dismissBtn.textContent = "dismiss";
      dismissBtn.addEventListener("click", () => {
        okBtn.remove();
        dismissBtn.remove();
        line.classList.add("resolved");
      });
      controls.appendChild(okBtn);
      controls.appendChild(dismissBtn);
      line.appendChild(controls);
      break;
    }
    case "finding_saved":
      appendLine("memory", "FINDING_SAVED", (msg.finding && (msg.finding.title || msg.finding.vuln_type)) || "saved");
      loadFindings(state.engagementId);
      break;
    case "handoff":
      setPhase(msg.phase || "collaboration");
      appendLine("handoff", "HANDOFF", msg.message);
      loadFindings(state.engagementId);
      break;
    case "phase":
      setPhase(msg.phase);
      break;
    case "stopped":
      appendLine("error", "STOPPED", "Turn halted.");
      currentAgentLine = null;
      break;
    case "report_ready":
      appendLine("memory", "REPORTS", "Reports generated.");
      loadReports(state.engagementId);
      break;
    case "help":
      appendLine("memory", "HELP", "");
      (msg.commands || []).forEach((c) => appendLine("dim", "", c));
      break;
    case "tools": {
      appendLine("memory", "TOOLS", "click a name to fill the Run-tool form:");
      (msg.tools || []).forEach((t) => {
        const line = appendLine("dim", "", "");
        const btn = document.createElement("button");
        btn.className = "mini";
        btn.textContent = t.name;
        btn.title = "Fill the Run-tool form with this tool";
        btn.addEventListener("click", () => {
          document.getElementById("run-tool-form").classList.remove("hidden");
          document.getElementById("run-tool-name").value = t.name;
          document.getElementById("run-tool-args").focus();
        });
        line.appendChild(btn);
        line.appendChild(document.createTextNode(` ${t.dangerous ? "(dangerous) " : ""}\u2014 ${t.description}`));
      });
      break;
    }
    case "compacted":
      chatLog.innerHTML = "";
      currentAgentLine = null;
      appendLine("memory", "COMPACTED", "session context summarized:");
      String(msg.summary || "").split("\n").forEach((ln) => appendLine("dim", "", ln));
      break;
    case "info":
      appendLine("dim", "INFO", msg.message);
      break;
    case "error":
      appendLine("error", "ERROR", msg.message);
      break;
    case "done":
      currentAgentLine = null;
      break;
  }
}

// ── WebSocket ────────────────────────────────────────────────────────────────

function connectSocket() {
  if (state.socket) {
    state.socket.onclose = null;
    state.socket.close();
    state.socket = null;
  }
  if (!state.engagementId) return;
  if (state.socketRetryTimer) {
    clearTimeout(state.socketRetryTimer);
    state.socketRetryTimer = null;
  }

  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/chat?engagement_id=${state.engagementId}`);
  state.socket = socket;

  socket.onopen = () => {
    state.socketRetryCount = 0;
    connStatus.textContent = "Chat: CONNECTED";
    connStatus.classList.remove("conn-disconnected");
    connStatus.classList.add("conn-connected");
  };

  socket.onclose = (ev) => {
    connStatus.textContent = "Chat: DISCONNECTED";
    connStatus.classList.remove("conn-connected");
    connStatus.classList.add("conn-disconnected");
    state.socket = null;
    if (!state.engagementId) return;
    const delay = Math.min(1000 * Math.pow(2, state.socketRetryCount), 30000);
    state.socketRetryCount++;
    state.socketRetryTimer = setTimeout(connectSocket, delay);
  };

  socket.onerror = () => {};

  currentAgentLine = null;
  socket.onmessage = (event) => renderEvent(JSON.parse(event.data));
}

// ── Input events ─────────────────────────────────────────────────────────────

chatInput.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text || !state.socket || state.socket.readyState !== WebSocket.OPEN) return;
  appendLine("user", "YOU", text);
  state.socket.send(text);
  chatInput.value = "";
});

document.getElementById("enumerate-btn").addEventListener("click", () => {
  if (!state.engagementId) { showToast("Select an engagement first.", "info"); return; }
  appendLine("user", "YOU", "/enumerate");
  sendControl({ type: "enumerate" });
});

document.getElementById("stop-btn").addEventListener("click", () => sendControl({ type: "stop" }));
document.getElementById("tools-btn").addEventListener("click", () => sendControl({ type: "list_tools" }));
document.getElementById("help-btn").addEventListener("click", () => sendControl({ type: "help" }));

document.getElementById("compact-btn").addEventListener("click", () => {
  if (!state.engagementId) { showToast("Select an engagement first.", "info"); return; }
  sendControl({ type: "compact" });
});

function sendInterrupt() {
  const input = document.getElementById("interrupt-text");
  const text = input.value.trim();
  if (!text) return;
  appendLine("user", "INTERRUPT", text);
  sendControl({ type: "interrupt", text });
  input.value = "";
  document.getElementById("interrupt-form").classList.add("hidden");
}

document.getElementById("interrupt-btn").addEventListener("click", () => {
  const form = document.getElementById("interrupt-form");
  form.classList.toggle("hidden");
  if (!form.classList.contains("hidden")) document.getElementById("interrupt-text").focus();
});
document.getElementById("interrupt-go").addEventListener("click", sendInterrupt);
document.getElementById("interrupt-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendInterrupt();
});

// Guide overlay
const guideOverlay = document.getElementById("guide-overlay");
document.getElementById("guide-btn").addEventListener("click", () => guideOverlay.classList.remove("hidden"));
document.getElementById("guide-close").addEventListener("click", () => guideOverlay.classList.add("hidden"));
guideOverlay.addEventListener("click", (e) => {
  if (e.target === guideOverlay) guideOverlay.classList.add("hidden");
});

document.getElementById("report-btn").addEventListener("click", () => {
  if (!state.engagementId) { showToast("Select an engagement first.", "info"); return; }
  appendLine("user", "YOU", "/report");
  sendControl({ type: "report" });
});

document.getElementById("run-tool-btn").addEventListener("click", () => {
  document.getElementById("run-tool-form").classList.toggle("hidden");
});

document.getElementById("run-tool-go").addEventListener("click", () => {
  const tool = document.getElementById("run-tool-name").value.trim();
  const argsRaw = document.getElementById("run-tool-args").value.trim() || "{}";
  if (!tool) return;
  let args;
  try { args = JSON.parse(argsRaw); } catch { showToast("Invalid JSON args", "error"); return; }
  appendLine("user", "YOU", `/run ${tool} ${argsRaw}`);
  sendControl({ type: "run_tool", tool, arguments: args });
  document.getElementById("run-tool-form").classList.add("hidden");
});

document.getElementById("new-engagement-btn").addEventListener("click", async () => {
  const name = document.getElementById("new-engagement-name").value.trim();
  const target = document.getElementById("new-engagement-target").value.trim();
  const analysis_mode = document.getElementById("new-engagement-mode").value;
  if (!name || !target) {
    showToast("Name and target are required.", "error");
    return;
  }
  try {
    const eng = await api("/api/engagements", { method: "POST", body: JSON.stringify({ name, target, analysis_mode }) });
    document.getElementById("new-engagement-name").value = "";
    document.getElementById("new-engagement-target").value = "";
    await loadEngagements();
    await selectEngagement(eng);
    showToast(`Engagement "${eng.name}" created`, "success");
  } catch (e) {
    showToast(`Create failed: ${e.message}`, "error");
  }
});

document.getElementById("add-finding-btn").addEventListener("click", async () => {
  if (!state.engagementId) { showToast("Select an engagement first.", "info"); return; }
  const vals = await showPrompt("Add Finding", [
    { key: "title", label: "Finding title", required: true, placeholder: "e.g. SQL Injection in login" },
    { key: "severity", label: "Severity", required: true, placeholder: "medium", options: ["critical", "high", "medium", "low", "info"] },
    { key: "vuln_type", label: "Vuln type", required: true, placeholder: "e.g. IDOR, XSS, SSRF" },
    { key: "description", label: "Description", placeholder: "Optional description" },
  ]);
  if (!vals) return;
  try {
    await api("/api/findings", {
      method: "POST",
      body: JSON.stringify({
        id: crypto.randomUUID(),
        title: vals.title,
        severity: vals.severity,
        vuln_type: vals.vuln_type,
        description: vals.description || "",
        reproduction_steps: "",
        technique_used: "",
        target: state.target || "",
        engagement_id: state.engagementId,
        date: new Date().toISOString().slice(0, 10),
        tags: [],
      }),
    });
    await loadFindings(state.engagementId);
    showToast("Finding added", "success");
  } catch (e) {
    showToast(`Add finding failed: ${e.message}`, "error");
  }
});

document.getElementById("export-training-btn").addEventListener("click", exportTrainingData);

document.getElementById("generate-reports-btn").addEventListener("click", async () => {
  if (!state.engagementId) { showToast("Select an engagement first.", "info"); return; }
  const btn = document.getElementById("generate-reports-btn");
  btn.disabled = true;
  btn.textContent = "[...] Generating";
  try {
    await api(`/api/engagements/${state.engagementId}/reports`, { method: "POST" });
    await loadReports(state.engagementId);
    showToast("Reports generated", "success");
  } catch (e) {
    showToast(`Report generation failed: ${e.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "[+] Generate Reports";
  }
});

// ── Keyboard shortcuts ──────────────────────────────────────────────────────

document.addEventListener("keydown", (e) => {
  // Escape closes modal or toast
  if (e.key === "Escape") {
    const modal = document.getElementById("modal-overlay");
    if (!modal.classList.contains("hidden")) {
      closeModal();
      return;
    }
  }
  // Ctrl+` focuses chat input
  if (e.ctrlKey && e.key === "`") {
    e.preventDefault();
    chatInput.focus();
  }
  // Ctrl+Enter sends chat
  if (e.ctrlKey && e.key === "Enter") {
    e.preventDefault();
    const text = chatInput.value.trim();
    if (!text || !state.socket || state.socket.readyState !== WebSocket.OPEN) return;
    appendLine("user", "YOU", text);
    state.socket.send(text);
    chatInput.value = "";
  }
});

// ── Modal close on backdrop click ────────────────────────────────────────────

document.getElementById("modal-overlay").addEventListener("click", (e) => {
  if (e.target === document.getElementById("modal-overlay") && !_modalResolve) {
    closeModal();
  }
});

// ── LLM status ───────────────────────────────────────────────────────────────

async function checkLlmStatus() {
  const el = document.getElementById("llm-status");
  if (!el) return;
  try {
    const s = await api("/api/lm-studio/status");
    if (s.lm_studio) {
      el.textContent = s.loaded ? `LLM: ${s.model} \u2713` : `LLM: ${s.model} (not loaded)`;
      el.className = `conn-status ${s.loaded ? "conn-connected" : "conn-disconnected"}`;
    } else {
      el.textContent = `LLM: ${s.provider}`;
      el.className = "conn-status conn-connected";
    }
  } catch {
    el.textContent = "LLM: unreachable";
    el.className = "conn-status conn-disconnected";
  }
}

// ── Init ─────────────────────────────────────────────────────────────────────

updateButtonStates(false);
checkLlmStatus();
loadEngagements();
