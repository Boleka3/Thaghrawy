const state = {
  engagementId: null,
  target: "",
  socket: null,
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
  chatLog.scrollTop = chatLog.scrollHeight;
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

// Send a structured control message over the socket.
function sendControl(obj) {
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    state.socket.send(JSON.stringify(obj));
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

async function loadEngagements() {
  const engagements = await api("/api/engagements");
  activeList.innerHTML = "";
  pastList.innerHTML = "";
  const active = engagements.filter(e => e.status === "active");
  for (const eng of engagements) {
    const li = document.createElement("li");
    li.textContent = `${eng.name} (${eng.target})`;
    li.dataset.id = eng.id;
    if (eng.id === state.engagementId) li.classList.add("selected");
    li.addEventListener("click", () => selectEngagement(eng));
    (eng.status === "active" ? activeList : pastList).appendChild(li);
  }
  if (!state.engagementId && active.length > 0) {
    await selectEngagement(active[0]);
  }
}

async function selectEngagement(eng) {
  state.engagementId = eng.id;
  state.target = eng.target || "";
  engagementLabel.textContent = `${eng.name} — ${eng.target}`;
  setPhase(eng.phase || "enumeration");
  document.querySelectorAll(".engagement-list li").forEach((li) => {
    li.classList.toggle("selected", li.dataset.id === eng.id);
  });
  connectSocket();
  await loadFindings(eng.id);
  await loadReports(eng.id);
}

async function loadFindings(engagementId) {
  findingsList.innerHTML = "";
  try {
    const findings = await api(`/api/findings/engagement/${engagementId}`);
    for (const f of findings) {
      renderFinding(f);
    }
  } catch (e) {
    console.error("Failed to load findings", e);
  }
}

function renderFinding(f) {
  const meta = f.metadata || {};
  const li = document.createElement("li");
  li.dataset.severity = meta.severity || "info";

  const label = document.createElement("span");
  label.className = "finding-label";
  label.textContent = `${meta.title || f.id} — ${(meta.severity || "?").toUpperCase()} · ${meta.vuln_type || "?"}`;
  li.appendChild(label);

  const actions = document.createElement("span");
  actions.className = "finding-actions";

  const editBtn = document.createElement("button");
  editBtn.className = "mini";
  editBtn.textContent = "edit";
  editBtn.addEventListener("click", (ev) => { ev.stopPropagation(); editFinding(f.id, meta); });

  const fpBtn = document.createElement("button");
  fpBtn.className = "mini danger";
  fpBtn.textContent = "FP✕";
  fpBtn.title = "Mark false positive (delete)";
  fpBtn.addEventListener("click", (ev) => { ev.stopPropagation(); deleteFinding(f.id); });

  actions.appendChild(editBtn);
  actions.appendChild(fpBtn);
  li.appendChild(actions);
  findingsList.appendChild(li);
}

async function editFinding(id, meta) {
  const severity = prompt("Severity (critical/high/medium/low/info):", meta.severity || "medium");
  if (severity === null) return;
  const vuln_type = prompt("Vuln type (must contain the OWASP/DVWA category to score):", meta.vuln_type || "");
  if (vuln_type === null) return;
  try {
    await api(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify({ severity, vuln_type }) });
    await loadFindings(state.engagementId);
  } catch (e) {
    alert(`Update failed: ${e.message}`);
  }
}

async function deleteFinding(id) {
  if (!confirm("Delete this finding (mark false positive)?")) return;
  try {
    await api(`/api/findings/${id}`, { method: "DELETE" });
    await loadFindings(state.engagementId);
  } catch (e) {
    alert(`Delete failed: ${e.message}`);
  }
}

// Turn a scanner tool_result into finding(s) the operator confirms.
async function promoteResult(tool, output) {
  try {
    const res = await api("/api/findings/promote", {
      method: "POST",
      body: JSON.stringify({ tool, result: output, engagement_id: state.engagementId, target: state.target }),
    });
    const drafts = res.drafts || [];
    if (!drafts.length) {
      alert(`No findings derivable from ${tool} output.`);
      return;
    }
    if (!confirm(`Promote ${drafts.length} finding(s) from ${tool}?`)) return;
    for (const d of drafts) {
      await api("/api/findings", { method: "POST", body: JSON.stringify(d) });
    }
    await loadFindings(state.engagementId);
  } catch (e) {
    alert(`Promote failed: ${e.message}`);
  }
}

async function loadReports(engagementId) {
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
}

// Render a pending tool call with Approve / Reject / Edit controls.
function appendPendingToolCall(msg) {
  const line = appendLine(`tool-call pending${msg.dangerous ? " dangerous" : ""}`, "APPROVE?", "");
  const desc = document.createElement("span");
  desc.textContent = `${msg.dangerous ? "⚠ " : ""}${msg.tool} ${JSON.stringify(msg.arguments || {})}`;
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
    try { parsed = JSON.parse(raw); } catch { alert("Invalid JSON"); return; }
    sendControl({ type: "edit", id: msg.id, arguments: parsed });
  }));

  line.appendChild(controls);
}

function connectSocket() {
  if (state.socket) state.socket.close();
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/chat?engagement_id=${state.engagementId}`);
  state.socket = socket;

  socket.onopen = () => {
    connStatus.textContent = "Chat: CONNECTED";
    connStatus.classList.remove("conn-disconnected");
    connStatus.classList.add("conn-connected");
  };
  socket.onclose = () => {
    connStatus.textContent = "Chat: DISCONNECTED";
    connStatus.classList.remove("conn-connected");
    connStatus.classList.add("conn-disconnected");
  };

  let currentAgentLine = null;

  socket.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    switch (msg.type) {
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
        appendLine("memory", "REJECTED", `${msg.tool} declined — agent will re-plan.`);
        break;
      case "tool_result": {
        const outText = typeof msg.output === "string" ? msg.output : JSON.stringify(msg.output);
        const line = appendLine("tool-result", msg.source === "human" ? "OUT(you)" : "OUT", outText);
        // Offer promotion to a finding; the backend derives drafts (or none) from
        // the raw output, which for scanner tools is a JSON string.
        if (msg.output != null) {
          const b = document.createElement("button");
          b.className = "mini promote";
          b.textContent = "→finding";
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
        chatLog.scrollTop = chatLog.scrollHeight;
        break;
      case "assistant_suggestion":
        appendLine("memory", "SUGGEST", typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content));
        break;
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
      case "tools":
        appendLine("memory", "TOOLS", "");
        (msg.tools || []).forEach((t) =>
          appendLine("dim", "", `${t.name}${t.dangerous ? " (dangerous)" : ""} — ${t.description}`)
        );
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
  };
}

chatInput.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const text = chatInput.value.trim();
  if (!text || !state.socket || state.socket.readyState !== WebSocket.OPEN) return;
  appendLine("user", "YOU", text);
  // Raw text: the backend parses plain chat, JSON, and /slash commands.
  state.socket.send(text);
  chatInput.value = "";
});

document.getElementById("enumerate-btn").addEventListener("click", () => {
  if (!state.engagementId) return alert("Select an engagement first.");
  appendLine("user", "YOU", "/enumerate");
  sendControl({ type: "enumerate" });
});

document.getElementById("stop-btn").addEventListener("click", () => sendControl({ type: "stop" }));
document.getElementById("tools-btn").addEventListener("click", () => sendControl({ type: "list_tools" }));
document.getElementById("help-btn").addEventListener("click", () => sendControl({ type: "help" }));

document.getElementById("report-btn").addEventListener("click", () => {
  if (!state.engagementId) return alert("Select an engagement first.");
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
  try { args = JSON.parse(argsRaw); } catch { return alert("Invalid JSON args"); }
  appendLine("user", "YOU", `/run ${tool} ${argsRaw}`);
  sendControl({ type: "run_tool", tool, arguments: args });
  document.getElementById("run-tool-form").classList.add("hidden");
});

document.getElementById("new-engagement-btn").addEventListener("click", async () => {
  const name = document.getElementById("new-engagement-name").value.trim();
  const target = document.getElementById("new-engagement-target").value.trim();
  const analysis_mode = document.getElementById("new-engagement-mode").value;
  if (!name || !target) return;
  const eng = await api("/api/engagements", { method: "POST", body: JSON.stringify({ name, target, analysis_mode }) });
  document.getElementById("new-engagement-name").value = "";
  document.getElementById("new-engagement-target").value = "";
  await loadEngagements();
  await selectEngagement(eng);
});

document.getElementById("add-finding-btn").addEventListener("click", async () => {
  if (!state.engagementId) {
    alert("Select an engagement first.");
    return;
  }
  const title = prompt("Finding title:");
  if (!title) return;
  const severity = prompt("Severity (critical/high/medium/low/info):", "medium");
  const vuln_type = prompt("Vuln type (e.g. IDOR, XSS, SSRF):", "other");
  const description = prompt("Description:", "");
  await api("/api/findings", {
    method: "POST",
    body: JSON.stringify({
      id: crypto.randomUUID(),
      title,
      severity,
      vuln_type,
      description: description || "",
      reproduction_steps: "",
      technique_used: "",
      target: state.target || "",
      engagement_id: state.engagementId,
      date: new Date().toISOString().slice(0, 10),
      tags: [],
    }),
  });
  await loadFindings(state.engagementId);
});

document.getElementById("generate-reports-btn").addEventListener("click", async () => {
  if (!state.engagementId) {
    alert("Select an engagement first.");
    return;
  }
  const btn = document.getElementById("generate-reports-btn");
  btn.disabled = true;
  btn.textContent = "[...] Generating";
  try {
    await api(`/api/engagements/${state.engagementId}/reports`, { method: "POST" });
    await loadReports(state.engagementId);
  } catch (e) {
    alert(`Report generation failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "[+] Generate Reports";
  }
});

async function checkLlmStatus() {
  const el = document.getElementById("llm-status");
  if (!el) return;
  try {
    const s = await api("/api/lm-studio/status");
    if (s.lm_studio) {
      el.textContent = s.loaded ? `LLM: ${s.model} ✓` : `LLM: ${s.model} (not loaded)`;
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

checkLlmStatus();
loadEngagements();
