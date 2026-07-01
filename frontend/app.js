const state = {
  engagementId: null,
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

function appendLine(cssClass, tag, text) {
  const line = document.createElement("div");
  line.className = `chat-line ${cssClass}`;
  if (tag) {
    const tagSpan = document.createElement("span");
    tagSpan.className = "tag";
    tagSpan.textContent = `[${tag}]`;
    line.appendChild(tagSpan);
  }
  line.appendChild(document.createTextNode(text));
  chatLog.appendChild(line);
  chatLog.scrollTop = chatLog.scrollHeight;
  return line;
}

function appendStreamingAgentLine() {
  const line = appendLine("agent", "AGENT", "");
  return line;
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
  engagementLabel.textContent = `${eng.name} — ${eng.target}`;
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
      const meta = f.metadata || {};
      const li = document.createElement("li");
      li.dataset.severity = meta.severity || "info";
      li.textContent = `${meta.title || f.id} — ${(meta.severity || "?").toUpperCase()}`;
      findingsList.appendChild(li);
    }
  } catch (e) {
    console.error("Failed to load findings", e);
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

function connectSocket() {
  if (state.socket) state.socket.close();
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws/chat?engagement_id=${state.engagementId}`);
  state.socket = socket;

  socket.onopen = () => {
    connStatus.textContent = "Chat: CONNECTED";
    connStatus.classList.remove("conn-disconnected");
    connStatus.classList.add("conn-connected");
    connStatus.classList.remove("conn-disconnected");
    connStatus.classList.add("conn-connected");
  };
  socket.onclose = () => {
    connStatus.textContent = "Chat: DISCONNECTED";
    connStatus.classList.remove("conn-connected");
    connStatus.classList.add("conn-disconnected");
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
      case "tool_result":
        appendLine("tool-result", "OUT", typeof msg.output === "string" ? msg.output : JSON.stringify(msg.output));
        break;
      case "token":
        if (!currentAgentLine) currentAgentLine = appendStreamingAgentLine();
        currentAgentLine.textContent += msg.content;
        chatLog.scrollTop = chatLog.scrollHeight;
        break;
      case "finding_saved":
        appendLine("memory", "FINDING_SAVED", JSON.stringify(msg.finding));
        loadFindings(state.engagementId);
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
  state.socket.send(text);
  chatInput.value = "";
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
      target: "",
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
