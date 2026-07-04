import { describe, expect, it } from "vitest";
import { loadApp, click, mkFetch, MockWebSocket } from "./helpers/dom.js";

const eng = { id: "e1", name: "acme", target: "acme.com", status: "active", phase: "enumeration" };

/** Load the app with one live (open-socket) engagement and return its socket. */
async function loadWithSocket(extraRoutes = []) {
  const fetchImpl = mkFetch([
    { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
    ...extraRoutes,
  ]);
  const ctx = await loadApp({ fetchImpl });
  const socket = MockWebSocket.instances.at(-1);
  socket.open();
  await new Promise((r) => setTimeout(r, 0));
  return { ...ctx, socket };
}

describe("tool_call_pending approval controls", () => {
  it("approve sends {type: approve, id} and removes the controls", async () => {
    const { document, socket } = await loadWithSocket();
    socket.emit({ type: "tool_call_pending", id: "t1", tool: "nuclei_scan", arguments: { target: "acme.com" } });
    const controls = document.querySelector(".approval-controls");
    expect(controls).not.toBeNull();
    click(controls.querySelector(".ok"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "approve", id: "t1" });
    expect(document.querySelector(".approval-controls")).toBeNull();
  });

  it("reject sends {type: reject, id} and removes the controls", async () => {
    const { document, socket } = await loadWithSocket();
    socket.emit({ type: "tool_call_pending", id: "t2", tool: "nuclei_scan", arguments: {} });
    click(document.querySelector(".approval-controls .danger"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "reject", id: "t2" });
    expect(document.querySelector(".approval-controls")).toBeNull();
  });

  it("edit prompts for JSON args and sends {type: edit, id, arguments}", async () => {
    const { document, window, socket } = await loadWithSocket();
    window.prompt = () => '{"target":"acme.com","port":443}';
    socket.emit({ type: "tool_call_pending", id: "t3", tool: "nuclei_scan", arguments: { target: "acme.com" } });
    const editBtn = [...document.querySelectorAll(".approval-controls button")].find((b) => b.textContent === "edit");
    click(editBtn);
    expect(JSON.parse(socket.sent.at(-1))).toEqual({
      type: "edit",
      id: "t3",
      arguments: { target: "acme.com", port: 443 },
    });
  });

  it("edit does nothing when the prompt is dismissed (null)", async () => {
    const { document, window, socket } = await loadWithSocket();
    window.prompt = () => null;
    socket.emit({ type: "tool_call_pending", id: "t4", tool: "nuclei_scan", arguments: {} });
    const before = socket.sent.length;
    const editBtn = [...document.querySelectorAll(".approval-controls button")].find((b) => b.textContent === "edit");
    click(editBtn);
    expect(socket.sent.length).toBe(before);
    // Dismissing removes the controls without resolving approve/reject either.
    expect(document.querySelector(".approval-controls")).toBeNull();
  });

  it("edit shows a toast and sends nothing for invalid JSON", async () => {
    const { document, window, socket } = await loadWithSocket();
    window.prompt = () => "{not json";
    socket.emit({ type: "tool_call_pending", id: "t5", tool: "nuclei_scan", arguments: {} });
    const before = socket.sent.length;
    const editBtn = [...document.querySelectorAll(".approval-controls button")].find((b) => b.textContent === "edit");
    click(editBtn);
    expect(socket.sent.length).toBe(before);
    expect(document.querySelector(".toast").textContent).toMatch(/invalid json/i);
  });
});

describe("finding_draft controls", () => {
  it("save finding POSTs the draft, reloads findings, and resolves the line", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/findings" && o.method === "POST", body: {} },
    ]);
    const ctx = await loadApp({ fetchImpl });
    const socket = MockWebSocket.instances.at(-1);
    socket.open();
    await new Promise((r) => setTimeout(r, 0));

    socket.emit({ type: "finding_draft", draft: { title: "Reflected XSS", vuln_type: "XSS" }, note: "secret detected" });
    const line = ctx.document.querySelector(".chat-line.finding-draft");
    expect(line).not.toBeNull();
    const saveBtn = [...line.querySelectorAll("button")].find((b) => b.textContent === "save finding");
    click(saveBtn);
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const post = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings" && o?.method === "POST");
    expect(post).toBeTruthy();
    expect(JSON.parse(post[1].body)).toEqual({ title: "Reflected XSS", vuln_type: "XSS" });
    expect(line.classList.contains("resolved")).toBe(true);
    expect(line.querySelector("button")).toBeNull();
  });

  it("dismiss removes the controls without saving anything", async () => {
    const { document, socket } = await loadWithSocket();
    socket.emit({ type: "finding_draft", draft: { title: "Reflected XSS" }, note: "secret detected" });
    const line = document.querySelector(".chat-line.finding-draft");
    const dismissBtn = [...line.querySelectorAll("button")].find((b) => b.textContent === "dismiss");
    click(dismissBtn);
    expect(line.classList.contains("resolved")).toBe(true);
    expect(line.querySelector("button")).toBeNull();
  });
});

describe("tool_result -> finding promote button", () => {
  it("clicking →finding promotes drafts after confirmation", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      {
        test: (url, o) => url === "/api/findings/promote" && o.method === "POST",
        body: { drafts: [{ title: "IDOR", vuln_type: "IDOR" }] },
      },
      { test: (url, o) => url === "/api/findings" && o.method === "POST", body: {} },
    ]);
    const ctx = await loadApp({ fetchImpl });
    const socket = MockWebSocket.instances.at(-1);
    socket.open();
    await new Promise((r) => setTimeout(r, 0));

    socket.emit({ type: "tool_result", tool: "sqlmap", output: "found IDOR at /api/user/1" });
    const promoteBtn = ctx.document.querySelector(".chat-line.tool-result .promote");
    expect(promoteBtn).not.toBeNull();
    click(promoteBtn);
    await new Promise((r) => setTimeout(r, 0));

    expect(ctx.document.getElementById("modal-title").textContent).toBe("Promote Findings");
    click(ctx.document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const post = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings" && o?.method === "POST");
    expect(post).toBeTruthy();
    expect(ctx.document.querySelector(".toast").textContent).toMatch(/1 finding\(s\) promoted/i);
  });

  it("declining the promote confirm does not POST any findings", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      {
        test: (url, o) => url === "/api/findings/promote" && o.method === "POST",
        body: { drafts: [{ title: "IDOR" }] },
      },
    ]);
    const ctx = await loadApp({ fetchImpl });
    const socket = MockWebSocket.instances.at(-1);
    socket.open();
    await new Promise((r) => setTimeout(r, 0));
    socket.emit({ type: "tool_result", tool: "sqlmap", output: "found IDOR" });
    click(ctx.document.querySelector(".promote"));
    await new Promise((r) => setTimeout(r, 0));
    click(ctx.document.querySelector("#modal-actions .cancel-btn"));
    await new Promise((r) => setTimeout(r, 0));
    const post = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings" && o?.method === "POST");
    expect(post).toBeUndefined();
  });
});

describe("tools list picker buttons", () => {
  it("clicking a tool name fills the run-tool form and shows it", async () => {
    const { document, socket } = await loadWithSocket();
    socket.emit({ type: "tools", tools: [{ name: "nuclei_scan", description: "runs nuclei", dangerous: false }] });
    const toolBtn = [...document.querySelectorAll(".chat-line button")].find((b) => b.textContent === "nuclei_scan");
    expect(toolBtn).not.toBeNull();
    click(toolBtn);
    expect(document.getElementById("run-tool-form").classList.contains("hidden")).toBe(false);
    expect(document.getElementById("run-tool-name").value).toBe("nuclei_scan");
  });
});

describe("scroll-lock-hint", () => {
  it("clicking it re-enables auto-scroll and hides itself", async () => {
    const { document } = await loadWithSocket();
    const hint = document.getElementById("scroll-lock-hint");
    hint.classList.remove("hidden"); // simulate having scrolled up already
    click(hint);
    expect(hint.classList.contains("hidden")).toBe(true);
  });
});
