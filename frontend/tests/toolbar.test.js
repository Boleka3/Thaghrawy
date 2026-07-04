import { beforeEach, describe, expect, it } from "vitest";
import { loadApp, click, MockWebSocket } from "./helpers/dom.js";

/** Load the app with one active engagement pre-selected and its socket open,
 * so socket-gated buttons (enumerate/stop/tools/help/compact/report) are live. */
async function loadWithLiveEngagement() {
  const engagement = { id: "e1", name: "acme", target: "acme.com", status: "active", phase: "enumeration" };
  const ctx = await loadApp({ engagements: [engagement] });
  const socket = MockWebSocket.instances[MockWebSocket.instances.length - 1];
  socket.open();
  await new Promise((r) => setTimeout(r, 0));
  return { ...ctx, socket, engagement };
}

describe("guide overlay", () => {
  it("guide-btn opens it, guide-close and backdrop click both close it", async () => {
    const { document } = await loadApp();
    const overlay = document.getElementById("guide-overlay");

    click(document.getElementById("guide-btn"));
    expect(overlay.classList.contains("hidden")).toBe(false);

    click(document.getElementById("guide-close"));
    expect(overlay.classList.contains("hidden")).toBe(true);

    click(document.getElementById("guide-btn"));
    expect(overlay.classList.contains("hidden")).toBe(false);
    click(overlay); // click the backdrop itself, not a child
    expect(overlay.classList.contains("hidden")).toBe(true);
  });

  it("does not close when clicking inside the overlay card", async () => {
    const { document } = await loadApp();
    const overlay = document.getElementById("guide-overlay");
    click(document.getElementById("guide-btn"));
    click(overlay.querySelector(".overlay-card h2"));
    expect(overlay.classList.contains("hidden")).toBe(false);
  });
});

describe("engagement-gated toolbar buttons with no engagement selected", () => {
  it("enumerate-btn shows a toast instead of sending control", async () => {
    const { document } = await loadApp();
    click(document.getElementById("enumerate-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/select an engagement first/i);
  });

  it("compact-btn shows a toast instead of sending control", async () => {
    const { document } = await loadApp();
    click(document.getElementById("compact-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/select an engagement first/i);
  });

  it("report-btn shows a toast instead of sending control", async () => {
    const { document } = await loadApp();
    click(document.getElementById("report-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/select an engagement first/i);
  });

  it("stop/tools/help are silent no-ops (no socket to send on)", async () => {
    const { document } = await loadApp();
    click(document.getElementById("stop-btn"));
    click(document.getElementById("tools-btn"));
    click(document.getElementById("help-btn"));
    expect(document.querySelectorAll(".toast").length).toBe(0);
  });
});

describe("engagement-gated toolbar buttons with a live engagement", () => {
  it("enumerate-btn echoes '/enumerate' and sends the enumerate control", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("enumerate-btn"));
    expect(document.querySelector(".chat-line.user").textContent).toContain("/enumerate");
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "enumerate" });
  });

  it("stop-btn sends a stop control", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("stop-btn"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "stop" });
  });

  it("tools-btn sends list_tools", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("tools-btn"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "list_tools" });
  });

  it("help-btn sends help", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("help-btn"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "help" });
  });

  it("compact-btn sends compact", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("compact-btn"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "compact" });
  });

  it("report-btn echoes '/report' and sends the report control", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    click(document.getElementById("report-btn"));
    expect(document.querySelector(".chat-line.user").textContent).toContain("/report");
    expect(JSON.parse(socket.sent.at(-1))).toEqual({ type: "report" });
  });
});

describe("run-tool form", () => {
  it("run-tool-btn toggles the form open and closed", async () => {
    const { document } = await loadApp();
    const form = document.getElementById("run-tool-form");
    expect(form.classList.contains("hidden")).toBe(true);
    click(document.getElementById("run-tool-btn"));
    expect(form.classList.contains("hidden")).toBe(false);
    click(document.getElementById("run-tool-btn"));
    expect(form.classList.contains("hidden")).toBe(true);
  });

  it("run-tool-go sends run_tool with parsed args and hides the form", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    document.getElementById("run-tool-form").classList.remove("hidden");
    document.getElementById("run-tool-name").value = "nuclei_scan";
    document.getElementById("run-tool-args").value = '{"target":"acme.com"}';
    click(document.getElementById("run-tool-go"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({
      type: "run_tool",
      tool: "nuclei_scan",
      arguments: { target: "acme.com" },
    });
    expect(document.getElementById("run-tool-form").classList.contains("hidden")).toBe(true);
  });

  it("run-tool-go rejects invalid JSON args without sending anything", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    document.getElementById("run-tool-name").value = "nuclei_scan";
    document.getElementById("run-tool-args").value = "{not json";
    const before = socket.sent.length;
    click(document.getElementById("run-tool-go"));
    expect(socket.sent.length).toBe(before);
    expect(document.querySelector(".toast").textContent).toMatch(/invalid json/i);
  });

  it("run-tool-go does nothing when the tool name is blank", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    document.getElementById("run-tool-name").value = "   ";
    const before = socket.sent.length;
    click(document.getElementById("run-tool-go"));
    expect(socket.sent.length).toBe(before);
  });
});

describe("interrupt form", () => {
  it("interrupt-btn toggles the form open and focuses the input", async () => {
    const { document } = await loadApp();
    const form = document.getElementById("interrupt-form");
    expect(form.classList.contains("hidden")).toBe(true);
    click(document.getElementById("interrupt-btn"));
    expect(form.classList.contains("hidden")).toBe(false);
    click(document.getElementById("interrupt-btn"));
    expect(form.classList.contains("hidden")).toBe(true);
  });

  it("interrupt-go sends the interrupt control, echoes the text, clears and hides the form", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    document.getElementById("interrupt-form").classList.remove("hidden");
    const input = document.getElementById("interrupt-text");
    input.value = "stop and pivot to the admin panel";
    click(document.getElementById("interrupt-go"));
    expect(JSON.parse(socket.sent.at(-1))).toEqual({
      type: "interrupt",
      text: "stop and pivot to the admin panel",
    });
    expect(document.querySelector(".chat-line").textContent).toContain("stop and pivot to the admin panel");
    expect(input.value).toBe("");
    expect(document.getElementById("interrupt-form").classList.contains("hidden")).toBe(true);
  });

  it("interrupt-go does nothing for blank input", async () => {
    const { document, socket } = await loadWithLiveEngagement();
    document.getElementById("interrupt-text").value = "   ";
    const before = socket.sent.length;
    click(document.getElementById("interrupt-go"));
    expect(socket.sent.length).toBe(before);
  });
});
