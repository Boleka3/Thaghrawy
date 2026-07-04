import { describe, expect, it } from "vitest";
import { loadApp, mkFetch } from "./helpers/dom.js";

// The buttons that updateButtonStates(hasEngagement) toggles, per app.js.
const ENGAGEMENT_GATED_BUTTON_IDS = [
  "enumerate-btn",
  "stop-btn",
  "report-btn",
  "compact-btn",
  "interrupt-btn",
  "add-finding-btn",
  "generate-reports-btn",
];

describe("app boot", () => {
  it("fetches the engagement list and LLM status on load", async () => {
    const { fetchMock } = await loadApp();
    const urls = fetchMock.mock.calls.map((c) => c[0]);
    expect(urls).toContain("/api/engagements");
    expect(urls).toContain("/api/lm-studio/status");
  });

  it("disables every engagement-gated button when no engagement is selected", async () => {
    const { document } = await loadApp();
    for (const id of ENGAGEMENT_GATED_BUTTON_IDS) {
      expect(document.getElementById(id).disabled, `#${id} should start disabled`).toBe(true);
    }
  });

  it("shows the disconnected LLM status when the status endpoint is unreachable", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => url === "/api/lm-studio/status", status: 500, body: {} },
    ]);
    const { document } = await loadApp({ fetchImpl });
    expect(document.getElementById("llm-status").textContent).toBe("LLM: unreachable");
  });
});
