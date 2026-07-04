import { describe, expect, it } from "vitest";
import { loadApp, click, mkFetch } from "./helpers/dom.js";

describe("new-engagement-btn", () => {
  it("requires both name and target", async () => {
    const { document, fetchMock } = await loadApp();
    const before = fetchMock.mock.calls.length;
    click(document.getElementById("new-engagement-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/name and target are required/i);
    expect(fetchMock.mock.calls.length).toBe(before);
  });

  it("POSTs the new engagement, clears the inputs, and selects it", async () => {
    const created = { id: "e9", name: "acme", target: "acme.com", status: "active", phase: "enumeration" };
    const fetchImpl = mkFetch([
      { test: (url, o) => url === "/api/engagements" && o.method === "POST", body: created },
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [created] },
    ]);
    const { document } = await loadApp({ fetchImpl });

    document.getElementById("new-engagement-name").value = "acme";
    document.getElementById("new-engagement-target").value = "acme.com";
    click(document.getElementById("new-engagement-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    expect(document.getElementById("new-engagement-name").value).toBe("");
    expect(document.getElementById("new-engagement-target").value).toBe("");
    expect(document.getElementById("engagement-label").textContent).toBe("acme — acme.com");
    expect(document.querySelector(".toast").textContent).toMatch(/created/i);
  });

  it("shows a toast when creation fails", async () => {
    const fetchImpl = mkFetch([
      { test: (url, o) => url === "/api/engagements" && o.method === "POST", status: 400, body: { detail: "duplicate" } },
    ]);
    const { document } = await loadApp({ fetchImpl });
    document.getElementById("new-engagement-name").value = "acme";
    document.getElementById("new-engagement-target").value = "acme.com";
    click(document.getElementById("new-engagement-btn"));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.querySelector(".toast").textContent).toMatch(/create failed/i);
  });
});

describe("engagement list row buttons", () => {
  const eng = { id: "e1", name: "acme", target: "acme.com", status: "active", phase: "enumeration" };

  it("clicking a label selects that engagement", async () => {
    // loadEngagements() auto-selects the first active engagement on load, so
    // click the *second* one to prove the label's own click handler (not
    // just the auto-select-on-load path) drives selection.
    const eng2 = { id: "e2", name: "beta", target: "beta.com", status: "active", phase: "enumeration" };
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng, eng2] },
    ]);
    const { document } = await loadApp({ fetchImpl });
    click(document.querySelector('li[data-id="e2"] .finding-label'));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.getElementById("engagement-label").textContent).toBe("beta — beta.com");
    expect(document.querySelector('li[data-id="e2"]').classList.contains("selected")).toBe(true);
  });

  it("edit button opens a prompt pre-filled with the engagement's fields, and PATCHes on OK", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/engagements/e1" && o.method === "PATCH", body: { ...eng, name: "acme-2" } },
    ]);
    const { document } = await loadApp({ fetchImpl });

    click(document.querySelector('li[data-id="e1"] button.mini:not(.danger)'));
    expect(document.getElementById("modal-title").textContent).toBe("Edit Engagement");
    const nameInput = document.querySelectorAll("#modal-body input")[0];
    expect(nameInput.value).toBe("acme");
    nameInput.value = "acme-2";
    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const patchCall = fetchImpl.mock.calls.find(([url, o]) => url === "/api/engagements/e1" && o?.method === "PATCH");
    expect(patchCall).toBeTruthy();
    expect(JSON.parse(patchCall[1].body)).toEqual({ name: "acme-2" });
  });

  it("edit button does nothing further when cancelled", async () => {
    const fetchImpl = mkFetch([{ test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] }]);
    const { document } = await loadApp({ fetchImpl });
    const callsBefore = fetchImpl.mock.calls.length;
    click(document.querySelector('li[data-id="e1"] button.mini:not(.danger)'));
    click(document.querySelector("#modal-actions .cancel-btn"));
    await new Promise((r) => setTimeout(r, 0));
    const patchCall = fetchImpl.mock.calls
      .slice(callsBefore)
      .find(([url, o]) => o?.method === "PATCH");
    expect(patchCall).toBeUndefined();
  });

  it("del button shows a confirm naming the engagement, and DELETEs on confirm", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/engagements/e1" && o.method === "DELETE", body: { status: "deleted", findings_removed: 0 } },
    ]);
    const { document } = await loadApp({ fetchImpl });

    click(document.querySelector('li[data-id="e1"] button.mini.danger'));
    expect(document.getElementById("modal-title").textContent).toBe("Delete Engagement");
    expect(document.getElementById("modal-body").textContent).toContain("acme");

    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const del = fetchImpl.mock.calls.find(([url, o]) => url === "/api/engagements/e1" && o?.method === "DELETE");
    expect(del).toBeTruthy();
    expect(document.querySelector(".toast").textContent).toMatch(/deleted/i);
  });

  it("del button does NOT delete when the confirm is cancelled", async () => {
    const fetchImpl = mkFetch([{ test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] }]);
    const { document } = await loadApp({ fetchImpl });

    click(document.querySelector('li[data-id="e1"] button.mini.danger'));
    click(document.querySelector("#modal-actions .cancel-btn"));
    await new Promise((r) => setTimeout(r, 0));

    const del = fetchImpl.mock.calls.find(([, o]) => o?.method === "DELETE");
    expect(del).toBeUndefined();
    // and the row is still there
    expect(document.querySelector('li[data-id="e1"]')).not.toBeNull();
  });

  it("clicking edit/del does not also trigger the row's select handler", async () => {
    const fetchImpl = mkFetch([{ test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] }]);
    const { document } = await loadApp({ fetchImpl });
    document.getElementById("engagement-label").textContent = "sentinel";
    click(document.querySelector('li[data-id="e1"] button.mini.danger'));
    click(document.querySelector("#modal-actions .cancel-btn"));
    await new Promise((r) => setTimeout(r, 0));
    // selectEngagement() would have overwritten this label; it shouldn't fire.
    expect(document.getElementById("engagement-label").textContent).toBe("sentinel");
  });
});
