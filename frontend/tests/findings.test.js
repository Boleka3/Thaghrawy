import { describe, expect, it } from "vitest";
import { loadApp, click, mkFetch } from "./helpers/dom.js";

const eng = { id: "e1", name: "acme", target: "acme.com", status: "active", phase: "enumeration" };
const finding = {
  id: "f1",
  metadata: { title: "SQLi in login", severity: "high", vuln_type: "SQLi", description: "desc" },
};

describe("add-finding-btn", () => {
  it("shows a toast when no engagement is selected", async () => {
    const { document } = await loadApp(); // no engagements seeded -> nothing selected
    click(document.getElementById("add-finding-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/select an engagement first/i);
  });

  it("opens the Add Finding prompt and POSTs on OK", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/findings" && o.method === "POST", body: { id: "f9" } },
    ]);
    const { document } = await loadApp({ fetchImpl });

    click(document.getElementById("add-finding-btn"));
    expect(document.getElementById("modal-title").textContent).toBe("Add Finding");
    const inputs = document.querySelectorAll("#modal-body input");
    inputs[0].value = "SQLi in login"; // title
    const select = document.querySelector("#modal-body select");
    select.value = "high";
    document.querySelectorAll("#modal-body input")[1].value = "SQLi"; // vuln_type

    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const post = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings" && o?.method === "POST");
    expect(post).toBeTruthy();
    const body = JSON.parse(post[1].body);
    expect(body).toMatchObject({ title: "SQLi in login", severity: "high", vuln_type: "SQLi", engagement_id: "e1" });
    expect(document.querySelector(".toast").textContent).toMatch(/finding added/i);
  });

  it("required-field validation blocks submission when fields are blank", async () => {
    const fetchImpl = mkFetch([{ test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] }]);
    const { document } = await loadApp({ fetchImpl });
    const before = fetchImpl.mock.calls.length;
    click(document.getElementById("add-finding-btn"));
    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    expect(fetchImpl.mock.calls.length).toBe(before); // no POST fired
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false); // stayed open
  });
});

describe("finding row buttons", () => {
  function seedFindingsFetch() {
    return mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url) => url === "/api/findings/engagement/e1", body: [finding] },
    ]);
  }

  it("label click opens the finding-detail modal with its metadata", async () => {
    const { document } = await loadApp({ fetchImpl: seedFindingsFetch() });
    click(document.querySelector('#findings-list li .finding-label'));
    expect(document.getElementById("modal-title").textContent).toBe("Finding: SQLi in login");
    expect(document.getElementById("modal-body").textContent).toContain("desc");
    // Close button works
    click(document.querySelector("#modal-actions .cancel-btn"));
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(true);
  });

  it("edit button pre-fills severity/vuln_type and PATCHes on OK", async () => {
    const fetchImpl = seedFindingsFetch();
    const { document } = await loadApp({ fetchImpl });
    click(document.querySelector('#findings-list li button.mini:not(.danger)'));
    expect(document.getElementById("modal-title").textContent).toBe("Edit Finding");
    expect(document.querySelector("#modal-body select").value).toBe("high");
    expect(document.querySelector("#modal-body input").value).toBe("SQLi");

    document.querySelector("#modal-body select").value = "critical";
    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    const patch = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings/f1" && o?.method === "PATCH");
    expect(patch).toBeTruthy();
    expect(JSON.parse(patch[1].body)).toEqual({ severity: "critical", vuln_type: "SQLi" });
  });

  it("FP button confirms then DELETEs the finding", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url) => url === "/api/findings/engagement/e1", body: [finding] },
      { test: (url, o) => url === "/api/findings/f1" && o.method === "DELETE", body: {} },
    ]);
    const { document } = await loadApp({ fetchImpl });
    click(document.querySelector('#findings-list li button.mini.danger'));
    expect(document.getElementById("modal-title").textContent).toBe("Delete Finding");
    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    const del = fetchImpl.mock.calls.find(([url, o]) => url === "/api/findings/f1" && o?.method === "DELETE");
    expect(del).toBeTruthy();
  });

  it("FP button does not delete when cancelled", async () => {
    const fetchImpl = seedFindingsFetch();
    const { document } = await loadApp({ fetchImpl });
    click(document.querySelector('#findings-list li button.mini.danger'));
    click(document.querySelector("#modal-actions .cancel-btn"));
    await new Promise((r) => setTimeout(r, 0));
    const del = fetchImpl.mock.calls.find(([, o]) => o?.method === "DELETE");
    expect(del).toBeUndefined();
  });

  it("edit/FP clicks don't also open the finding-detail modal", async () => {
    const { document } = await loadApp({ fetchImpl: seedFindingsFetch() });
    click(document.querySelector('#findings-list li button.mini.danger'));
    expect(document.getElementById("modal-title").textContent).toBe("Delete Finding");
  });
});

describe("generate-reports-btn", () => {
  it("shows a toast when no engagement is selected", async () => {
    const { document } = await loadApp();
    click(document.getElementById("generate-reports-btn"));
    expect(document.querySelector(".toast").textContent).toMatch(/select an engagement first/i);
  });

  it("disables itself, POSTs, reloads reports, and re-enables on success", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/engagements/e1/reports" && o.method === "POST", body: {} },
      { test: (url, o) => url === "/api/engagements/e1/reports" && !o.method, body: [{ type: "technical", format: "pdf", filename: "r.pdf" }] },
    ]);
    const { document } = await loadApp({ fetchImpl });
    const btn = document.getElementById("generate-reports-btn");
    click(btn);
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(btn.disabled).toBe(false);
    expect(btn.textContent).toBe("[+] Generate Reports");
    expect(document.querySelector("#reports-list a").textContent).toBe("TECHNICAL (pdf)");
    expect(document.querySelector(".toast").textContent).toMatch(/reports generated/i);
  });

  it("re-enables itself and shows a toast on failure", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => /^\/api\/engagements(\?|$)/.test(url), body: [eng] },
      { test: (url, o) => url === "/api/engagements/e1/reports" && o.method === "POST", status: 500, body: {} },
    ]);
    const { document } = await loadApp({ fetchImpl });
    click(document.getElementById("generate-reports-btn"));
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.getElementById("generate-reports-btn").disabled).toBe(false);
    expect(document.querySelector(".toast").textContent).toMatch(/report generation failed/i);
  });
});

describe("export-training-btn", () => {
  it("shows an info toast when there is nothing to export", async () => {
    const fetchImpl = mkFetch([
      { test: (url) => url.startsWith("/api/training/export"), body: { count: 0 } },
    ]);
    const { document } = await loadApp({ fetchImpl });
    click(document.getElementById("export-training-btn"));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.querySelector(".toast").textContent).toMatch(/no training data to export/i);
  });

  it("builds a download link and shows a success toast when there is data", async () => {
    const fetchImpl = mkFetch([
      {
        test: (url) => url.startsWith("/api/training/export"),
        body: { count: 2, examples: [{ a: 1 }, { a: 2 }], sources: { findings: 2 } },
      },
    ]);
    const { window, document } = await loadApp({ fetchImpl });
    click(document.getElementById("export-training-btn"));
    await new Promise((r) => setTimeout(r, 0));
    expect(window.URL.createObjectURL).toHaveBeenCalled();
    expect(window.HTMLAnchorElement.prototype.click).toHaveBeenCalled();
    expect(document.querySelector(".toast").textContent).toMatch(/exported 2 example/i);
  });

  it("uses the selected format in the export request", async () => {
    const fetchImpl = mkFetch([{ test: (url) => url.startsWith("/api/training/export"), body: { count: 0 } }]);
    const { document } = await loadApp({ fetchImpl });
    document.getElementById("train-format").value = "sft";
    click(document.getElementById("export-training-btn"));
    await new Promise((r) => setTimeout(r, 0));
    const call = fetchImpl.mock.calls.find(([url]) => url.startsWith("/api/training/export"));
    expect(call[0]).toBe("/api/training/export?format=sft");
  });
});
