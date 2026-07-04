import { describe, expect, it } from "vitest";
import { loadApp, click } from "./helpers/dom.js";

// Regression coverage for the resolve-swallowing bug: closeModal() resolves
// the modal promise with `null` as a "dismissed" fallback, and the button
// handler used to call closeModal() *before* resolving with the button's own
// value — since a promise only resolves once, that always won, so every
// modal (confirm, prompt, ...) silently resolved to null regardless of which
// button was clicked. See frontend/app.js showModal().
describe("modal system", () => {
  it("Confirm resolves true and Cancel resolves false", async () => {
    const { window, document } = await loadApp();

    const confirmed = window.showConfirm("Delete?", "sure?");
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false);
    click(document.querySelector("#modal-actions .confirm-btn"));
    await expect(confirmed).resolves.toBe(true);
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(true);

    const cancelled = window.showConfirm("Delete?", "sure?");
    click(document.querySelector("#modal-actions .cancel-btn"));
    await expect(cancelled).resolves.toBe(false);
  });

  it("showPrompt OK resolves with the entered field values", async () => {
    const { window, document } = await loadApp();
    const pending = window.showPrompt("Edit", [{ key: "name", label: "Name", required: true }]);
    document.getElementById("_prompt_0").value = "new name";
    click(document.querySelector("#modal-actions .confirm-btn"));
    await expect(pending).resolves.toEqual({ name: "new name" });
  });

  it("showPrompt OK stays open and flags the field when a required field is blank", async () => {
    const { window, document } = await loadApp();
    let resolved = false;
    const pending = window.showPrompt("Edit", [{ key: "name", label: "Name", required: true }]);
    pending.then(() => { resolved = true; });

    document.getElementById("_prompt_0").value = "   ";
    click(document.querySelector("#modal-actions .confirm-btn"));
    await new Promise((r) => setTimeout(r, 0));

    expect(resolved).toBe(false);
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false);
    expect(document.getElementById("_prompt_0").classList.contains("invalid")).toBe(true);

    document.getElementById("_prompt_0").value = "ok now";
    click(document.querySelector("#modal-actions .confirm-btn"));
    await expect(pending).resolves.toEqual({ name: "ok now" });
  });

  it("Escape key closes an open modal (resolves null)", async () => {
    const { window, document } = await loadApp();
    const pending = window.showConfirm("Delete?", "sure?");
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false);
    document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    await expect(pending).resolves.toBe(null);
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(true);
  });

  it("clicking the backdrop closes an open modal (resolves null)", async () => {
    const { window, document } = await loadApp();
    const pending = window.showConfirm("Delete?", "sure?");
    click(document.getElementById("modal-overlay"));
    await expect(pending).resolves.toBe(null);
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(true);
  });

  it("clicking inside the modal card does not close it", async () => {
    const { window, document } = await loadApp();
    window.showConfirm("Delete?", "sure?");
    click(document.getElementById("modal-body"));
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false);
  });

  // The header's "X" button (#modal-close in index.html) has no click
  // listener wired up anywhere in app.js — it's inert. Documented here so a
  // future reader isn't left guessing whether that's intentional; if it gets
  // wired up, flip this assertion.
  it("KNOWN GAP: the modal-close (X) button does not close the modal", async () => {
    const { window, document } = await loadApp();
    window.showConfirm("Delete?", "sure?");
    click(document.getElementById("modal-close"));
    expect(document.getElementById("modal-overlay").classList.contains("hidden")).toBe(false);
  });
});
