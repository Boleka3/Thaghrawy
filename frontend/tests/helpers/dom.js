// Test harness that loads the *real* frontend/index.html + frontend/app.js
// into a fresh JSDOM window, so tests click actual buttons in the actual
// markup rather than a re-implementation of it.
//
// app.js is a classic (non-module) script with no exports, so it can't be
// `import`-ed directly. Instead we parse index.html with JSDOM in
// `runScripts: "outside-only"` mode (which parses the DOM but does not try
// to fetch/execute the <script src="/static/app.js"> tag itself) and then
// `window.eval()` the app.js source ourselves. Indirect eval like this runs
// as global code in that window's realm, so app.js's top-level `function`
// declarations (showToast, deleteEngagement, api, ...) end up as properties
// of `window`, exactly as they would in a browser, and its
// `document.getElementById(...)` calls see the fully-parsed DOM.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { vi } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = path.resolve(__dirname, "..", "..");

const HTML = fs.readFileSync(path.join(FRONTEND_DIR, "index.html"), "utf-8");
const APP_JS = fs.readFileSync(path.join(FRONTEND_DIR, "app.js"), "utf-8");

/** Minimal controllable WebSocket stand-in (jsdom has no real WS transport). */
export class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.sent = [];
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onerror = null;
    MockWebSocket.instances.push(this);
  }

  send(data) {
    this.sent.push(data);
  }

  close() {
    if (this.readyState === MockWebSocket.CLOSED) return;
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) this.onclose({ type: "close" });
  }

  /** Test helper: simulate the server accepting the connection. */
  open() {
    this.readyState = MockWebSocket.OPEN;
    if (this.onopen) this.onopen({ type: "open" });
  }

  /** Test helper: simulate a server->client protocol message. */
  emit(msg) {
    if (this.onmessage) this.onmessage({ data: JSON.stringify(msg) });
  }
}
MockWebSocket.instances = [];

/**
 * Build a `fetch` mock from an ordered list of routes:
 *   { test: (url, opts) => bool, status?: number, body: value | (url, opts) => value }
 * The first matching route wins; unmatched calls default to `200 []`, which
 * is a harmless response for the list endpoints (`/api/engagements`,
 * `/api/findings/engagement/:id`, `/api/engagements/:id/reports`, ...).
 */
export function mkFetch(routes = []) {
  const fn = vi.fn(async (url, opts = {}) => {
    for (const r of routes) {
      if (r.test(url, opts)) {
        const body = typeof r.body === "function" ? r.body(url, opts) : r.body;
        const status = r.status ?? 200;
        return {
          ok: status < 400,
          status,
          json: async () => body,
          text: async () => JSON.stringify(body),
        };
      }
    }
    return { ok: true, status: 200, json: async () => [], text: async () => "[]" };
  });
  return fn;
}

/** Let pending promise chains (fetch mocks, .then handlers) settle. */
export function flush(rounds = 3) {
  return new Promise((resolve) => {
    let n = 0;
    const tick = () => {
      n += 1;
      if (n >= rounds) resolve();
      else setTimeout(tick, 0);
    };
    setTimeout(tick, 0);
  });
}

/**
 * Load a fresh copy of the app into a new JSDOM window.
 *
 * @param {object} opts
 * @param {ReturnType<typeof mkFetch>} [opts.fetchImpl] custom fetch mock
 * @param {Array} [opts.engagements] seed list returned from GET /api/engagements
 */
export async function loadApp({ fetchImpl, engagements = [] } = {}) {
  const dom = new JSDOM(HTML, {
    url: "http://localhost/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const { window } = dom;

  MockWebSocket.instances.length = 0;
  window.WebSocket = MockWebSocket;

  const fetchMock =
    fetchImpl ||
    mkFetch([
      {
        test: (url) => /^\/api\/engagements(\?|$)/.test(url),
        body: engagements,
      },
    ]);
  window.fetch = fetchMock;

  // jsdom doesn't implement these; stub them so app.js code paths that touch
  // them (export-training, native confirm/prompt fallbacks) don't throw.
  window.URL.createObjectURL = vi.fn(() => "blob:mock");
  window.URL.revokeObjectURL = vi.fn();
  window.HTMLAnchorElement.prototype.click = vi.fn();
  window.alert = vi.fn();
  window.prompt = vi.fn(() => null);
  window.confirm = vi.fn(() => true);
  if (!window.crypto) window.crypto = {};
  if (!window.crypto.randomUUID) {
    window.crypto.randomUUID = vi.fn(() => "00000000-0000-0000-0000-000000000000");
  }

  window.eval(APP_JS);

  // The script's init tail (checkLlmStatus(), loadEngagements()) fires async
  // work we didn't await (app.js doesn't either — it's fire-and-forget at
  // load time in the real page). Let it settle before handing back control.
  await flush();

  return { dom, window, document: window.document, fetchMock };
}

/** Dispatch a real bubbling click event, like a user would produce. */
export function click(el) {
  el.dispatchEvent(new el.ownerDocument.defaultView.MouseEvent("click", { bubbles: true, cancelable: true }));
}
