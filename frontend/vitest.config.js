import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // app.js is a classic (non-module) script loaded via a JSDOM window per
    // test in tests/helpers/dom.js, so the default "node" environment is
    // enough — we don't need vitest's own jsdom environment.
    environment: "node",
    include: ["tests/**/*.test.js"],
  },
});
