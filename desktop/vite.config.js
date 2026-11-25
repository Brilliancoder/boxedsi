export default {
  clearScreen: false,
  build: {
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari13",
    // The page loads its own files and nothing else: no data: URIs, no inline script, so the CSP needs no exceptions.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
};
