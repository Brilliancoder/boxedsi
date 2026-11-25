// What the side panel, the service worker and the tests share: requests, replies, the supported sites and the page inserter.
// A plain script: a <script> tag in the panel, an import for its side effect in the service worker, require() under node --test.
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.boxedProtocol = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const HOST_NAME = "si.boxed.host";
  // Where the switch and the results of observation live: the panel writes the first and reads the second, the worker the other way.
  const OBSERVE_KEY = "observe"; // chrome.storage.local: true when the person has turned observation on
  const OBSERVED_KEY = "observed"; // chrome.storage.session: the last results, newest first
  const MAX_MESSAGE = 1024 * 1024; // bytes of UTF-8 JSON; the host and the browser refuse more
  const LEVELS = [0, 1, 2];
  const SCOPE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const SCOPE_HINT = "Scope: use letters, digits, dot, dash and underscore, up to 64 characters.";
  const SITES = [
    "https://chatgpt.com/*",
    "https://claude.ai/*",
    "https://gemini.google.com/*",
    "https://chat.deepseek.com/*",
    "https://chat.z.ai/*",
  ];
  // The names the host knows these sites by (observation and training checks).
  const SITE_IDS = ["chatgpt", "claude", "gemini", "deepseek", "zai"];
  const COVERAGE = ["checked", "not checked"];
  const STATES = ["on", "off", "unknown"];
  const PROVIDER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const PROVIDER_HINT = "Provider: choose one of the chats in the list.";
  const ACCOUNT_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$/;
  const ACCOUNT_HINT = "Account: use letters, digits, dot, dash, plus, at sign and underscore, up to 64 characters.";

  // The host's error codes are fixed words; the panel shows these sentences and never the code or anything else.
  const ERRORS = {
    "bad request": "The boxed.si program refused the request as malformed.",
    "unknown scope": "No placeholders are saved under this scope. Use the scope shown after masking.",
    "reply too large": "The result is larger than 1 MB. Split the text into smaller parts.",
    "message too large": "The text is larger than 1 MB. Split it into smaller parts.",
    "host cannot start": "The boxed.si program cannot start. Check keychain access and boxed.toml.",
    "internal error": "The boxed.si program failed. Nothing was prepared.",
    "bad json": "The boxed.si program could not read the message.",
    "truncated frame": "The message to the boxed.si program was cut short.",
    "reply is not valid text": "The result holds text that cannot be sent back. Remove odd characters and try again.",
    "checks unreadable":
      "The saved training checks cannot be read, so every provider counts as training on your chats. " +
      "Run boxed check reset in a terminal (it moves the file aside and keeps it), then record your settings again.",
  };
  const REFUSED = "The boxed.si program refused the request.";
  const UNREADABLE = "The boxed.si program sent a reply this panel cannot read.";

  function checked(message) {
    if (new TextEncoder().encode(JSON.stringify(message)).length > MAX_MESSAGE) {
      throw new Error("The text is larger than 1 MB. Split it into smaller parts.");
    }
    return message;
  }

  function validScope(scope) {
    return typeof scope === "string" && SCOPE_RE.test(scope);
  }

  // The host's default scope: one per UTC day.
  function defaultScope(now = new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `web-${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}`;
  }

  function buildMaskRequest(text, level = 2, scope = null) {
    if (typeof text !== "string" || text === "") throw new Error("Nothing to mask: the text is empty.");
    if (!LEVELS.includes(level)) throw new Error("Level must be 0, 1 or 2.");
    if (scope !== null && !validScope(scope)) throw new Error(SCOPE_HINT);
    return checked({ cmd: "mask", text, scope, level });
  }

  function buildRestoreRequest(text, scope) {
    if (typeof text !== "string" || text === "") throw new Error("Nothing to restore: the text is empty.");
    if (!validScope(scope)) throw new Error(SCOPE_HINT);
    return checked({ cmd: "restore", text, scope });
  }

  // A message sent from one of the chats. A send that was not read ("not checked") carries no text.
  function buildObserveRequest(site, text, coverage) {
    if (!SITE_IDS.includes(site)) throw new Error("Site must be chatgpt, claude, gemini, deepseek or zai.");
    if (!COVERAGE.includes(coverage)) throw new Error("Coverage must be checked or not checked.");
    if (typeof text !== "string") throw new Error("Text must be a string.");
    if (coverage === "not checked" && text !== "") throw new Error("A send that was not checked carries no text.");
    return checked({ cmd: "observe", site, text, coverage });
  }

  function buildChecksRequest() {
    return { cmd: "checks" };
  }

  const validProvider = (v) => typeof v === "string" && PROVIDER_RE.test(v);
  const validAccount = (v) => typeof v === "string" && ACCOUNT_RE.test(v);

  function buildCheckSetRequest(provider, account, training, memory) {
    if (!validProvider(provider)) throw new Error(PROVIDER_HINT);
    if (!validAccount(account)) throw new Error(ACCOUNT_HINT);
    if (!STATES.includes(training)) throw new Error("Training must be on, off or unknown.");
    if (!STATES.includes(memory)) throw new Error("Memory must be on, off or unknown.");
    return checked({ cmd: "check-set", provider, account, training, memory });
  }

  const isStrings = (v) => Array.isArray(v) && v.every((x) => typeof x === "string");
  const isCounts = (v) =>
    v !== null && typeof v === "object" && !Array.isArray(v) && Object.values(v).every((n) => Number.isInteger(n) && n >= 0);

  // The pages of data controls that the panel may open, one for each chat the program knows a page for. They are kept as
  // the parts of an address, and an address from the program is opened only if it is exactly one of them: no other
  // host, path, query, fragment, port or login, whatever the program says.
  const SETTINGS_PAGES = [
    { host: "chatgpt.com", path: "/", hash: "#settings/DataControls" },
    { host: "claude.ai", path: "/settings/data-privacy-controls", hash: "" },
    { host: "myactivity.google.com", path: "/product/gemini", hash: "" },
  ];

  function isSettingsUrl(value) {
    if (typeof value !== "string") return false;
    let url;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.port === "" &&
      url.search === "" &&
      SETTINGS_PAGES.some((page) => url.hostname === page.host && url.pathname === page.path && url.hash === page.hash)
    );
  }

  // The page to open for a chat, from the "settings" of a parsed "checks" reply, or null. Checked again here, at the
  // place where the address is used.
  function settingsFor(settings, provider) {
    if (settings === null || typeof settings !== "object" || typeof provider !== "string") return null;
    return Object.hasOwn(settings, provider) && isSettingsUrl(settings[provider]) ? settings[provider] : null;
  }

  // {provider: address or null}, as the program sends it for all its chats; null when it holds anything else.
  function parseSettings(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const settings = {};
    for (const [provider, url] of Object.entries(value)) {
      if (!validProvider(provider) || !(url === null || isSettingsUrl(url))) return null;
      settings[provider] = url;
    }
    return settings;
  }

  function parseCheck(item) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) return null;
    const good =
      validProvider(item.provider) &&
      validAccount(item.account) &&
      STATES.includes(item.training) &&
      STATES.includes(item.memory) &&
      typeof item.source === "string" &&
      typeof item.checked_at === "string" &&
      typeof item.due === "boolean" &&
      (item.settings_url === null || isSettingsUrl(item.settings_url));
    if (!good) return null;
    return {
      provider: item.provider,
      account: item.account,
      training: item.training,
      memory: item.memory,
      source: item.source,
      checkedAt: item.checked_at,
      due: item.due,
      settingsUrl: item.settings_url,
    };
  }

  function parseChecks(reply) {
    if (!Array.isArray(reply.checks) || !Array.isArray(reply.providers) || !reply.providers.every(validProvider)) return null;
    if (typeof reply.note !== "string") return null;
    const settings = reply.settings === undefined ? {} : parseSettings(reply.settings); // an older program sends none
    if (settings === null) return null;
    const checks = reply.checks.map(parseCheck);
    return checks.includes(null) ? null : { ok: true, checks, providers: reply.providers, note: reply.note, settings };
  }

  // reply: what the host sent; cmd: "ping", "mask", "restore", "observe", "checks" or "check-set".
  // Returns {ok: true, ...} or {ok: false, error}.
  function parseReply(reply, cmd) {
    const fail = (error) => ({ ok: false, error });
    if (reply === null || typeof reply !== "object" || Array.isArray(reply) || typeof reply.ok !== "boolean") {
      return fail(UNREADABLE);
    }
    if (!reply.ok) return fail(Object.hasOwn(ERRORS, reply.error) ? ERRORS[reply.error] : REFUSED);
    if (cmd === "ping" && typeof reply.version === "string") return { ok: true, version: reply.version };
    if (cmd === "mask" && typeof reply.text === "string" && typeof reply.scope === "string" && isCounts(reply.markers_by_kind)) {
      return { ok: true, text: reply.text, scope: reply.scope, markersByKind: reply.markers_by_kind };
    }
    if (cmd === "restore" && typeof reply.text === "string" && isStrings(reply.unknown) && isStrings(reply.suspicious)) {
      return { ok: true, text: reply.text, unknown: reply.unknown, suspicious: reply.suspicious };
    }
    if (cmd === "observe" && isCounts(reply.found)) return { ok: true, found: reply.found };
    if (cmd === "check-set") return { ok: true };
    if (cmd === "checks") {
      const parsed = parseChecks(reply);
      if (parsed) return parsed;
    }
    return fail(UNREADABLE);
  }

  // One line for a stored result of observation: what was found, or why nothing was. Null for anything that is not a result.
  function describeObserved(entry) {
    if (entry === null || typeof entry !== "object") return null;
    const { site, time, found, coverage } = entry;
    if (!SITE_IDS.includes(site) || !Number.isFinite(time) || !COVERAGE.includes(coverage)) return null;
    if (coverage === "not checked") return "not checked (not readable or too large, or the boxed.si program was too slow or busy)";
    if (found === null) return "not recorded (the boxed.si program did not answer)";
    if (!isCounts(found)) return null;
    const parts = Object.entries(found).map(([kind, count]) => `${kind} ${count}`);
    return parts.length ? parts.join(", ") : "nothing found";
  }

  // check: one item of a parsed "checks" reply.
  function describeCheck(check) {
    return `Training ${check.training}, memory ${check.memory}. Checked ${check.checkedAt} (${check.source}).`;
  }

  // message: the browser's own error text for a failed native call; it is matched, never shown.
  function describeFailure(message, extensionId) {
    const fix = `Run: boxed install native-host --extension-id ${extensionId}`;
    if (message === "Specified native messaging host not found.") {
      return `The boxed.si program is not registered with this browser. ${fix}`;
    }
    if (message === "Access to the specified native messaging host is forbidden.") {
      return `The boxed.si program does not trust this extension yet. ${fix}`;
    }
    if (message === "Native host has exited.") {
      return "The boxed.si program exited before it answered. Reinstall it, then try again.";
    }
    return "Could not reach the boxed.si program.";
  }

  function isAiSite(url) {
    try {
      const origin = new URL(url).origin;
      return SITES.some((pattern) => origin === pattern.slice(0, -2));
    } catch {
      return false;
    }
  }

  // Runs inside the page: chrome.scripting.executeScript sends it as source text, so it may use only globals.
  // It fills the focused input and does nothing else. No keys, no buttons: the person sends the message.
  function insertIntoActiveInput(text) {
    let el = document.activeElement;
    while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
    if (!el || el === document.body || el === document.documentElement) return "no-input";
    const tag = String(el.tagName).toUpperCase();
    if (tag === "TEXTAREA" || (tag === "INPUT" && (el.type === "text" || el.type === "search"))) {
      if (el.readOnly || el.disabled) return "not-an-input";
      const start = el.selectionStart == null ? el.value.length : el.selectionStart;
      const end = el.selectionEnd == null ? el.value.length : el.selectionEnd;
      el.setRangeText(text, start, end, "end");
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return "inserted";
    }
    if (el.isContentEditable) {
      el.focus();
      return document.execCommand("insertText", false, text) ? "inserted" : "failed";
    }
    return "not-an-input";
  }

  return {
    HOST_NAME,
    OBSERVE_KEY,
    OBSERVED_KEY,
    MAX_MESSAGE,
    SITES,
    SITE_IDS,
    SCOPE_RE,
    defaultScope,
    buildMaskRequest,
    buildRestoreRequest,
    buildObserveRequest,
    buildChecksRequest,
    buildCheckSetRequest,
    parseReply,
    settingsFor,
    describeObserved,
    describeCheck,
    describeFailure,
    isAiSite,
    insertIntoActiveInput,
  };
});
