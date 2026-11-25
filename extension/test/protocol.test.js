"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const P = require("../lib/protocol.js");

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
const bytes = (s) => new TextEncoder().encode(s).length;
const MB = 1024 * 1024;

test("the host name and the size limit match the Python host", () => {
  assert.equal(P.HOST_NAME, "si.boxed.host");
  assert.equal(P.MAX_MESSAGE, MB);
});

test("defaultScope is web- plus the UTC date, whatever the time zone", () => {
  const zone = process.env.TZ;
  try {
    for (const tz of ["Asia/Tokyo", "Pacific/Honolulu"]) {
      process.env.TZ = tz;
      assert.equal(P.defaultScope(new Date(Date.UTC(2026, 9, 21, 23, 59))), "web-20261021");
      assert.equal(P.defaultScope(new Date("2026-10-21T00:30:00+03:00")), "web-20261020");
    }
  } finally {
    if (zone === undefined) delete process.env.TZ;
    else process.env.TZ = zone;
  }
  assert.match(P.defaultScope(), /^web-\d{8}$/);
  assert.ok(P.SCOPE_RE.test(P.defaultScope()));
});

test("buildMaskRequest has the shape the host takes", () => {
  assert.deepEqual(P.buildMaskRequest("mail a@b.io", 1, "web-20261021"), {
    cmd: "mask",
    text: "mail a@b.io",
    scope: "web-20261021",
    level: 1,
  });
  assert.deepEqual(P.buildMaskRequest("x"), { cmd: "mask", text: "x", scope: null, level: 2 });
  assert.deepEqual(Object.keys(P.buildMaskRequest("x")).sort(), ["cmd", "level", "scope", "text"]);
});

test("buildMaskRequest refuses what the host would refuse", () => {
  for (const text of ["", null, undefined, 5, ["x"]]) assert.throws(() => P.buildMaskRequest(text), /text/i);
  for (const level of [3, -1, 1.5, "1", null, true]) assert.throws(() => P.buildMaskRequest("x", level), /level/i);
  for (const scope of ["", "a b", "a@b.io", ".hidden", "web-1\n", "a".repeat(65), 5])
    assert.throws(() => P.buildMaskRequest("x", 2, scope), /scope/i);
  assert.doesNotThrow(() => P.buildMaskRequest("x", 2, "a".repeat(64)));
});

test("the 1 MB limit counts bytes of the whole message", () => {
  const overhead = bytes(JSON.stringify(P.buildMaskRequest("x"))) - 1;
  assert.doesNotThrow(() => P.buildMaskRequest("x".repeat(MB - overhead)));
  assert.throws(() => P.buildMaskRequest("x".repeat(MB - overhead + 1)), /1 MB/);
  assert.throws(() => P.buildMaskRequest("я".repeat(MB / 2)), /1 MB/); // 2 bytes each in UTF-8
  const restoreOverhead = bytes(JSON.stringify(P.buildRestoreRequest("x", "s"))) - 1;
  assert.doesNotThrow(() => P.buildRestoreRequest("x".repeat(MB - restoreOverhead), "s"));
  assert.throws(() => P.buildRestoreRequest("x".repeat(MB - restoreOverhead + 1), "s"), /1 MB/);
});

test("buildRestoreRequest needs the answer and a scope", () => {
  assert.deepEqual(P.buildRestoreRequest("Mail [EMAIL_1]", "web-20261021"), {
    cmd: "restore",
    text: "Mail [EMAIL_1]",
    scope: "web-20261021",
  });
  assert.throws(() => P.buildRestoreRequest("", "s"), /text/i);
  assert.throws(() => P.buildRestoreRequest("x"), /scope/i);
  assert.throws(() => P.buildRestoreRequest("x", null), /scope/i);
  assert.throws(() => P.buildRestoreRequest("x", "a b"), /scope/i);
});

test("parseReply reads the three good replies", () => {
  assert.deepEqual(P.parseReply({ ok: true, version: "0.1.0" }, "ping"), { ok: true, version: "0.1.0" });
  assert.deepEqual(
    P.parseReply({ ok: true, text: "mail [EMAIL_1]", scope: "s", markers_by_kind: { EMAIL: 1 } }, "mask"),
    { ok: true, text: "mail [EMAIL_1]", scope: "s", markersByKind: { EMAIL: 1 } },
  );
  assert.deepEqual(
    P.parseReply({ ok: true, text: "a@b.io", unknown: ["[EMAIL_9]"], suspicious: ["[EMAIL-1]"] }, "restore"),
    { ok: true, text: "a@b.io", unknown: ["[EMAIL_9]"], suspicious: ["[EMAIL-1]"] },
  );
});

test("parseReply turns the host's error codes into sentences", () => {
  const codes = [
    "bad request",
    "unknown scope",
    "reply too large",
    "message too large",
    "host cannot start",
    "internal error",
    "bad json",
    "truncated frame",
    "reply is not valid text",
  ];
  const seen = new Set();
  for (const code of codes) {
    const reply = P.parseReply({ ok: false, error: code }, "mask");
    assert.equal(reply.ok, false);
    assert.notEqual(reply.error, code);
    assert.match(reply.error, /\.$/);
    seen.add(reply.error);
  }
  assert.equal(seen.size, codes.length);
  const unknown = P.parseReply({ ok: false, error: "<img src=x onerror=alert(1)>" }, "mask");
  assert.equal(unknown.ok, false);
  assert.doesNotMatch(unknown.error, /img/); // an unknown code is never echoed
});

test("parseReply refuses a reply that is not what the host sends", () => {
  const bad = [
    [undefined, "ping"],
    [null, "ping"],
    ["ok", "ping"],
    [[], "ping"],
    [{}, "ping"],
    [{ ok: "yes" }, "ping"],
    [{ ok: true }, "ping"],
    [{ ok: true, version: 1 }, "ping"],
    [{ ok: true, text: "x" }, "mask"],
    [{ ok: true, text: 5, scope: "s", markers_by_kind: {} }, "mask"],
    [{ ok: true, text: "x", scope: "s", markers_by_kind: { EMAIL: "1" } }, "mask"],
    [{ ok: true, text: "x", unknown: "[EMAIL_9]", suspicious: [] }, "restore"],
    [{ ok: true, text: "x", unknown: [], suspicious: [1] }, "restore"],
    [{ ok: true, text: "x" }, "restore"],
    [{ ok: true, version: "0.1.0" }, "shell"],
    [{ ok: true, version: "0.1.0" }, undefined],
  ];
  for (const [reply, cmd] of bad) {
    const parsed = P.parseReply(reply, cmd);
    assert.equal(parsed.ok, false, JSON.stringify([reply, cmd]));
    assert.equal(typeof parsed.error, "string");
  }
});

test("describeFailure explains the browser's native messaging errors", () => {
  const id = "a".repeat(32);
  assert.match(P.describeFailure("Specified native messaging host not found.", id), /boxed install native-host --extension-id a{32}/);
  assert.match(P.describeFailure("Access to the specified native messaging host is forbidden.", id), /--extension-id a{32}/);
  assert.match(P.describeFailure("Native host has exited.", id), /cannot start|exited/i);
  assert.match(P.describeFailure(undefined, id), /boxed\.si/);
  assert.doesNotMatch(P.describeFailure("<b>x</b>", id), /<b>/); // browser text is never echoed
});

test("isAiSite accepts the five sites and nothing that looks like them", () => {
  for (const url of [
    "https://chatgpt.com/",
    "https://chatgpt.com/c/123?model=x",
    "https://claude.ai/new",
    "https://gemini.google.com/app",
    "https://chat.deepseek.com/",
    "https://chat.z.ai/c/1",
  ]) {
    assert.equal(P.isAiSite(url), true, url);
  }
  for (const url of [
    "http://chatgpt.com/",
    "https://chatgpt.com.evil.com/",
    "https://evilchatgpt.com/",
    "https://chatgpt.com@evil.com/",
    "https://evil.com/?u=https://chatgpt.com/",
    "https://www.claude.ai/",
    "https://google.com/",
    "chrome://extensions",
    "file:///etc/passwd",
    "",
    undefined,
    null,
    5,
  ]) {
    assert.equal(P.isAiSite(url), false, String(url));
  }
});

test("SITES are exactly the host permissions of the manifest", () => {
  assert.deepEqual([...P.SITES].sort(), [...manifest.host_permissions].sort());
  assert.equal(P.SITES.length, 5);
});

// A page as the inserter sees it: the focused element is document.activeElement.
function field(tag, props = {}) {
  const el = {
    tagName: tag,
    type: "text",
    value: "",
    selectionStart: 0,
    selectionEnd: 0,
    readOnly: false,
    disabled: false,
    isContentEditable: false,
    events: [],
    calls: [],
    setRangeText(text, start, end) {
      this.value = this.value.slice(0, start) + text + this.value.slice(end);
      this.selectionStart = this.selectionEnd = start + text.length;
    },
    dispatchEvent(event) {
      this.events.push(event.type);
      return true;
    },
    focus() {
      this.calls.push("focus");
    },
    // anything that would send the message must never be called
    click() {
      throw new Error("click");
    },
    submit() {
      throw new Error("submit");
    },
    requestSubmit() {
      throw new Error("requestSubmit");
    },
    form: {
      submit() {
        throw new Error("form submit");
      },
      requestSubmit() {
        throw new Error("form requestSubmit");
      },
    },
    ...props,
  };
  return el;
}

// the inserter is sent to the page as source text: run that text with nothing but a document
function insertInto(active, text) {
  const document = { activeElement: active, body: { tagName: "BODY" }, documentElement: { tagName: "HTML" }, commands: [] };
  document.execCommand = (...args) => {
    document.commands.push(args);
    return true;
  };
  const run = vm.runInNewContext(`(${P.insertIntoActiveInput.toString()})`, { document, Event });
  return { result: run(text), document };
}

test("insert into a textarea at the caret and tell the page's framework", () => {
  const el = field("TEXTAREA", { value: "Hello  world", selectionStart: 6, selectionEnd: 6 });
  const { result } = insertInto(el, "[EMAIL_1]");
  assert.equal(result, "inserted");
  assert.equal(el.value, "Hello [EMAIL_1] world");
  assert.deepEqual(el.events, ["input"]);
});

test("insert replaces a selection and fills an empty text input", () => {
  const el = field("TEXTAREA", { value: "abcdef", selectionStart: 1, selectionEnd: 4 });
  insertInto(el, "X");
  assert.equal(el.value, "aXef");
  const input = field("INPUT", { type: "search" });
  assert.equal(insertInto(input, "q").result, "inserted");
  assert.equal(input.value, "q");
});

test("insert into a rich text box through the editing command", () => {
  const el = field("DIV", { isContentEditable: true });
  const { result, document } = insertInto(el, "line 1\nline 2");
  assert.equal(result, "inserted");
  assert.deepEqual(document.commands, [["insertText", false, "line 1\nline 2"]]);
  assert.deepEqual(el.events, []);
});

test("insert reports a refused editing command", () => {
  const el = field("DIV", { isContentEditable: true });
  const document = { activeElement: el, body: {}, documentElement: {}, execCommand: () => false };
  const run = vm.runInNewContext(`(${P.insertIntoActiveInput.toString()})`, { document, Event });
  assert.equal(run("x"), "failed");
});

test("insert follows focus into a shadow root", () => {
  const inner = field("TEXTAREA");
  const host = field("DIV", { shadowRoot: { activeElement: inner } });
  assert.equal(insertInto(host, "deep").result, "inserted");
  assert.equal(inner.value, "deep");
});

test("insert does nothing when nothing suitable has focus", () => {
  const readOnly = field("TEXTAREA", { readOnly: true });
  const disabled = field("INPUT", { disabled: true });
  const password = field("INPUT", { type: "password" });
  const button = field("BUTTON");
  for (const el of [readOnly, disabled, password, button]) {
    assert.equal(insertInto(el, "x").result, "not-an-input");
    assert.equal(el.value, "");
    assert.deepEqual(el.events, []);
  }
  assert.equal(insertInto(null, "x").result, "no-input");
  assert.equal(insertInto(undefined, "x").result, "no-input");
  const page = { body: { tagName: "BODY" }, documentElement: { tagName: "HTML" }, execCommand: () => assert.fail("no command") };
  for (const idle of [page.body, page.documentElement]) {
    const run = vm.runInNewContext(`(${P.insertIntoActiveInput.toString()})`, { document: { ...page, activeElement: idle }, Event });
    assert.equal(run("x"), "no-input");
  }
});

test("insert never submits anything", () => {
  const source = P.insertIntoActiveInput.toString();
  assert.doesNotMatch(source, /\b(?:submit|requestSubmit|click|KeyboardEvent|MouseEvent|keydown|keypress|keyup|Enter)\b/);
  for (const el of [field("TEXTAREA", { value: "a" }), field("DIV", { isContentEditable: true })]) {
    insertInto(el, "text with a trailing newline\n");
    assert.ok(el.events.every((type) => type === "input"));
  }
});

// Observation and training checks: the requests and replies of the message contract with the host.

test("the observed sites are the five of the contract", () => {
  assert.deepEqual([...P.SITE_IDS].sort(), ["chatgpt", "claude", "deepseek", "gemini", "zai"]);
});

test("buildObserveRequest has exactly the fields the host takes", () => {
  assert.deepEqual(P.buildObserveRequest("claude", "mail a@b.io", "checked"), {
    cmd: "observe",
    site: "claude",
    text: "mail a@b.io",
    coverage: "checked",
  });
  assert.deepEqual(P.buildObserveRequest("zai", "", "not checked"), { cmd: "observe", site: "zai", text: "", coverage: "not checked" });
  assert.deepEqual(P.buildObserveRequest("gemini", "", "checked"), { cmd: "observe", site: "gemini", text: "", coverage: "checked" });
});

test("buildObserveRequest refuses what the host would refuse", () => {
  for (const site of ["bing", "", "ChatGPT", "chatgpt ", undefined, null, 5, ["chatgpt"]]) {
    assert.throws(() => P.buildObserveRequest(site, "x", "checked"), /site/i, String(site));
  }
  for (const coverage of ["full", "Checked", "not_checked", "", undefined, null, true]) {
    assert.throws(() => P.buildObserveRequest("claude", "x", coverage), /coverage/i, String(coverage));
  }
  for (const text of [undefined, null, 5, ["x"], {}]) assert.throws(() => P.buildObserveRequest("claude", text, "checked"), /text/i);
  assert.throws(() => P.buildObserveRequest("claude", "x", "not checked"), /not checked/i); // a send that was not read has no text
});

test("the 1 MB limit holds for observe requests too", () => {
  const overhead = bytes(JSON.stringify(P.buildObserveRequest("claude", "x", "checked"))) - 1;
  assert.doesNotThrow(() => P.buildObserveRequest("claude", "x".repeat(MB - overhead), "checked"));
  assert.throws(() => P.buildObserveRequest("claude", "x".repeat(MB - overhead + 1), "checked"), /1 MB/);
});

test("buildChecksRequest is the bare command", () => {
  assert.deepEqual(P.buildChecksRequest(), { cmd: "checks" });
});

test("buildCheckSetRequest has exactly the fields the host takes", () => {
  assert.deepEqual(P.buildCheckSetRequest("chatgpt", "me@example.com", "off", "unknown"), {
    cmd: "check-set",
    provider: "chatgpt",
    account: "me@example.com",
    training: "off",
    memory: "unknown",
  });
  for (const account of ["a", "A1", "a.b_c-d+e@f.g", "a".repeat(64)]) {
    assert.doesNotThrow(() => P.buildCheckSetRequest("zai", account, "on", "on"), account);
  }
});

test("buildCheckSetRequest refuses a bad provider, account or state", () => {
  for (const provider of ["", "a b", "<b>", "x".repeat(65), undefined, null, 5, ["chatgpt"]]) {
    assert.throws(() => P.buildCheckSetRequest(provider, "me", "off", "off"), /provider/i, String(provider));
  }
  for (const account of ["", "a b", "me@exa mple.com", ".hidden", "-x", "_x", "a".repeat(65), "me\n", "я", undefined, null, 5]) {
    assert.throws(() => P.buildCheckSetRequest("chatgpt", account, "off", "off"), /account/i, String(account));
  }
  for (const state of ["maybe", "ON", "yes", "", true, 1, undefined, null]) {
    assert.throws(() => P.buildCheckSetRequest("chatgpt", "me", state, "off"), /training/i, String(state));
    assert.throws(() => P.buildCheckSetRequest("chatgpt", "me", "off", state), /memory/i, String(state));
  }
});

test("parseReply reads the observe and check-set replies", () => {
  assert.deepEqual(P.parseReply({ ok: true, found: { EMAIL: 2, PHONE: 1 } }, "observe"), { ok: true, found: { EMAIL: 2, PHONE: 1 } });
  assert.deepEqual(P.parseReply({ ok: true, found: {} }, "observe"), { ok: true, found: {} });
  assert.deepEqual(P.parseReply({ ok: true }, "check-set"), { ok: true });
  for (const reply of [{ ok: true }, { ok: true, found: null }, { ok: true, found: [1] }, { ok: true, found: { EMAIL: "2" } }, { ok: true, found: { EMAIL: -1 } }]) {
    assert.equal(P.parseReply(reply, "observe").ok, false, JSON.stringify(reply));
  }
  assert.equal(P.parseReply({ ok: false, error: "bad request" }, "check-set").ok, false);
});

const NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while.";
const CHECK = {
  provider: "chatgpt",
  account: "personal",
  training: "off",
  memory: "unknown",
  source: "asked",
  checked_at: "2026-10-01",
  due: false,
  settings_url: "https://chatgpt.com/#settings/DataControls",
};
// the three pages of data controls the panel may open, and the program's list of them for all five chats
const PAGES = ["https://chatgpt.com/#settings/DataControls", "https://claude.ai/settings/data-privacy-controls", "https://myactivity.google.com/product/gemini"];
const SETTINGS = { chatgpt: PAGES[0], claude: PAGES[1], gemini: PAGES[2], deepseek: null, zai: null };
const checksReply = (...checks) => ({ ok: true, checks, providers: ["chatgpt", "claude", "gemini", "deepseek", "zai"], note: NOTE, settings: SETTINGS });

test("parseReply reads the list of checks", () => {
  const second = { ...CHECK, provider: "deepseek", account: "me@example.com", training: "unknown", due: true, settings_url: null };
  assert.deepEqual(P.parseReply(checksReply(CHECK, second), "checks"), {
    ok: true,
    checks: [
      {
        provider: "chatgpt",
        account: "personal",
        training: "off",
        memory: "unknown",
        source: "asked",
        checkedAt: "2026-10-01",
        due: false,
        settingsUrl: "https://chatgpt.com/#settings/DataControls",
      },
      {
        provider: "deepseek",
        account: "me@example.com",
        training: "unknown",
        memory: "unknown",
        source: "asked",
        checkedAt: "2026-10-01",
        due: true,
        settingsUrl: null,
      },
    ],
    providers: ["chatgpt", "claude", "gemini", "deepseek", "zai"],
    note: NOTE,
    settings: SETTINGS,
  });
  assert.deepEqual(P.parseReply(checksReply(), "checks").checks, []); // nothing recorded yet
});

test("a settings address is taken only when it is one of the three pages the panel knows", () => {
  for (const url of PAGES) assert.equal(P.parseReply(checksReply({ ...CHECK, settings_url: url }), "checks").ok, true, url);
  const foreign = [
    "https://evil.example/phish",
    "https://user:pw@evil.example:8443/x?y#z",
    "https://chatgpt.com/", // the right site, but not the page
    "https://chatgpt.com/#settings/Other",
    "https://chatgpt.com/?next=https://evil.example#settings/DataControls",
    "https://chatgpt.com/phish#settings/DataControls",
    "https://claude.ai/settings",
    "https://claude.ai/settings/data-privacy-controls/extra",
    "https://claude.ai/settings/data-privacy-controls?x=1",
    "https://claude.ai/settings/data-privacy-controls#x",
    "https://myactivity.google.com/",
    "https://myactivity.google.com/product/gemini?hl=en",
    "https://myactivity.google.com/product/gemini#x",
    "https://myactivity.google.com/product/other",
    "http://claude.ai/settings/data-privacy-controls",
    "https://user:pw@claude.ai/settings/data-privacy-controls",
    "https://:pw@claude.ai/settings/data-privacy-controls", // a password and no user name
    "https://claude.ai:8443/settings/data-privacy-controls",
    "https://claude.ai.evil.com/settings/data-privacy-controls",
    "https://www.claude.ai/settings/data-privacy-controls",
    "javascript:alert(1)",
    "data:text/html,x",
    "file:///etc/passwd",
    "",
    "https://",
    "not a url",
    5,
    [],
    {},
    true,
  ];
  for (const url of foreign) assert.equal(P.parseReply(checksReply({ ...CHECK, settings_url: url }), "checks").ok, false, String(url));
});

test("the program's list of settings pages comes with the checks, and only known pages are taken from it", () => {
  assert.deepEqual(P.parseReply(checksReply(CHECK), "checks").settings, SETTINGS);
  const older = checksReply(CHECK);
  delete older.settings; // a program that does not send the list yet
  assert.deepEqual(P.parseReply(older, "checks").settings, {});
  const bad = [
    null,
    [],
    "chatgpt",
    5,
    true,
    { chatgpt: "https://evil.example/phish" },
    { chatgpt: PAGES[0], claude: "http://claude.ai/settings/data-privacy-controls" },
    { chatgpt: 5 },
    { chatgpt: [PAGES[0]] },
    { "a b": null },
    { "": null },
    JSON.parse('{"__proto__": null}'), // an own property of that name, which is no provider
  ];
  for (const settings of bad) assert.equal(P.parseReply({ ...checksReply(CHECK), settings }, "checks").ok, false, JSON.stringify(settings));
});

test("settingsFor gives the page of a chat, and nothing for a name the list does not hold", () => {
  assert.equal(P.settingsFor(SETTINGS, "claude"), PAGES[1]);
  assert.equal(P.settingsFor(SETTINGS, "chatgpt"), PAGES[0]);
  assert.equal(P.settingsFor(SETTINGS, "deepseek"), null); // the program knows no page for it
  for (const name of ["", "bing", "constructor", "toString", "__proto__", "hasOwnProperty", undefined, null, 5, { toString: () => "claude" }]) {
    assert.equal(P.settingsFor(SETTINGS, name), null, String(name)); // a name must be a string, not something that turns into one
  }
  assert.equal(P.settingsFor({ claude: "https://evil.example/phish" }, "claude"), null); // the allow-list holds where the page is opened
  assert.equal(P.settingsFor(Object.create({ claude: PAGES[1] }), "claude"), null); // a page that is only inherited is not the program's
  for (const settings of [undefined, null, "claude", 5, []]) assert.equal(P.settingsFor(settings, "claude"), null, String(settings));
});

test("parseReply refuses a list of checks that is not what the host sends", () => {
  const without = (field) => {
    const copy = { ...CHECK };
    delete copy[field];
    return copy;
  };
  const badItems = [
    null,
    "chatgpt",
    [],
    ...Object.keys(CHECK).map(without),
    { ...CHECK, provider: "" },
    { ...CHECK, provider: 5 },
    { ...CHECK, account: "a b" },
    { ...CHECK, training: "maybe" },
    { ...CHECK, memory: true },
    { ...CHECK, source: null },
    { ...CHECK, checked_at: 20261001 },
    { ...CHECK, due: "yes" },
    { ...CHECK, settings_url: "http://chatgpt.com/" },
    { ...CHECK, settings_url: "javascript:alert(1)" },
    { ...CHECK, settings_url: "not a url" },
    { ...CHECK, settings_url: 5 },
  ];
  for (const item of badItems) assert.equal(P.parseReply(checksReply(item), "checks").ok, false, JSON.stringify(item));
  const good = checksReply(CHECK);
  const badReplies = [
    { ok: true },
    { ...good, checks: "none" },
    { ...good, checks: { 0: CHECK } },
    { ...good, providers: "chatgpt" },
    { ...good, providers: ["chatgpt", 5] },
    { ...good, providers: ["a b"] },
    { ...good, note: undefined },
    { ...good, note: 5 },
  ];
  for (const reply of badReplies) assert.equal(P.parseReply(reply, "checks").ok, false, JSON.stringify(reply));
});

test("a damaged checks file gets its own sentence, which says what it means for the chats and how to repair it", () => {
  const reply = P.parseReply({ ok: false, error: "checks unreadable" }, "checks");
  assert.equal(reply.ok, false);
  assert.match(reply.error, /training/i);
  assert.match(reply.error, /\.$/);
  assert.match(reply.error, /boxed check reset/); // the command the program names too, which keeps the file
  assert.doesNotMatch(reply.error, /Delete checks\.json/);
  assert.notEqual(reply.error, P.parseReply({ ok: false, error: "something new" }, "checks").error);
});

test("describeObserved says what was found, or why nothing was", () => {
  const entry = (props) => ({ site: "claude", time: 1761000000000, found: { EMAIL: 2, PHONE: 1 }, coverage: "checked", ...props });
  assert.equal(P.describeObserved(entry({})), "EMAIL 2, PHONE 1");
  assert.equal(P.describeObserved(entry({ found: {} })), "nothing found");
  assert.match(P.describeObserved(entry({ found: null })), /^not recorded/);
  assert.match(P.describeObserved(entry({ coverage: "not checked", found: {} })), /^not checked/);
  assert.match(P.describeObserved(entry({ coverage: "not checked", found: null })), /^not checked/); // the gap matters more than the missing answer
  const odd = [
    null,
    undefined,
    "x",
    5,
    [],
    {},
    entry({ site: "bing" }),
    entry({ coverage: "full" }),
    entry({ found: [1] }),
    entry({ found: { EMAIL: "2" } }),
    entry({ time: "now" }),
  ];
  for (const value of odd) assert.equal(P.describeObserved(value), null, JSON.stringify(value));
});

test("describeCheck gives the two settings and when they were recorded", () => {
  const check = { provider: "chatgpt", account: "personal", training: "off", memory: "unknown", source: "asked", checkedAt: "2026-10-01", due: false, settingsUrl: null };
  assert.equal(P.describeCheck(check), "Training off, memory unknown. Checked 2026-10-01 (asked).");
  assert.equal(P.describeCheck({ ...check, training: "unknown", memory: "on" }), "Training unknown, memory on. Checked 2026-10-01 (asked).");
});
