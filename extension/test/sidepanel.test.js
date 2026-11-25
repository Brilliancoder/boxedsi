"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const v8 = require("node:v8");
const vm = require("node:vm");

const P = require("../lib/protocol.js");

const EXTENSION = path.join(__dirname, "..");
const HTML = fs.readFileSync(path.join(EXTENSION, "sidepanel.html"), "utf8");
const SCRIPT = fs.readFileSync(path.join(EXTENSION, "sidepanel.js"), "utf8");
const clone = (value) => JSON.parse(JSON.stringify(value));
// Everything here is promises that settle without timers, so one turn of the event loop lets all of it finish.
const settle = () => new Promise((resolve) => setImmediate(resolve));

// Just enough of the DOM for the panel: elements with the ids and starting state of sidepanel.html, text that
// belongs to the element or its children, attributes, and listeners that a test can fire.
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = {};
    this.attrs = {};
    this._text = "";
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.value = "";
    this.options = []; // for a <select> written in the HTML: the values of its options
    this.className = "";
    this.tabIndex = 0;
    this.type = "";
  }
  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join("");
  }
  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }
  // the panel shows everything as text; a page, the program or the storage must never be able to inject markup
  set innerHTML(_) {
    throw new Error("innerHTML is not used by the panel");
  }
  set outerHTML(_) {
    throw new Error("outerHTML is not used by the panel");
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes) {
    this._text = "";
    this.children = nodes;
    if (this.tagName === "SELECT") this.value = nodes.length ? nodes[0].value : ""; // a browser selects the first option again
  }
  setAttribute(name, value) {
    this.attrs[name] = String(value);
  }
  removeAttribute(name) {
    delete this.attrs[name];
  }
  addEventListener(type, listener) {
    (this.listeners[type] ||= []).push(listener);
  }
  focus() {}
  async fire(type, event = {}) {
    for (const listener of this.listeners[type] || []) await listener({ type, preventDefault() {}, ...event });
  }
  find(tag) {
    return this.children.flatMap((child) => [...(child.tagName === tag.toUpperCase() ? [child] : []), ...child.find(tag)]);
  }
}

function buildDom() {
  const elements = {};
  for (const [, tag, attrs] of HTML.matchAll(/<(\w+)\b([^>]*)>/g)) {
    const id = /\bid="([a-z-]+)"/.exec(attrs);
    if (!id) continue;
    const el = new El(tag);
    for (const [, name, value] of attrs.matchAll(/([a-z-]+)="([^"]*)"/g)) el.attrs[name] = value;
    el.hidden = /(^|\s)hidden(\s|$)/.test(attrs);
    el.disabled = /(^|\s)disabled(\s|$)/.test(attrs);
    elements[id[1]] = el;
  }
  // a browser shows the option marked selected, or else the first, and a <select> reads as that option's value
  for (const [, id, inner] of HTML.matchAll(/<select\b[^>]*\bid="([a-z-]+)"[^>]*>([\s\S]*?)<\/select>/g)) {
    const options = [...inner.matchAll(/<option\b([^>]*)>/g)].map(([, attrs]) => ({
      value: /\bvalue="([^"]*)"/.exec(attrs)[1],
      selected: /(^|\s)selected(\s|$)/.test(attrs),
    }));
    elements[id].options = options.map((option) => option.value);
    elements[id].value = (options.find((option) => option.selected) || options[0] || { value: "" }).value;
  }
  return elements;
}

function area(store) {
  return {
    async get(keys) {
      const wanted = typeof keys === "string" ? { [keys]: undefined } : keys;
      const result = {};
      for (const [key, fallback] of Object.entries(wanted)) {
        if (Object.hasOwn(store, key)) result[key] = clone(store[key]);
        else if (fallback !== undefined) result[key] = clone(fallback);
      }
      return result;
    },
    async set(items) {
      for (const [key, value] of Object.entries(items)) store[key] = clone(value);
    },
  };
}

const NOTE = "Training off does not mean nothing is stored: providers still keep chats for a while.";
const PROVIDERS = ["chatgpt", "claude", "gemini", "deepseek", "zai"];
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
const DUE = { ...CHECK, provider: "deepseek", account: "me@example.com", training: "unknown", due: true, settings_url: null };
// the three pages of data controls the panel may open, and the program's list of them for the five chats
const PAGES = ["https://chatgpt.com/#settings/DataControls", "https://claude.ai/settings/data-privacy-controls", "https://myactivity.google.com/product/gemini"];
const SETTINGS = { chatgpt: PAGES[0], claude: PAGES[1], gemini: PAGES[2], deepseek: null, zai: null };
const checksReply = (checks = [], providers = PROVIDERS, note = NOTE, settings = SETTINGS) => ({ ok: true, checks, providers, note, settings });

// Opens the real panel on the fake DOM. env.replies answers the host by command: a value, or a function that returns or throws one
// (a throw is the program going away: on a single message it fails the call, on a port the browser disconnects it).
// Messages go to the host two ways, as in the browser: sendNativeMessage (env.oneShot lists their commands) and
// connectNative (env.ports holds each port opened, with what was posted to it). Time is the test's: env.advance(ms) moves the
// clock and runs the timers that fall due.
async function openPanel({ local = {}, session = {}, replies = {} } = {}) {
  const dom = buildDom();
  const env = {
    $: (id) => dom[id],
    local: clone(local),
    session: clone(session),
    sent: [],
    created: [],
    changeListeners: [],
    saveFails: false,
    tabs: [], // what chrome.tabs.query gives: the active tab of the window, with a url only where the extension may see it
    injection: [{ result: "inserted" }], // what the inserter returns from the page
    injected: [],
    copied: [],
    copyFails: false,
    oneShot: [],
    ports: [],
    unchecked: [], // errors of the browser that the panel left unread
    watch: [], // weak references to the messages and answers that crossed a port
    timers: [],
    now: 0,
    windowListeners: {},
    replies: { ping: { ok: true, version: "0.1.0" }, checks: checksReply(), "check-set": { ok: true }, ...replies },
  };
  let nextTimer = 1;
  const fakeSetTimeout = (fn, ms) => {
    const id = nextTimer++;
    env.timers.push({ id, fn, at: env.now + ms });
    return id;
  };
  const fakeClearTimeout = (id) => {
    env.timers = env.timers.filter((timer) => timer.id !== id);
  };
  env.advance = async (ms) => {
    const end = env.now + ms;
    for (;;) {
      const due = env.timers.filter((timer) => timer.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      env.timers = env.timers.filter((timer) => timer !== due);
      env.now = due.at;
      due.fn();
      await settle();
    }
    env.now = end;
    await settle();
  };
  const answerFor = (message) => {
    const reply = env.replies[message.cmd];
    return typeof reply === "function" ? reply(message) : reply;
  };
  const localArea = area(env.local);
  const chrome = {
    runtime: {
      id: "a".repeat(32),
      // the browser logs an error that nobody read; here it is noted
      get lastError() {
        env.lastErrorRead = true;
        return env.lastError;
      },
      async sendNativeMessage(host, message) {
        env.sent.push(clone(message));
        env.oneShot.push(message.cmd);
        return answerFor(message);
      },
      // A native messaging port as the browser has it: a posted message goes to the one process of the program, its answer
      // arrives on onMessage, and a program that exits arrives on onDisconnect with runtime.lastError set. After the page's own
      // disconnect() nothing more is delivered.
      connectNative(host) {
        const port = { host, posted: [], disconnected: false, onMessage: [], onDisconnect: [] };
        env.ports.push(port);
        const lost = (message) => {
          if (port.disconnected) return;
          port.disconnected = true;
          env.lastError = { message };
          env.lastErrorRead = false;
          for (const listener of port.onDisconnect) listener();
          if (!env.lastErrorRead) env.unchecked.push(message);
          env.lastError = undefined;
        };
        port.exit = () => lost("Native host has exited."); // the program ends on its own
        return {
          name: host,
          onMessage: { addListener: (listener) => port.onMessage.push(listener) },
          onDisconnect: { addListener: (listener) => port.onDisconnect.push(listener) },
          postMessage(message) {
            if (port.disconnected) throw new Error("Attempting to use a disconnected port object");
            env.watch.push(new WeakRef(message));
            port.posted.push(clone(message));
            env.sent.push(clone(message));
            Promise.resolve()
              .then(() => answerFor(clone(message)))
              .then(
                (answer) => {
                  if (port.disconnected) return;
                  const value = answer === undefined ? undefined : clone(answer);
                  if (value !== undefined) env.watch.push(new WeakRef(value));
                  for (const listener of port.onMessage) listener(value);
                },
                (error) => lost(error.message),
              );
          },
          disconnect() {
            port.disconnected = true;
          },
        };
      },
    },
    storage: {
      local: {
        ...localArea,
        async set(items) {
          if (env.saveFails) throw new Error("storage unavailable");
          return localArea.set(items);
        },
      },
      session: area(env.session),
      onChanged: { addListener: (listener) => env.changeListeners.push(listener) },
    },
    tabs: {
      async query() {
        return clone(env.tabs);
      },
      async create(options) {
        env.created.push(clone(options));
      },
    },
    scripting: {
      async executeScript(injection) {
        env.injected.push(injection);
        return env.injection;
      },
    },
  };
  const document = {
    getElementById: (id) => dom[id] || null,
    createElement: (tag) => new El(tag),
  };
  const store = {};
  const localStorage = { getItem: (key) => store[key] ?? null, setItem: (key, value) => void (store[key] = String(value)) };
  const win = { addEventListener: (type, listener) => (env.windowListeners[type] ||= []).push(listener) };
  new Function("document", "chrome", "boxedProtocol", "localStorage", "navigator", "setTimeout", "clearTimeout", "window", SCRIPT)(
    document,
    chrome,
    P,
    localStorage,
    {
      clipboard: {
        async writeText(text) {
          if (env.copyFails) throw new Error("denied");
          env.copied.push(text);
        },
      },
    },
    fakeSetTimeout,
    fakeClearTimeout,
    win,
  );
  env.pagehide = () => (env.windowListeners.pagehide || []).forEach((listener) => listener({ type: "pagehide" })); // the panel is closed
  env.changed = (changes, areaName) => env.changeListeners.forEach((listener) => listener(changes, areaName));
  env.openObserve = async () => {
    await dom["tab-observe"].fire("click");
    await settle();
  };
  await settle();
  return env;
}

const rows = (list) => list.children;
const buttons = (row) => row.find("button");

test("the switch shows the stored state, and only exactly true is on", async () => {
  const expected = [[{}, false], [{ observe: false }, false], [{ observe: "true" }, false], [{ observe: 1 }, false], [{ observe: true }, true]];
  for (const [local, on] of expected) {
    const env = await openPanel({ local });
    assert.equal(env.$("observe-on").checked, on, JSON.stringify(local));
  }
});

test("turning the switch on or off is written to storage, exactly", async () => {
  const env = await openPanel();
  env.$("observe-on").checked = true;
  await env.$("observe-on").fire("change");
  assert.equal(env.local.observe, true);
  env.$("observe-on").checked = false;
  await env.$("observe-on").fire("change");
  assert.equal(env.local.observe, false);
});

test("a switch the browser cannot save goes back and says so", async () => {
  const env = await openPanel();
  env.saveFails = true;
  env.$("observe-on").checked = true;
  await env.$("observe-on").fire("change");
  assert.equal(env.$("observe-on").checked, false);
  assert.equal(env.$("notice").className, "notice bad");
  assert.match(env.$("notice").textContent, /switch/i);
});

test("the results list shows each stored result, newest first, and skips what is not a result", async () => {
  const session = {
    observed: [
      { site: "claude", time: 1761000002000, found: { EMAIL: 2, PHONE: 1 }, coverage: "checked" },
      "damaged",
      { site: "gemini", time: 1761000001000, found: {}, coverage: "checked" },
      { site: "zai", time: 1761000000000, found: null, coverage: "not checked" },
    ],
  };
  const env = await openPanel({ session });
  const items = rows(env.$("observed"));
  assert.equal(items.length, 3);
  assert.match(items[0].textContent, /claude: EMAIL 2, PHONE 1$/);
  assert.match(items[1].textContent, /gemini: nothing found$/);
  assert.match(items[2].textContent, /zai: not checked/);
  assert.equal(env.$("observed-empty").hidden, true);
});

test("the results list says so when it is empty and follows the session storage", async () => {
  const env = await openPanel();
  assert.equal(rows(env.$("observed")).length, 0);
  assert.equal(env.$("observed-empty").hidden, false);
  const entry = { site: "deepseek", time: 1761000000000, found: { SECRET: 1 }, coverage: "checked" };
  env.changed({ observed: { newValue: [entry] } }, "session");
  assert.equal(rows(env.$("observed")).length, 1);
  assert.match(rows(env.$("observed"))[0].textContent, /deepseek: SECRET 1/);
  assert.equal(env.$("observed-empty").hidden, true);
  env.changed({ observed: { newValue: [] } }, "local"); // another area
  env.changed({ other: { newValue: [] } }, "session"); // another key
  assert.equal(rows(env.$("observed")).length, 1);
  env.changed({ observed: { newValue: [] } }, "session");
  assert.equal(rows(env.$("observed")).length, 0);
  assert.equal(env.$("observed-empty").hidden, false);
  env.changed({ observed: {} }, "session"); // the key was removed
  assert.equal(rows(env.$("observed")).length, 0);
});

test("the program is asked for the checks when the Observe tab opens, not before", async () => {
  const env = await openPanel();
  assert.deepEqual(env.sent, [{ cmd: "ping" }]);
  await env.openObserve();
  assert.deepEqual(env.sent, [{ cmd: "ping" }, { cmd: "checks" }]);
  assert.equal(env.$("observe").hidden, false);
  assert.equal(env.$("prepare").hidden, true);
  assert.equal(env.$("tab-observe").attrs["aria-selected"], "true");
});

test("each check is listed with its settings, a due mark only when due, and Open setting only with an address", async () => {
  const env = await openPanel({ replies: { checks: checksReply([CHECK, DUE]) } });
  await env.openObserve();
  const items = rows(env.$("checks"));
  assert.equal(items.length, 2);
  assert.match(items[0].textContent, /chatgpt - personal/);
  assert.match(items[0].textContent, /Training off, memory unknown\. Checked 2026-10-01 \(asked\)\./);
  assert.doesNotMatch(items[0].textContent, /Check again/);
  assert.match(items[1].textContent, /deepseek - me@example\.com/);
  assert.match(items[1].textContent, /Check again/);
  assert.equal(buttons(items[0]).length, 1);
  assert.equal(buttons(items[0])[0].textContent, "Open setting");
  assert.equal(buttons(items[1]).length, 0);
  assert.equal(env.$("checks-note").textContent, NOTE);
  assert.equal(env.$("checks-status").hidden, true);
});

test("Open setting opens the address the program gave, in a new tab", async () => {
  const env = await openPanel({ replies: { checks: checksReply([CHECK]) } });
  await env.openObserve();
  await buttons(rows(env.$("checks"))[0])[0].fire("click");
  assert.deepEqual(env.created, [{ url: "https://chatgpt.com/#settings/DataControls" }]);
});

test("before any check is saved, Open setting for the chosen chat uses the program's list of pages", async () => {
  const env = await openPanel();
  assert.equal(env.$("check-open").hidden, true); // nothing is known before the program has answered
  await env.openObserve();
  assert.equal(rows(env.$("checks")).length, 0); // and no check is saved
  assert.equal(env.$("check-provider").value, "chatgpt");
  assert.equal(env.$("check-open").hidden, false);
  await env.$("check-open").fire("click");
  assert.deepEqual(env.created, [{ url: PAGES[0] }]);
  env.$("check-provider").value = "claude";
  await env.$("check-provider").fire("change");
  assert.equal(env.$("check-open").hidden, false);
  await env.$("check-open").fire("click");
  assert.deepEqual(env.created, [{ url: PAGES[0] }, { url: PAGES[1] }]);
  env.$("check-provider").value = "deepseek"; // the program knows no page for it
  await env.$("check-provider").fire("change");
  assert.equal(env.$("check-open").hidden, true);
});

test("a reply that names a page outside the three is refused as a whole: no rows, no Open setting, nothing opened", async () => {
  const evilRow = { ...CHECK, settings_url: "https://evil.example/phish" };
  const evilList = { ...SETTINGS, claude: "https://evil.example/phish" };
  for (const checks of [checksReply([evilRow]), checksReply([], PROVIDERS, NOTE, evilList)]) {
    const env = await openPanel({ replies: { checks } });
    await env.openObserve();
    assert.equal(rows(env.$("checks")).length, 0);
    assert.match(env.$("checks-status").textContent, /cannot read/);
    assert.equal(env.$("check-open").hidden, true);
    assert.deepEqual(env.created, []);
  }
});

test("with nothing recorded yet the list says so and keeps the note", async () => {
  const env = await openPanel();
  await env.openObserve();
  assert.equal(rows(env.$("checks")).length, 0);
  assert.equal(env.$("checks-status").hidden, false);
  assert.match(env.$("checks-status").textContent, /nothing recorded/i);
  assert.equal(env.$("checks-note").textContent, NOTE);
});

test("a program that cannot be reached, or a damaged checks file, shows the sentence and no rows", async () => {
  const gone = () => {
    throw new Error("Specified native messaging host not found.");
  };
  const env = await openPanel({ replies: { checks: gone } });
  await env.openObserve();
  assert.equal(rows(env.$("checks")).length, 0);
  assert.match(env.$("checks-status").textContent, /not registered/);
  assert.equal(env.$("checks-status").hidden, false);

  const damaged = await openPanel({ replies: { checks: { ok: false, error: "checks unreadable" } } });
  await damaged.openObserve();
  assert.equal(rows(damaged.$("checks")).length, 0);
  assert.match(damaged.$("checks-status").textContent, /every provider counts as training/);
  assert.match(damaged.$("checks-status").textContent, /Run boxed check reset in a terminal/);
  assert.doesNotMatch(damaged.$("checks-status").textContent, /Delete checks\.json/);
});

test("a reload that fails replaces the old list with the reason", async () => {
  let up = true;
  const env = await openPanel({
    replies: {
      checks: () => {
        if (up) return checksReply([CHECK]);
        throw new Error("Native host has exited.");
      },
    },
  });
  await env.openObserve();
  assert.equal(rows(env.$("checks")).length, 1);
  assert.equal(env.$("check-open").hidden, false);
  up = false;
  await env.openObserve();
  assert.equal(rows(env.$("checks")).length, 0);
  assert.equal(env.$("checks-status").hidden, false);
  assert.equal(env.$("checks-status").className, "hint bad");
  assert.equal(env.$("checks-note").textContent, "");
  assert.equal(env.$("check-open").hidden, true); // no list of pages to go by any more
});

test("when two answers for the list cross, the newer request decides what is shown", async () => {
  const gates = [];
  const env = await openPanel({ replies: { checks: () => new Promise((resolve) => gates.push(resolve)) } });
  await env.$("tab-observe").fire("click"); // request 1
  await env.$("tab-observe").fire("click"); // request 2
  await settle();
  assert.equal(gates.length, 2);
  gates[1](checksReply([DUE])); // the newer answer comes first ...
  await settle();
  gates[0](checksReply([CHECK])); // ... the older one after it
  await settle();
  assert.equal(rows(env.$("checks")).length, 1);
  assert.match(rows(env.$("checks"))[0].textContent, /deepseek/);
});

test("what the program sends is shown as text", async () => {
  const markup = "<img src=x onerror=alert(1)>";
  const env = await openPanel({ replies: { checks: checksReply([CHECK], PROVIDERS, markup) } });
  await env.openObserve();
  assert.equal(env.$("checks-note").textContent, markup);
});

test("the chat choice of the form comes from the program's list", async () => {
  const env = await openPanel();
  assert.deepEqual(env.$("check-provider").children.map((o) => o.value), PROVIDERS); // before the program has answered
  await env.openObserve();
  assert.deepEqual(env.$("check-provider").children.map((o) => o.value), PROVIDERS);
  const own = await openPanel({ replies: { checks: checksReply([], ["claude", "zai"]) } });
  own.$("check-provider").value = "zai";
  await own.openObserve();
  assert.deepEqual(own.$("check-provider").children.map((o) => o.value), ["claude", "zai"]);
  assert.equal(own.$("check-provider").value, "zai"); // the choice survives the reload
});

function fill(env, { provider = "claude", account = "me@example.com", training = "off", memory = "unknown" } = {}) {
  env.$("check-provider").value = provider;
  env.$("check-account").value = account;
  env.$("check-training").value = training;
  env.$("check-memory").value = memory;
}

test("Save sends the check as the contract has it, then lists the checks again", async () => {
  const env = await openPanel();
  await env.openObserve();
  fill(env, { account: "  me@example.com " });
  await env.$("check-form").fire("submit");
  await settle();
  assert.deepEqual(env.sent.slice(2), [
    { cmd: "check-set", provider: "claude", account: "me@example.com", training: "off", memory: "unknown" },
    { cmd: "checks" },
  ]);
  assert.equal(env.$("notice").textContent, "Saved.");
  assert.equal(env.$("notice").className, "notice");
});

test("Save with a bad account says what is allowed and sends nothing", async () => {
  const env = await openPanel();
  await env.openObserve();
  fill(env, { account: "my account" });
  await env.$("check-form").fire("submit");
  await settle();
  assert.deepEqual(env.sent, [{ cmd: "ping" }, { cmd: "checks" }]);
  assert.equal(env.$("notice").className, "notice bad");
  assert.match(env.$("notice").textContent, /^Account:/);
});

test("a program that refuses the save is shown as such, and the list is not reloaded", async () => {
  const env = await openPanel({ replies: { "check-set": { ok: false, error: "checks unreadable" } } });
  await env.openObserve();
  fill(env);
  await env.$("check-form").fire("submit");
  await settle();
  assert.deepEqual(env.sent.map((m) => m.cmd), ["ping", "checks", "check-set"]);
  assert.equal(env.$("notice").className, "notice bad");
  assert.match(env.$("notice").textContent, /every provider counts as training/);
  assert.match(env.$("notice").textContent, /Run boxed check reset in a terminal/);
  assert.equal(env.$("check-save").disabled, false); // the button is usable again
});

test("the arrow keys walk through all three tabs and wrap round", async () => {
  const env = await openPanel();
  await env.$("tab-restore").fire("keydown", { key: "ArrowRight" });
  await settle();
  assert.equal(env.$("tab-observe").attrs["aria-selected"], "true");
  assert.equal(env.$("observe").hidden, false);
  assert.deepEqual(env.sent.map((m) => m.cmd), ["ping", "checks"]);
  await env.$("tab-observe").fire("keydown", { key: "ArrowRight" });
  assert.equal(env.$("tab-prepare").attrs["aria-selected"], "true");
  await env.$("tab-prepare").fire("keydown", { key: "ArrowLeft" });
  assert.equal(env.$("tab-observe").attrs["aria-selected"], "true");
  await env.$("tab-observe").fire("keydown", { key: "Tab" }); // other keys do nothing
  assert.equal(env.$("tab-observe").attrs["aria-selected"], "true");
});

// Prepare: the level.

test("the level list offers 0, 1 and 2, no more, and starts on 2", async () => {
  const env = await openPanel();
  assert.deepEqual(env.$("level").options, ["0", "1", "2"]);
  assert.equal(env.$("level").value, "2");
});

test("Mask sends the level the person chose, and 2 when they chose nothing", async () => {
  const mask = { ok: true, text: "mail [EMAIL_1]", scope: "web-test", markers_by_kind: { EMAIL: 1 } };
  for (const [choice, level] of [[undefined, 2], ["0", 0], ["1", 1], ["2", 2]]) {
    const env = await openPanel({ replies: { mask } });
    env.$("input").value = "mail a@b.io";
    if (choice !== undefined) env.$("level").value = choice;
    await env.$("mask").fire("click");
    const sent = env.sent.filter((message) => message.cmd === "mask");
    assert.equal(sent.length, 1, String(choice));
    assert.equal(sent[0].level, level, String(choice));
    assert.equal(sent[0].text, "mail a@b.io", String(choice));
  }
});

// Copy and Insert. The manifest has neither clipboardWrite nor activeTab: Copy writes from the click on its button, and
// Insert reaches the tab through the host permissions of the five chats, which also show the tab's address.

const MASK_REPLY = { ok: true, text: "mail [EMAIL_1]", scope: "web-test", markers_by_kind: { EMAIL: 1 } };

async function maskedPanel() {
  const env = await openPanel({ replies: { mask: MASK_REPLY } });
  env.$("input").value = "mail a@b.io";
  await env.$("mask").fire("click");
  return env;
}

test("Copy writes the masked text to the clipboard from the click on its button", async () => {
  const env = await maskedPanel();
  assert.equal(env.$("copy-masked").disabled, false);
  await env.$("copy-masked").fire("click");
  assert.deepEqual(env.copied, ["mail [EMAIL_1]"]);
  assert.equal(env.$("notice").textContent, "Copied.");
  assert.equal(env.$("notice").className, "notice");
});

test("Copy of the restored text writes it the same way", async () => {
  const env = await openPanel({ replies: { restore: { ok: true, text: "mail a@b.io", unknown: [], suspicious: [] } } });
  env.$("answer").value = "mail [EMAIL_1]";
  await env.$("run-restore").fire("click");
  await env.$("copy-restored").fire("click");
  assert.deepEqual(env.copied, ["mail a@b.io"]);
  assert.equal(env.$("notice").textContent, "Copied.");
});

test("a copy the browser refuses is said so", async () => {
  const env = await maskedPanel();
  env.copyFails = true;
  await env.$("copy-masked").fire("click");
  assert.deepEqual(env.copied, []);
  assert.equal(env.$("notice").className, "notice bad");
  assert.match(env.$("notice").textContent, /copying/);
});

test("Insert runs the inserter with the masked text in the open tab of a chat, and says so", async () => {
  const env = await maskedPanel();
  env.tabs = [{ id: 7, url: "https://claude.ai/new" }];
  await env.$("insert").fire("click");
  assert.equal(env.injected.length, 1);
  assert.deepEqual(env.injected[0].target, { tabId: 7 });
  assert.equal(env.injected[0].func, P.insertIntoActiveInput);
  assert.deepEqual(env.injected[0].args, ["mail [EMAIL_1]"]);
  assert.equal(env.$("notice").textContent, "Inserted. Check the text, then press Send yourself.");
  assert.equal(env.$("notice").className, "notice");
});

test("Insert injects nothing into a tab that is not a chat or whose address the browser does not show", async () => {
  const noTab = [];
  const noAddress = [{ id: 7 }]; // what the browser gives for a page the extension has no permission for
  const other = [{ id: 7, url: "https://example.com/" }];
  const lookalike = [{ id: 7, url: "https://claude.ai.evil.example/" }];
  for (const tabs of [noTab, noAddress, other, lookalike]) {
    const env = await maskedPanel();
    env.tabs = tabs;
    await env.$("insert").fire("click");
    assert.deepEqual(env.injected, [], JSON.stringify(tabs));
    assert.equal(env.$("notice").className, "notice bad");
    assert.match(env.$("notice").textContent, /Open ChatGPT, Claude, Gemini, DeepSeek or Z\.ai in this window first/);
  }
});

test("Insert tells what the page did, and a page it could not reach", async () => {
  const outcomes = [
    ["no-input", /Click into the chat box first/, true],
    ["not-an-input", /not a text box/, true],
    ["failed", /did not take the text/, true],
    ["something new", /did not take the text/, true],
  ];
  for (const [result, message, bad] of outcomes) {
    const env = await maskedPanel();
    env.tabs = [{ id: 7, url: "https://chatgpt.com/c/1" }];
    env.injection = [{ result }];
    await env.$("insert").fire("click");
    assert.match(env.$("notice").textContent, message, result);
    assert.equal(env.$("notice").className, bad ? "notice bad" : "notice", result);
  }
  const env = await maskedPanel();
  env.tabs = [{ id: 7, url: "https://chatgpt.com/c/1" }];
  env.injection = Promise.reject(new Error("Cannot access contents of the page."));
  env.injection.catch(() => {});
  await env.$("insert").fire("click");
  assert.match(env.$("notice").textContent, /Could not reach the page/);
  assert.equal(env.$("notice").className, "notice bad");
});

// The port. Mask and Restore share one port to the program for as long as the panel is used, so that the program starts, and loads
// the language model for names, once. It closes after 60 seconds without a request and when the panel closes, and the program
// ends with it. Nothing of a request or its answer stays behind in the panel.

const RESTORE_REPLY = { ok: true, text: "mail a@b.io", unknown: [], suspicious: [] };
const BOTH = { mask: MASK_REPLY, restore: RESTORE_REPLY };

// A click that waits for an answer which never comes would keep its test, and the whole run, waiting for ever. Give up after a
// moment of real time and say what was waited for, so that a panel that lost its listener or its timer fails the test.
function soon(promise, what) {
  let timer;
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`still waiting for ${what}`)), 2000);
  });
  return Promise.race([promise, late]).finally(() => clearTimeout(timer));
}

async function pressMask(env) {
  env.$("input").value = "mail a@b.io";
  await soon(env.$("mask").fire("click"), "the answer to Mask");
}

async function pressRestore(env) {
  env.$("answer").value = "mail [EMAIL_1]";
  await soon(env.$("run-restore").fire("click"), "the answer to Restore");
}

const posted = (port) => port.posted.map((message) => message.cmd);

test("Mask and Restore share one port, which the first of them opens", async () => {
  const env = await openPanel({ replies: BOTH });
  assert.equal(env.ports.length, 0); // opening the panel needs none
  await pressMask(env);
  await pressMask(env);
  await pressRestore(env);
  await pressMask(env);
  assert.equal(env.ports.length, 1);
  assert.equal(env.ports[0].host, "si.boxed.host");
  assert.deepEqual(posted(env.ports[0]), ["mask", "mask", "restore", "mask"]);
  assert.equal(env.ports[0].disconnected, false);
  assert.equal(env.$("masked").value, "mail [EMAIL_1]"); // and the answers reach the screen as before
  assert.equal(env.$("restored").value, "mail a@b.io");
  assert.equal(env.$("notice").className, "notice");
});

test("the status check, the list of checks and Save stay single messages: they need no language model", async () => {
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  await env.openObserve();
  fill(env);
  await env.$("check-form").fire("submit");
  await settle();
  assert.deepEqual(env.oneShot, ["ping", "checks", "check-set", "checks"]);
  assert.deepEqual(posted(env.ports[0]), ["mask"]);
});

test("the port closes after 60 seconds without a request, not before, and nothing is left running", async () => {
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  await env.advance(59999);
  assert.equal(env.ports[0].disconnected, false);
  await env.advance(1);
  assert.equal(env.ports[0].disconnected, true);
  assert.deepEqual(env.timers, []);
});

test("every request starts the 60 seconds again", async () => {
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  await env.advance(40000);
  await pressRestore(env); // 40 seconds after the first
  await env.advance(59999); // 99.999 seconds after the first, 59.999 after the second
  assert.equal(env.ports[0].disconnected, false);
  await env.advance(1);
  assert.equal(env.ports[0].disconnected, true);
  assert.equal(env.ports.length, 1);
});

test("a program that is busy is not idle: the port stays open however long the answer takes", async () => {
  const gates = [];
  let calls = 0;
  const env = await openPanel({ replies: { mask: () => (++calls === 1 ? MASK_REPLY : new Promise((resolve) => gates.push(resolve))) } });
  await pressMask(env); // a quick one first: its 60 seconds are running
  await env.advance(30000);
  env.$("input").value = "a long text";
  const click = env.$("mask").fire("click");
  await settle();
  await env.advance(90000); // the first clock would have run out 60 seconds in
  assert.equal(env.ports[0].disconnected, false);
  gates[0](MASK_REPLY);
  await soon(click, "the answer to the long Mask");
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
  await env.advance(59999); // the 60 seconds count from the answer
  assert.equal(env.ports[0].disconnected, false);
  await env.advance(1);
  assert.equal(env.ports[0].disconnected, true);
});

test("a request after the port closed for idleness opens a new one", async () => {
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  await env.advance(60000);
  await pressMask(env);
  assert.equal(env.ports.length, 2);
  assert.equal(env.ports[0].disconnected, true);
  assert.equal(env.ports[1].disconnected, false);
  assert.deepEqual(posted(env.ports[1]), ["mask"]);
  assert.equal(env.$("notice").className, "notice");
});

test("closing the panel closes the port", async () => {
  const env = await openPanel({ replies: BOTH });
  assert.equal((env.windowListeners.pagehide || []).length, 1);
  await pressMask(env);
  env.pagehide();
  assert.equal(env.ports[0].disconnected, true);
  assert.deepEqual(env.timers, []);
  env.pagehide(); // nothing is open any more: nothing happens
  assert.equal(env.ports.length, 1);
});

test("closing the panel while the program works closes the port and leaves no request waiting", async () => {
  const env = await openPanel({ replies: { mask: () => new Promise(() => {}) } });
  env.$("input").value = "mail a@b.io";
  const click = env.$("mask").fire("click");
  await settle();
  env.pagehide();
  await soon(click, "the click to return once the panel is closed"); // its request was ended with the port
  assert.equal(env.ports[0].disconnected, true);
  assert.equal(env.$("masked").value, "");
  assert.deepEqual(env.timers, []); // and no clock is left to give up a request that is gone
});

test("a program that exits between two requests is started again by the next one", async () => {
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  env.ports[0].exit();
  assert.deepEqual(env.unchecked, []); // the browser's error is read, not left to be logged
  assert.deepEqual(env.timers, []);
  await pressMask(env);
  assert.equal(env.ports.length, 2);
  assert.equal(env.$("notice").className, "notice");
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
});

test("a program that exits while it works gives the sentence for that, and the next request starts it again", async () => {
  const env = await openPanel({
    replies: {
      mask: () => {
        throw new Error("Native host has exited.");
      },
    },
  });
  await pressMask(env);
  assert.equal(env.$("notice").className, "notice bad");
  assert.match(env.$("notice").textContent, /exited before it answered/);
  assert.equal(env.ports[0].disconnected, true);
  assert.deepEqual(env.unchecked, []);
  assert.deepEqual(env.timers, []);
  assert.equal(env.$("mask").disabled, false);
  env.replies.mask = MASK_REPLY; // it is back
  await pressMask(env);
  assert.equal(env.ports.length, 2);
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
});

test("a program that is not registered says so, as it did on a single message", async () => {
  const env = await openPanel({
    replies: {
      mask: () => {
        throw new Error("Specified native messaging host not found.");
      },
    },
  });
  await pressMask(env);
  assert.match(env.$("notice").textContent, /not registered with this browser/);
  assert.match(env.$("notice").textContent, /boxed install native-host --extension-id a{32}/);
  assert.equal(env.$("notice").className, "notice bad");
});

test("a program that says it cannot start, or that failed, is closed, so that the next request starts it again", async () => {
  for (const error of ["host cannot start", "internal error"]) {
    const env = await openPanel({ replies: { mask: { ok: false, error } } });
    await pressMask(env);
    assert.equal(env.$("notice").className, "notice bad", error);
    assert.equal(env.ports[0].disconnected, true, error);
    assert.deepEqual(env.timers, [], error);
    env.replies.mask = MASK_REPLY; // the setting is mended, the keychain unlocked
    await pressMask(env);
    assert.equal(env.ports.length, 2, error);
    assert.equal(env.$("masked").value, "mail [EMAIL_1]", error);
  }
});

test("an ordinary refusal leaves the port as it is", async () => {
  for (const error of ["unknown scope", "bad request", "reply too large"]) {
    const env = await openPanel({ replies: { restore: { ok: false, error } } });
    await pressRestore(env);
    assert.equal(env.$("notice").className, "notice bad", error);
    assert.equal(env.ports[0].disconnected, false, error);
  }
});

test("requests go to the program one at a time, in the order they were made", async () => {
  const gates = [];
  const env = await openPanel({ replies: { mask: () => new Promise((resolve) => gates.push(resolve)), restore: RESTORE_REPLY } });
  env.$("input").value = "mail a@b.io";
  env.$("answer").value = "mail [EMAIL_1]";
  const first = env.$("mask").fire("click");
  const second = env.$("run-restore").fire("click");
  await settle();
  assert.deepEqual(posted(env.ports[0]), ["mask"]); // the answers carry no number: Restore waits for the answer to Mask
  gates[0](MASK_REPLY);
  await soon(Promise.all([first, second]), "the answers to Mask and Restore");
  assert.deepEqual(posted(env.ports[0]), ["mask", "restore"]);
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
  assert.equal(env.$("restored").value, "mail a@b.io");
  assert.equal(env.ports.length, 1);
});

test("a request that fails does not hold up the ones behind it", async () => {
  const env = await openPanel({ replies: { mask: () => { throw new Error("Native host has exited."); }, restore: RESTORE_REPLY } });
  env.$("input").value = "mail a@b.io";
  env.$("answer").value = "mail [EMAIL_1]";
  await soon(Promise.all([env.$("mask").fire("click"), env.$("run-restore").fire("click")]), "the answers to Mask and Restore");
  assert.equal(env.$("restored").value, "mail a@b.io");
  assert.equal(env.ports.length, 2);
});

// A watchdog: a request the program has not answered after 120 seconds is given up, so that a stuck program does not hold the
// panel (and Restore behind a stuck Mask) until the panel is closed.

const due = (env) => env.timers.map((timer) => timer.at - env.now).sort((a, b) => a - b); // when each running timer falls due, from now

test("a request still unanswered after 120 seconds is given up: the port is closed, the panel says so, the next click starts the program again", async () => {
  const env = await openPanel({ replies: { mask: () => new Promise(() => {}) } }); // a program that never answers
  env.$("input").value = "mail a@b.io";
  const click = env.$("mask").fire("click");
  await settle();
  assert.equal(env.$("mask").disabled, true);
  assert.deepEqual(due(env), [120000]); // the clock of idleness does not run while the program works; this one does
  await env.advance(119999);
  assert.equal(env.ports[0].disconnected, false);
  await env.advance(1);
  await soon(click, "the click to return once the request is given up");
  assert.equal(env.ports[0].disconnected, true); // closing the port is what makes the browser stop the program
  assert.equal(env.$("notice").className, "notice bad");
  assert.equal(
    env.$("notice").textContent,
    "The boxed.si program did not answer in 2 minutes, so it was stopped. Try again, or split the text into smaller parts.",
  );
  assert.equal(env.$("masked").value, "");
  assert.equal(env.$("mask").disabled, false);
  assert.deepEqual(env.timers, []);
  env.replies.mask = MASK_REPLY; // a program that answers
  await pressMask(env);
  assert.equal(env.ports.length, 2);
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
  assert.equal(env.$("notice").className, "notice");
});

test("a request waiting behind a stuck one goes on, on a new port, once the stuck one is given up", async () => {
  const env = await openPanel({ replies: { mask: () => new Promise(() => {}), restore: RESTORE_REPLY } });
  env.$("input").value = "mail a@b.io";
  env.$("answer").value = "mail [EMAIL_1]";
  const mask = env.$("mask").fire("click");
  const restore = env.$("run-restore").fire("click");
  await settle();
  assert.deepEqual(posted(env.ports[0]), ["mask"]); // Restore waits for the answer to Mask
  await env.advance(120000);
  await soon(Promise.all([mask, restore]), "Mask to be given up and Restore to be answered");
  assert.equal(env.ports.length, 2);
  assert.deepEqual(posted(env.ports[1]), ["restore"]);
  assert.equal(env.$("restored").value, "mail a@b.io");
  assert.equal(env.ports[0].disconnected, true);
  assert.equal(env.ports[1].disconnected, false);
});

test("the 120 seconds count from the moment a request is posted to the program, and an answer stops them", async () => {
  const gates = [];
  const env = await openPanel({
    replies: { mask: () => new Promise((resolve) => gates.push(resolve)), restore: () => new Promise((resolve) => gates.push(resolve)) },
  });
  env.$("input").value = "mail a@b.io";
  env.$("answer").value = "mail [EMAIL_1]";
  const mask = env.$("mask").fire("click");
  const restore = env.$("run-restore").fire("click");
  await env.advance(100000); // Mask takes 100 seconds ...
  gates[0](MASK_REPLY);
  await settle();
  assert.deepEqual(posted(env.ports[0]), ["mask", "restore"]);
  assert.deepEqual(due(env), [120000]); // ... and Restore, posted only now, has its own 120 seconds
  await env.advance(119999);
  assert.equal(env.ports[0].disconnected, false);
  gates[1](RESTORE_REPLY);
  await soon(Promise.all([mask, restore]), "both answers");
  assert.deepEqual(due(env), [60000]); // the answer stopped that clock; only the idleness of the port is counted
  assert.equal(env.$("restored").value, "mail a@b.io");
});

test("a program that answers in time is not stopped", async () => {
  const gates = [];
  const env = await openPanel({ replies: { mask: () => new Promise((resolve) => gates.push(resolve)) } });
  env.$("input").value = "mail a@b.io";
  const click = env.$("mask").fire("click");
  await settle();
  await env.advance(119999);
  gates[0](MASK_REPLY);
  await soon(click, "the answer to Mask");
  assert.equal(env.$("masked").value, "mail [EMAIL_1]");
  assert.equal(env.$("notice").className, "notice");
  assert.equal(env.ports[0].disconnected, false);
});

test("nothing of a request or of its answer is kept once the answer has been handed on", async () => {
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc");
  const env = await openPanel({ replies: BOTH });
  await pressMask(env);
  await pressRestore(env);
  await settle();
  gc();
  await settle(); // a WeakRef keeps its target until the turn that made it is over
  gc();
  assert.equal(env.watch.length, 4); // two requests as the panel built them, two answers as the browser handed them over
  assert.deepEqual(env.watch.map((ref) => ref.deref() !== undefined), [false, false, false, false]);
});
