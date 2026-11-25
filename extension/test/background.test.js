"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const v8 = require("node:v8");
const vm = require("node:vm");

const P = require("../lib/protocol.js");
const O = require("../lib/observe.js");

const EXTENSION = path.join(__dirname, "..");
const SOURCE = fs.readFileSync(path.join(EXTENSION, "background.js"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(EXTENSION, "manifest.json"), "utf8"));
const enc = new TextEncoder();
const clone = (value) => JSON.parse(JSON.stringify(value));
// Everything here is promises that settle without timers, so one turn of the event loop lets all of it finish.
const settle = () => new Promise((resolve) => setImmediate(resolve));

// The worker is a module: it imports the two libraries for their side effect and finds them on self. Here the
// imports are taken out, checked to be exactly those two files, and the libraries are handed over as self.
const IMPORT = /^import "\.\/(lib\/[a-z]+\.js)";\n/gm;
function workerBody() {
  assert.deepEqual([...SOURCE.matchAll(IMPORT)].map((m) => m[1]).sort(), ["lib/observe.js", "lib/protocol.js"]);
  const body = SOURCE.replace(IMPORT, "");
  assert.doesNotMatch(body, /^\s*(?:import|export)\b/m); // nothing else would run in a plain function
  return body;
}

// chrome.storage areas as the browser has them: get takes a key, a list, or an object of defaults; values are copied.
function area(store) {
  return {
    async get(keys) {
      const wanted = typeof keys === "string" ? { [keys]: undefined } : Array.isArray(keys) ? Object.fromEntries(keys.map((k) => [k, undefined])) : keys;
      if (keys === null || keys === undefined) return clone(store);
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

// Runs background.js against a stub browser. env.reply answers the host: a value, or a function that returns a value
// (or a promise of one, which may never settle) or throws, which is the program exiting. Time is the test's:
// env.date is what Date.now() says, and env.advance(ms) moves the clock and fires the timers that fall due.
function start({ local = {}, reply = { ok: true, found: {} }, protocol = P } = {}) {
  const env = {
    local: clone(local),
    session: {},
    sent: [],
    logged: [],
    panel: [],
    registrations: [],
    ports: [],
    unchecked: [], // errors of the browser that the worker left unread
    reply,
    inFlight: 0,
    maxInFlight: 0,
    localBroken: false, // reading the switch fails
    connectThrows: false, // connectNative throws, as it does for a host name it does not accept
    postThrows: false, // postMessage throws, as it does on a port that is already closed
    sessionSetFailures: 0, // this many writes of the results fail
    date: 1761000000000,
    now: 0,
    timers: [],
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
      env.date += due.at - env.now;
      env.now = due.at;
      due.fn();
      await settle();
    }
    env.date += end - env.now;
    env.now = end;
    await settle();
  };
  const localArea = area(env.local);
  const sessionArea = area(env.session);
  const chrome = {
    sidePanel: {
      async setPanelBehavior(behavior) {
        env.panel.push(clone(behavior));
      },
    },
    webRequest: {
      onBeforeRequest: {
        addListener(listener, filter, extra) {
          env.registrations.push({ listener, filter: clone(filter), extra: clone(extra) });
        },
      },
    },
    storage: {
      local: {
        ...localArea,
        async get(keys) {
          if (env.localBroken) throw new Error("storage unavailable");
          return localArea.get(keys);
        },
      },
      session: {
        ...sessionArea,
        async set(items) {
          if (env.sessionSetFailures > 0) {
            env.sessionSetFailures -= 1;
            throw new Error("quota exceeded");
          }
          return sessionArea.set(items);
        },
      },
    },
    runtime: {
      // the browser logs an error that nobody read; here it is noted
      get lastError() {
        env.lastErrorRead = true;
        return env.lastError;
      },
      // A native messaging port as the browser has it: the message goes to a new process of the program, its first
      // answer arrives on onMessage, and an exit or a missing program arrives on onDisconnect with runtime.lastError set.
      // Once the worker has called disconnect() nothing more is delivered.
      connectNative(host) {
        if (env.connectThrows) throw new Error("Invalid native messaging host name specified.");
        const port = { host, disconnected: false, open: false, onMessage: [], onDisconnect: [] };
        env.ports.push(port);
        const endExchange = () => {
          if (!port.open) return;
          port.open = false;
          env.inFlight -= 1;
        };
        return {
          name: host,
          onMessage: { addListener: (listener) => port.onMessage.push(listener) },
          onDisconnect: { addListener: (listener) => port.onDisconnect.push(listener) },
          postMessage(message) {
            if (port.disconnected || env.postThrows) throw new Error("Attempting to use a disconnected port object");
            const copy = clone(message);
            env.sent.push({ host, message: copy });
            port.open = true;
            env.inFlight += 1;
            env.maxInFlight = Math.max(env.maxInFlight, env.inFlight);
            const n = env.sent.length;
            Promise.resolve()
              .then(() => (typeof env.reply === "function" ? env.reply(copy, n) : env.reply))
              .then(
                (answer) => {
                  if (port.disconnected) return;
                  endExchange();
                  const value = answer === undefined ? undefined : clone(answer);
                  for (const listener of port.onMessage) listener(value);
                },
                (error) => {
                  if (port.disconnected) return;
                  endExchange();
                  env.lastError = { message: error.message };
                  env.lastErrorRead = false;
                  for (const listener of port.onDisconnect) listener();
                  if (!env.lastErrorRead) env.unchecked.push(error.message);
                  env.lastError = undefined;
                },
              );
          },
          disconnect() {
            port.disconnected = true;
            endExchange();
          },
        };
      },
    },
  };
  const log = (...args) => env.logged.push(args.map((arg) => String(arg && arg.message ? arg.message : arg)).join(" "));
  const fakeDate = { now: () => env.date };
  new Function("chrome", "self", "console", "setTimeout", "clearTimeout", "Date", workerBody())(
    chrome,
    { boxedProtocol: protocol, boxedObserve: O },
    { log, error: log, warn: log, info: log, debug: log },
    fakeSetTimeout,
    fakeClearTimeout,
    fakeDate,
  );
  // A request as the browser reports it. By default it is what a chat's own page sends with fetch: type xmlhttprequest,
  // initiated from the origin of the address it goes to. `overrides` changes any of that.
  env.send = (url, body, method = "POST", overrides = {}) => {
    const listener = env.registrations[0].listener;
    return listener({
      requestId: "1",
      url,
      method,
      frameId: 0,
      parentFrameId: -1,
      tabId: 7,
      type: "xmlhttprequest",
      timeStamp: 1761000000000.5,
      initiator: new URL(url).origin,
      requestBody: body,
      ...overrides,
    });
  };
  return env;
}

const ORG = "5a1b2c3d-0000-4000-8000-000000000001";
const CHAT = "6e7f8a9b-0000-4000-8000-000000000002";
const CLAUDE_SEND = `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/completion`;
const bodyOf = (value) => ({ raw: [{ bytes: enc.encode(typeof value === "string" ? value : JSON.stringify(value)).buffer }] });
const SECRET = "ivan.petrov@acme.com";

test("the worker registers one listener for fetch and XHR requests to the five sites that asks for the request body and cannot hold a request back", () => {
  const env = start();
  assert.equal(env.registrations.length, 1);
  const [{ listener, filter, extra }] = env.registrations;
  assert.equal(typeof listener, "function");
  assert.deepEqual(filter, { urls: manifest.host_permissions, types: ["xmlhttprequest"] });
  assert.deepEqual(extra, ["requestBody"]); // no "blocking": the request goes on whatever happens here
});

test("the toolbar button still opens the side panel", () => {
  assert.deepEqual(start().panel, [{ openPanelOnActionClick: true }]);
});

test("observation is off unless the switch holds exactly true: nothing is read, sent or kept", async () => {
  for (const local of [{}, { observe: false }, { observe: "true" }, { observe: 1 }, { observe: null }, { observe: {} }]) {
    const env = start({ local });
    let read = false;
    const body = {
      get raw() {
        read = true;
        return bodyOf({ prompt: SECRET }).raw;
      },
    };
    assert.equal(env.send(CLAUDE_SEND, body), undefined);
    await settle();
    assert.equal(read, false, JSON.stringify(local));
    assert.deepEqual(env.sent, [], JSON.stringify(local));
    assert.deepEqual(env.session, {}, JSON.stringify(local));
    assert.deepEqual(env.local, local, JSON.stringify(local)); // the worker never writes the switch
  }
});

test("with the switch on, a send reaches the host as an observe request and only counts are kept", async () => {
  const env = start({ local: { observe: true }, reply: { ok: true, found: { EMAIL: 1 } } });
  env.date = 1761000123456;
  assert.equal(env.send(CLAUDE_SEND, bodyOf({ prompt: `mail ${SECRET}`, timezone: "Europe/Moscow" })), undefined);
  await settle();
  assert.deepEqual(env.sent, [
    { host: "si.boxed.host", message: { cmd: "observe", site: "claude", text: `mail ${SECRET}`, coverage: "checked" } },
  ]);
  assert.equal(env.session.observed.length, 1);
  const { time, ...rest } = env.session.observed[0];
  assert.deepEqual(rest, { site: "claude", found: { EMAIL: 1 }, coverage: "checked" });
  assert.equal(time, 1761000123456); // the moment of the send
  assert.doesNotMatch(JSON.stringify([env.local, env.session, env.logged]), /ivan/); // no text anywhere but in the message to the host
});

test("a send that cannot be read goes to the host as not checked, without text", async () => {
  const env = start({ local: { observe: true } });
  env.send(CLAUDE_SEND, bodyOf("{not json"));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message), [{ cmd: "observe", site: "claude", text: "", coverage: "not checked" }]);
  assert.equal(env.session.observed[0].coverage, "not checked");
});

test("requests that are not sends are left alone", async () => {
  const env = start({ local: { observe: true } });
  env.send(CLAUDE_SEND, bodyOf({ prompt: SECRET }), "GET");
  env.send(`https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}`, bodyOf({ prompt: SECRET }));
  env.send("https://chatgpt.com/backend-api/me", bodyOf({ prompt: SECRET }));
  env.send("https://evil.example/backend-api/conversation", bodyOf({ prompt: SECRET }));
  await settle();
  assert.deepEqual(env.sent, []);
  assert.deepEqual(env.session, {});
});

test("a form posted into a frame, or a fetch by another chat's page, at a chat's send address is not a send", async () => {
  const env = start({ local: { observe: true } });
  const body = bodyOf({ prompt: SECRET });
  // the hidden-form forgery: the browser reports a sub_frame (or a navigation) started by the page of another site
  env.send(CLAUDE_SEND, body, "POST", { type: "sub_frame", initiator: "https://evil.example" });
  env.send(CLAUDE_SEND, body, "POST", { type: "main_frame", initiator: "https://evil.example" });
  env.send(CLAUDE_SEND, body, "POST", { type: "sub_frame" }); // even from the chat's own origin: not fetch or XHR
  // a fetch that the page of another site, or of another chat, made
  env.send(CLAUDE_SEND, body, "POST", { initiator: "https://evil.example" });
  env.send(CLAUDE_SEND, body, "POST", { initiator: "null" });
  env.send(CLAUDE_SEND, body, "POST", { initiator: "https://chatgpt.com" });
  env.send(CLAUDE_SEND, body, "POST", { initiator: undefined });
  env.send("https://chatgpt.com/backend-api/conversation", bodyOf({ messages: [{ author: { role: "user" }, content: { parts: [SECRET] } }] }), "POST", {
    initiator: "https://claude.ai",
  });
  await settle();
  assert.deepEqual(env.sent, []);
  assert.deepEqual(env.session, {});
  // the same address, sent the way the chat sends it, is still observed
  env.send(CLAUDE_SEND, body);
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.site), ["claude"]);
});

test("the switch takes effect at once, in both directions", async () => {
  const env = start({ local: { observe: false } });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "one" }));
  await settle();
  assert.equal(env.sent.length, 0);
  env.local.observe = true;
  env.send(CLAUDE_SEND, bodyOf({ prompt: "two" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["two"]);
  env.local.observe = false;
  env.send(CLAUDE_SEND, bodyOf({ prompt: "three" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["two"]);
});

test("a host that fails or answers badly is kept as not recorded, and its error text is not logged", async () => {
  const replies = [
    () => {
      throw new Error(`Native host has exited. ${SECRET}`);
    },
    { ok: false, error: "bad request" },
    { ok: false, error: SECRET },
    { ok: true },
    { ok: true, found: "EMAIL 1" },
    { ok: true, found: { EMAIL: "1" } },
    "text",
    null,
  ];
  for (const reply of replies) {
    const env = start({ local: { observe: true }, reply });
    env.send(CLAUDE_SEND, bodyOf({ prompt: `mail ${SECRET}` }));
    await settle();
    assert.equal(env.session.observed.length, 1);
    const { time, ...rest } = env.session.observed[0];
    assert.deepEqual(rest, { site: "claude", found: null, coverage: "checked" });
    assert.doesNotMatch(env.logged.join("\n"), /ivan/);
    assert.deepEqual(env.unchecked, []); // the browser's error for a missing or exiting program is read, not left to be logged
  }
});

test("the program gets 20 seconds to answer, then the port is closed, the send is kept as not checked and the next one goes on", async () => {
  const env = start({ local: { observe: true }, reply: (message) => (message.text === "first" ? new Promise(() => {}) : { ok: true, found: { EMAIL: 1 } }) });
  env.date = 1000;
  env.send(CLAUDE_SEND, bodyOf({ prompt: "first" }));
  env.date = 2000;
  env.send(CLAUDE_SEND, bodyOf({ prompt: "second" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["first"]);
  await env.advance(19999);
  assert.deepEqual(env.sent.map((s) => s.message.text), ["first"]); // still waiting for the first answer
  assert.equal(env.session.observed, undefined);
  assert.equal(env.ports[0].disconnected, false);
  await env.advance(1);
  assert.equal(env.ports[0].disconnected, true); // this also ends the program's process
  assert.deepEqual(env.sent.map((s) => s.message.text), ["first", "second"]);
  assert.deepEqual(env.session.observed, [
    { site: "claude", time: 2000, found: { EMAIL: 1 }, coverage: "checked" },
    { site: "claude", time: 1000, found: null, coverage: "not checked" },
  ]);
  assert.doesNotMatch(JSON.stringify(env.session), /first|second/); // a gap keeps no text either
});

test("an answer closes the port and stops the clock, so nothing is left running", async () => {
  const env = start({ local: { observe: true }, reply: { ok: true, found: {} } });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "x" }));
  await settle();
  assert.equal(env.ports.length, 1);
  assert.equal(env.ports[0].disconnected, true);
  assert.deepEqual(env.timers, []);
  assert.equal(env.inFlight, 0);
  await env.advance(60000);
  assert.deepEqual(env.session.observed.map((entry) => entry.coverage), ["checked"]); // the stopped clock added nothing
});

test("a program that is missing or exits is not a timeout: it is not recorded, the port is closed", async () => {
  const env = start({
    local: { observe: true },
    reply: () => {
      throw new Error("Native host has exited.");
    },
  });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "x" }));
  await settle();
  assert.deepEqual(env.session.observed.map((entry) => [entry.found, entry.coverage]), [[null, "checked"]]);
  assert.equal(env.ports[0].disconnected, true);
  assert.deepEqual(env.timers, []);
});

test("a port that cannot be opened or written to is kept as not recorded, with no clock left running", async () => {
  for (const fault of ["connectThrows", "postThrows"]) {
    const env = start({ local: { observe: true } });
    env[fault] = true;
    env.send(CLAUDE_SEND, bodyOf({ prompt: "x" }));
    await settle();
    assert.deepEqual(env.session.observed.map((entry) => [entry.found, entry.coverage]), [[null, "checked"]], fault);
    assert.deepEqual(env.timers, [], fault);
    if (fault === "postThrows") assert.equal(env.ports[0].disconnected, true);
  }
});

// A worker with the switch on whose program never answers the send with the text "send 1" and answers every other at once.
// bodyN(n) is the body of "send n" that records when it is read.
function stuckFirst() {
  const env = start({ local: { observe: true }, reply: (message) => (message.text === "send 1" ? new Promise(() => {}) : { ok: true, found: {} }) });
  const reads = [];
  const bodyN = (n) => ({
    get raw() {
      reads.push(n);
      return bodyOf({ prompt: `send ${n}` }).raw;
    },
  });
  return { env, reads, bodyN };
}

test("at most 5 sends wait for the program: the others are kept as not checked at once and their bodies are never read", async () => {
  const { env, reads, bodyN } = stuckFirst();
  for (let n = 1; n <= 9; n++) {
    env.date = 1000 * n;
    env.send(CLAUDE_SEND, bodyN(n));
  }
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["send 1"]); // one is with the program, four wait their turn
  assert.deepEqual(reads, [1]);
  const gap = (n) => ({ site: "claude", time: 1000 * n, found: null, coverage: "not checked" });
  assert.deepEqual(env.session.observed, [gap(9), gap(8), gap(7), gap(6)]); // 6 to 9 did not fit
  await env.advance(20000); // the first gives up, then 2 to 5 go through one at a time
  assert.deepEqual(env.sent.map((s) => s.message.text), ["send 1", "send 2", "send 3", "send 4", "send 5"]);
  assert.deepEqual(reads, [1, 2, 3, 4, 5]); // 6 to 9 were never read
  const done = (n) => ({ site: "claude", time: 1000 * n, found: {}, coverage: "checked" });
  // newest send first, although the gaps for 6 to 9 were written before the answers for 1 to 5
  assert.deepEqual(env.session.observed, [gap(9), gap(8), gap(7), gap(6), done(5), done(4), done(3), done(2), gap(1)]);
  env.date = 30000;
  env.send(CLAUDE_SEND, bodyN(10)); // the line has gone, there is room again
  await settle();
  assert.equal(env.sent.at(-1).message.text, "send 10");
});

test("the worker lets go of the body of a send that does not fit", async () => {
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc");
  const { env } = stuckFirst();
  const refs = [];
  // in a function of its own, so that no variable of this test keeps the last body alive
  (function sendNine() {
    for (let n = 1; n <= 9; n++) {
      const body = bodyOf({ prompt: `send ${n}` });
      refs.push(new WeakRef(body));
      env.send(CLAUDE_SEND, body);
    }
  })();
  await settle();
  gc();
  await settle(); // a WeakRef keeps its target until the turn that made it is over
  gc();
  // the five in the line are held (that is the bound), the four that did not fit are not
  assert.deepEqual(refs.map((ref) => ref.deref() !== undefined), [true, true, true, true, true, false, false, false, false]);
});

test("a send that is waiting when the switch is turned off is dropped, not sent", async () => {
  const gates = [];
  const env = start({ local: { observe: true }, reply: () => new Promise((resolve) => gates.push(resolve)) });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "A" }));
  env.send(CLAUDE_SEND, bodyOf({ prompt: "B" }));
  await settle();
  env.local.observe = false;
  gates[0]({ ok: true, found: {} });
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["A"]);
  assert.deepEqual(env.session.observed.map((entry) => entry.coverage), ["checked"]);
});

test("with the switch off nothing is kept as a gap either, however many sends come", async () => {
  const env = start({ local: { observe: true }, reply: () => new Promise(() => {}) });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "one" }));
  await settle();
  env.local.observe = false;
  for (let n = 0; n < 12; n++) env.send(CLAUDE_SEND, bodyOf({ prompt: `later ${n}` }));
  await settle();
  assert.equal(env.session.observed, undefined);
  assert.equal(env.sent.length, 1);
});

test("sends go to the host one at a time, and the list keeps them newest first", async () => {
  const gates = [];
  const env = start({ local: { observe: true }, reply: () => new Promise((resolve) => gates.push(resolve)) });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "first" }));
  env.send(CLAUDE_SEND, bodyOf({ prompt: "second" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["first"]); // the second waits for the first answer
  gates[0]({ ok: true, found: { A: 1 } });
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["first", "second"]);
  gates[1]({ ok: true, found: { B: 2 } });
  await settle();
  assert.equal(env.maxInFlight, 1);
  assert.deepEqual(env.session.observed.map((entry) => entry.found), [{ B: 2 }, { A: 1 }]);
});

test("only the last 20 results are kept", async () => {
  const env = start({ local: { observe: true }, reply: (message, n) => ({ ok: true, found: { N: n } }) });
  for (let i = 1; i <= 25; i++) {
    env.date = 1000 * i;
    env.send(CLAUDE_SEND, bodyOf({ prompt: `message ${i}` }));
    await settle(); // one at a time: the line for the program is not what is tested here
  }
  assert.equal(env.sent.length, 25);
  assert.deepEqual(env.session.observed.map((entry) => entry.found.N), [25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6]);
});

test("a damaged list in storage is replaced, not an end to observation", async () => {
  const env = start({ local: { observe: true } });
  env.session.observed = "damaged";
  env.send(CLAUDE_SEND, bodyOf({ prompt: "one" }));
  await settle();
  assert.equal(env.session.observed.length, 1);
});

test("a send that cannot even be prepared is skipped, and the line goes on with the next", async () => {
  const protocol = {
    ...P,
    buildObserveRequest(site, text, coverage) {
      if (text === "boom") throw new Error("cannot be built");
      return P.buildObserveRequest(site, text, coverage);
    },
  };
  const env = start({ local: { observe: true }, protocol });
  env.send(CLAUDE_SEND, bodyOf({ prompt: "boom" }));
  env.send(CLAUDE_SEND, bodyOf({ prompt: "next" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["next"]);
  assert.equal(env.session.observed.length, 1);
  env.send(CLAUDE_SEND, bodyOf({ prompt: "and later" })); // the line is not stuck, nor its count of waiting sends wrong
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["next", "and later"]);
});

test("a switch that cannot be read counts as off", async () => {
  const env = start({ local: { observe: true } });
  env.localBroken = true;
  env.send(CLAUDE_SEND, bodyOf({ prompt: SECRET }));
  await settle();
  assert.deepEqual(env.sent, []);
  assert.deepEqual(env.session, {});
});

test("a send that fails half way does not stop the next one", async () => {
  const env = start({ local: { observe: true } });
  env.sessionSetFailures = 1; // the first result cannot be written
  env.send(CLAUDE_SEND, bodyOf({ prompt: "one" }));
  env.send(CLAUDE_SEND, bodyOf({ prompt: "two" }));
  await settle();
  assert.deepEqual(env.sent.map((s) => s.message.text), ["one", "two"]);
  assert.equal(env.session.observed.length, 1);
});

test("a worker that imports its libraries is declared as a module, with the permissions it uses", () => {
  assert.deepEqual(manifest.background, { service_worker: "background.js", type: "module" });
  for (const permission of ["webRequest", "storage", "nativeMessaging", "sidePanel"]) assert.ok(manifest.permissions.includes(permission), permission);
  // watching is allowed, holding back or rewriting a request is not
  for (const permission of ["webRequestBlocking", "webRequestAuthProvider", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "tabs"]) {
    assert.ok(!manifest.permissions.includes(permission), permission);
  }
});

test("loaded as plain scripts, the libraries publish themselves on self where the worker looks", () => {
  for (const [file, name, member] of [
    ["protocol.js", "boxedProtocol", "parseReply"],
    ["observe.js", "boxedObserve", "matchSend"],
  ]) {
    const scope = { TextEncoder, TextDecoder, URL };
    scope.self = scope;
    vm.createContext(scope);
    vm.runInContext(fs.readFileSync(path.join(EXTENSION, "lib", file), "utf8"), scope);
    assert.equal(typeof scope[name][member], "function", file);
  }
});
