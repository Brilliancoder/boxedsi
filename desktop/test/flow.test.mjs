import test from "node:test";
import assert from "node:assert/strict";

import { createFlow, levelHelp, LEVELS } from "../src/flow.js";

// A request function that answers from a list and records what it was asked.
function fakeRequest(...replies) {
  const calls = [];
  const request = async (cmd, fields) => {
    calls.push({ cmd, fields });
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return reply;
  };
  request.calls = calls;
  return request;
}

// A store of scope names that keeps what it is given in memory.
function memoryStore(initial = []) {
  const store = { saved: [...initial], load: () => [...store.saved], save: (names) => (store.saved = [...names]) };
  return store;
}

const masked = (scope, text = "Write to [EMAIL_1]") => ({ ok: true, text, scope, level: 2, markers_by_kind: { EMAIL: 1 } });
const restored = (text = "x", extra = {}) => ({ ok: true, text, restored: 1, unknown: [], suspicious: [], ...extra });

test("ping shows the version of the engine and what it detects, or the sentence it failed with", async () => {
  const flow = createFlow(
    fakeRequest(
      { ok: true, version: "0.1.0", ner: ["ru"], ner_installed: ["ru"] },
      { ok: true, version: "0.1.0" },
      { ok: false, error: "The masking engine is not running.", code: "unavailable" },
    ),
  );
  assert.deepEqual(await flow.ping(), {
    ready: true,
    status: "Masking engine ready (version 0.1.0). Names: Russian model.",
    detects: { known: true, ru: true, en: false },
    retry: false,
  });
  const unknown = await flow.ping();
  assert.equal(unknown.status, "Masking engine ready (version 0.1.0). Names: not known.");
  assert.deepEqual(unknown.detects, { known: false, ru: false, en: false });
  assert.deepEqual(await flow.ping(), {
    ready: false,
    status: "The masking engine is not running.",
    detects: { known: false, ru: false, en: false },
    retry: false,
  });
});

test("a detector that runs but whose library is not installed finds nothing", async () => {
  const flow = createFlow(fakeRequest({ ok: true, version: "0.1.0", ner: ["ru", "en"], ner_installed: ["ru"] }));
  assert.deepEqual((await flow.ping()).detects, { known: true, ru: true, en: false });
});

test("mask sends the text, the level and the scope it is given, and nothing else", async () => {
  const request = fakeRequest(masked("manual-1"), masked("manual-1"));
  const flow = createFlow(request);
  const first = await flow.mask("Write to ivan@example.com", 2, "");
  assert.deepEqual(request.calls[0], { cmd: "mask", fields: { text: "Write to ivan@example.com", level: 2 } });
  assert.equal(first.text, "Write to [EMAIL_1]");
  assert.equal(first.mode, "masked");
  assert.equal(first.error, false);
  assert.equal(first.scope, "manual-1");
  assert.match(first.status, /Masked 1 item at level 2/);
  await flow.mask("And to anna@example.com", 2, first.scope);
  assert.deepEqual(request.calls[1], { cmd: "mask", fields: { text: "And to anna@example.com", level: 2, scope: "manual-1" } });
});

test("restore uses the scope it is given, not the scope of the last mask", async () => {
  const request = fakeRequest(masked("manual-A"), masked("manual-B"), restored("Dear a@example.com", { unknown: ["[CLIENT_9]"], suspicious: ["[email 1]"] }));
  const flow = createFlow(request);
  await flow.mask("a", 2, "");
  await flow.mask("b", 2, "");
  const view = await flow.restore("Dear [EMAIL_1], see [CLIENT_9]", "manual-A");
  assert.deepEqual(request.calls[2], { cmd: "restore", fields: { text: "Dear [EMAIL_1], see [CLIENT_9]", scope: "manual-A" } });
  assert.equal(view.text, "Dear a@example.com");
  assert.equal(view.mode, "restored");
  assert.equal(view.scope, "manual-A");
  assert.match(view.status, /Restored 1 placeholder\./);
  assert.match(view.status, /stays in this window/);
  assert.deepEqual(view.notes, [
    { title: "Not found for this scope", items: ["[CLIENT_9]"] },
    { title: "Look changed, check by hand", items: ["[email 1]"] },
  ]);
});

test("a restore with nothing wrong has no notes", async () => {
  const flow = createFlow(fakeRequest(restored("x", { restored: 2 })));
  assert.deepEqual((await flow.restore("a", "manual-1")).notes, []);
});

test("restore without a scope asks for one and sends nothing", async () => {
  const request = fakeRequest();
  const view = await createFlow(request).restore("Dear [EMAIL_1]", "");
  assert.equal(request.calls.length, 0);
  assert.equal(view.text, null);
  assert.equal(view.error, true);
  assert.match(view.status, /Enter the scope/);
});

test("empty text, a level outside 0 to 3 and a scope that is not a name send nothing", async () => {
  const request = fakeRequest();
  const flow = createFlow(request);
  assert.match((await flow.mask("   \n", 2, "")).status, /Type or paste some text/);
  for (const level of [-1, 4, 2.5, NaN, "2", null, undefined]) {
    assert.match((await flow.mask("text", level, "")).status, /Choose a level from 0 to 3/, String(level));
  }
  for (const scope of ["a b", "-x", "a/b", "x".repeat(65), "Иван", "a\nb"]) {
    assert.match((await flow.mask("text", 2, scope)).status, /A scope name is/, JSON.stringify(scope));
    assert.match((await flow.restore("text", scope)).status, /A scope name is/, JSON.stringify(scope));
  }
  assert.match((await flow.restore("  ", "manual-1")).status, /Type or paste some text/);
  assert.equal(request.calls.length, 0);
});

test("an error reply is shown as the sentence it came with and the screen text is left alone", async () => {
  const flow = createFlow(fakeRequest({ ok: false, error: "bad request" }));
  const view = await flow.mask("text", 2, "");
  assert.equal(view.text, null);
  assert.equal(view.error, true);
  assert.equal(view.status, "bad request");
  assert.equal(view.retry, false);
});

test("a failed mask changes nothing about the scopes", async () => {
  const flow = createFlow(fakeRequest(masked("manual-1"), { ok: false, error: "The request took too long and was stopped. Please try again.", code: "timeout" }), { store: memoryStore() });
  await flow.mask("a", 2, "");
  await flow.mask("b", 2, "manual-1");
  assert.deepEqual(flow.state.scopes, ["manual-1"]);
});

test("something that is not a reply, or a request that throws, gives a fixed sentence and never the exception text", async () => {
  const secret = "ivan.petrov@example.com";
  const flow = createFlow(fakeRequest(null, { ok: "yes" }, { ok: true, scope: "s", text: 5 }, new Error(`failed on ${secret}`), "oops"));
  for (let i = 0; i < 5; i++) {
    const view = await flow.mask("text", 2, "");
    assert.equal(view.error, true);
    assert.equal(view.text, null);
    assert.ok(!view.status.includes(secret));
  }
  assert.equal((await createFlow(fakeRequest(new Error(secret))).ping()).ready, false);
});

test("a sidecar that was given up on shows its sentence, the numbers and a way to try again", async () => {
  const reply = { ok: false, error: "The masking engine keeps stopping, so it was not started again. Press Try again.", code: "gave-up", restarts: 2, exit_code: 1 };
  const view = await createFlow(fakeRequest(reply)).mask("text", 2, "");
  assert.equal(view.retry, true);
  assert.equal(view.status, "The masking engine keeps stopping, so it was not started again. Press Try again. Restarted 2 times, last exit code 1.");
  const killed = await createFlow(fakeRequest({ ...reply, restarts: 1, exit_code: undefined, signal: 9 })).mask("text", 2, "");
  assert.match(killed.status, /Restarted 1 time, ended by signal 9\.$/);
  const waiting = await createFlow(fakeRequest({ ok: false, error: "The masking engine is not running. It is restarting, please try again in a moment.", code: "unavailable", restarts: 0 })).mask("text", 2, "");
  assert.equal(waiting.retry, false);
});

test("a ping that finds the engine given up on offers the way to try again too", async () => {
  const reply = { ok: false, error: "The masking engine keeps stopping, so it was not started again. Press Try again.", code: "gave-up", restarts: 2, exit_code: 1 };
  const view = await createFlow(fakeRequest(reply)).ping();
  assert.equal(view.ready, false);
  assert.equal(view.retry, true);
});

test("try again restarts the engine and asks it again", async () => {
  const request = fakeRequest({ ok: true }, { ok: true, version: "0.1.0", ner: ["ru"] });
  const view = await createFlow(request).retry();
  assert.deepEqual(request.calls.map((call) => call.cmd), ["restart", "ping"]);
  assert.equal(view.ready, true);
  const failed = await createFlow(fakeRequest(new Error("x"))).retry();
  assert.equal(failed.ready, false);
});

test("the flow remembers scope names and no text, and keeps the last twenty in its store", async () => {
  const store = memoryStore(["manual-old"]);
  const replies = Array.from({ length: 25 }, (_, n) => masked(`manual-${n}`));
  const flow = createFlow(fakeRequest(...replies, restored("Dear ivan@example.com")), { store });
  assert.deepEqual(flow.state.scopes, ["manual-old"]);
  for (let n = 0; n < 25; n++) await flow.mask("Write to ivan@example.com", 2, "");
  await flow.restore("Dear [EMAIL_1]", "manual-3");
  assert.deepEqual(Object.keys(flow.state), ["scopes"]);
  assert.equal(flow.state.scopes.length, 20);
  assert.equal(flow.state.scopes.at(-1), "manual-24");
  assert.deepEqual(store.saved, flow.state.scopes);
  const kept = JSON.stringify([flow.state, store.saved]);
  for (const text of ["ivan@example.com", "Dear", "EMAIL_1", "Write to"]) assert.ok(!kept.includes(text), text);
  assert.ok(store.saved.every((name) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)));
});

test("a store that gives back rubbish, or fails, is ignored", async () => {
  const rubbish = { load: () => ["fine-1", "not a name!", 7, null, "x".repeat(70)], save: () => {} };
  assert.deepEqual(createFlow(fakeRequest(), { store: rubbish }).state.scopes, ["fine-1"]);
  const broken = { load: () => { throw new Error("no storage"); }, save: () => { throw new Error("no storage"); } };
  const flow = createFlow(fakeRequest(masked("manual-1")), { store: broken });
  assert.deepEqual(flow.state.scopes, []);
  assert.equal((await flow.mask("a", 2, "")).error, false);
});

test("the four levels say what they replace, and never promise names that the engine cannot find", () => {
  assert.deepEqual(LEVELS.map((l) => l.level), [0, 1, 2, 3]);
  const cases = {
    russian: { known: true, ru: true, en: false },
    both: { known: true, ru: true, en: true },
    english: { known: true, ru: false, en: true },
    none: { known: true, ru: false, en: false },
    unknown: { known: false, ru: false, en: false },
  };
  for (const [name, detects] of Object.entries(cases)) {
    for (const { level } of LEVELS) {
      const text = levelHelp(level, detects);
      assert.ok(text.length > 20, `${name} ${level}`);
      assert.ok(!/[–—]/.test(text), "no dashes");
      assert.ok(!/anonymous/i.test(text), "no promise of anonymity");
    }
  }
  const people = (detects) => levelHelp(1, detects);
  const companies = (detects) => levelHelp(2, detects);
  assert.match(people(cases.russian), /Russian names are found by a small model/);
  assert.match(people(cases.russian), /English names are not reliably found/);
  assert.match(people(cases.russian), /ner-en/);
  assert.match(companies(cases.russian), /English ones are not reliably found/);
  assert.match(companies(cases.russian), /Context can still identify a person/);
  assert.match(people(cases.both), /Russian and English models/);
  assert.match(people(cases.english), /English model/);
  for (const bare of [cases.none, cases.unknown]) {
    assert.doesNotMatch(people(bare), /names are (found|replaced|hidden)|hides? names/i);
    assert.doesNotMatch(companies(bare), /Direct names are hidden/);
    assert.doesNotMatch(companies(bare), /Context can still identify/);
  }
  assert.match(people(cases.none), /People's names are not found/);
  assert.match(people(cases.unknown), /not known/);
  // levels 0 and 3 do not depend on the name models
  assert.equal(levelHelp(0, cases.none), levelHelp(0, cases.both));
  assert.equal(levelHelp(3, cases.none), levelHelp(3, cases.both));
});
