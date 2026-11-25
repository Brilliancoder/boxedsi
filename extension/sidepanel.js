// The side panel: mask, copy, insert into the chat box, restore, and the Observe tab (the switch, its last results,
// the training checks). Whatever the host, a page or the browser's storage returns is shown as plain text, never as markup.
"use strict";

(function () {
  const P = boxedProtocol;
  const $ = (id) => document.getElementById(id);
  const SCOPE_KEY = "boxed.scope";
  const INSERTED = {
    inserted: "Inserted. Check the text, then press Send yourself.",
    "no-input": "Click into the chat box first, then press Insert into page again.",
    "not-an-input": "The selected element is not a text box. Click into the chat box first.",
    failed: "The page did not take the text. Use Copy and paste it by hand.",
  };
  const TABS = [
    { button: $("tab-prepare"), section: $("prepare") },
    { button: $("tab-restore"), section: $("restore") },
    { button: $("tab-observe"), section: $("observe"), onShow: () => loadChecks() },
  ];
  let noticeTimer;

  function say(message, bad = false) {
    $("notice").textContent = message;
    $("notice").className = bad ? "notice bad" : "notice";
    clearTimeout(noticeTimer);
    if (message && !bad) noticeTimer = setTimeout(() => say(""), 6000);
  }

  function savedScope() {
    try {
      const scope = localStorage.getItem(SCOPE_KEY);
      return scope && P.SCOPE_RE.test(scope) ? scope : null;
    } catch {
      return null;
    }
  }

  function saveScope(scope) {
    try {
      localStorage.setItem(SCOPE_KEY, scope);
    } catch {
      // storage can be off in private windows; the scope field still works
    }
  }

  // Mask and Restore talk to the program through one port, so that the program starts - and loads the language model that finds
  // names - once, not at every click. The port closes after IDLE_MS without a request and when the panel closes, and the program
  // ends with it. Requests go one at a time, because the program's answers carry no number, so one that never gets its answer would
  // hold up all the rest: after ANSWER_MS it is given up, the port is closed and the next request starts the program again. Nothing
  // of a request or of its answer is kept here once the answer has been handed on. The status check, the checks and Save are
  // single messages: they need no model.
  const IDLE_MS = 60000;
  const ANSWER_MS = 120000;
  const TOO_SLOW = "The boxed.si program did not answer in 2 minutes, so it was stopped. Try again, or split the text into smaller parts.";
  const ON_THE_PORT = ["mask", "restore"];
  const START_AGAIN = ["host cannot start", "internal error"]; // after these answers the program is started afresh by the next request
  let port = null;
  let asking = null; // {resolve, reject} of the one request the program is answering
  let idleTimer;
  let answerTimer;
  let turn = Promise.resolve();
  const nothing = () => {};

  class TooSlow extends Error {}

  function closePort() {
    clearTimeout(idleTimer);
    clearTimeout(answerTimer);
    const closing = port;
    const waiting = asking;
    port = null;
    asking = null;
    try {
      if (closing) closing.disconnect();
    } catch {
      // it was closed already
    }
    if (waiting) waiting.reject(new Error("The port was closed."));
  }

  // The request that the program has not answered in ANSWER_MS: the port is closed, which makes the browser stop the program.
  function giveUp() {
    const waiting = asking;
    asking = null; // so that closing the port does not end it with the plain "closed"
    closePort();
    if (waiting) waiting.reject(new TooSlow());
  }

  function openPort() {
    const opened = chrome.runtime.connectNative(P.HOST_NAME);
    opened.onMessage.addListener((reply) => {
      const waiting = asking;
      asking = null;
      if (waiting && port === opened) waiting.resolve(reply);
    });
    opened.onDisconnect.addListener(() => {
      const reason = chrome.runtime.lastError && chrome.runtime.lastError.message; // read, so that the browser does not log it
      if (port !== opened) return; // a port that was closed here already
      const waiting = asking;
      clearTimeout(idleTimer);
      clearTimeout(answerTimer);
      port = null;
      asking = null;
      if (waiting) waiting.reject(new Error(reason));
    });
    port = opened;
  }

  function viaPort(request) {
    const answer = turn.then(async () => {
      clearTimeout(idleTimer); // while the program works it is not idle
      try {
        const reply = await new Promise((resolve, reject) => {
          if (!port) openPort();
          asking = { resolve, reject };
          answerTimer = setTimeout(giveUp, ANSWER_MS);
          port.postMessage(request);
        });
        clearTimeout(answerTimer);
        if (reply && reply.ok === false && START_AGAIN.includes(reply.error)) closePort();
        else idleTimer = setTimeout(closePort, IDLE_MS);
        return reply;
      } catch (error) {
        closePort(); // whatever went wrong, the next request starts the program again
        throw error;
      }
    });
    turn = answer.then(nothing, nothing); // the next request waits for this one, however it ends; the answer itself is not passed on
    return answer;
  }

  async function send(request, cmd) {
    try {
      const reply = ON_THE_PORT.includes(cmd) ? await viaPort(request) : await chrome.runtime.sendNativeMessage(P.HOST_NAME, request);
      return P.parseReply(reply, cmd);
    } catch (error) {
      return { ok: false, error: error instanceof TooSlow ? TOO_SLOW : P.describeFailure(error && error.message, chrome.runtime.id) };
    }
  }

  async function working(button, work) {
    const label = button.textContent;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Working...";
    try {
      return await work();
    } finally {
      button.textContent = label;
      button.removeAttribute("aria-busy");
      button.disabled = false;
    }
  }

  function describeCounts(counts) {
    const parts = Object.entries(counts).map(([kind, count]) => `${kind} ${count}`);
    return parts.length ? `Replaced: ${parts.join(", ")}.` : "Nothing found to replace. Read the text yourself before you send it.";
  }

  function selectTab(index, focus = false) {
    TABS.forEach((tab, i) => {
      tab.button.setAttribute("aria-selected", String(i === index));
      tab.button.tabIndex = i === index ? 0 : -1;
      tab.section.hidden = i !== index;
    });
    if (focus) TABS[index].button.focus();
    say("");
    if (TABS[index].onShow) TABS[index].onShow();
  }

  async function onMask() {
    let request;
    try {
      request = P.buildMaskRequest($("input").value, Number($("level").value), $("scope").value.trim() || null);
    } catch (error) {
      return say(error.message, true);
    }
    $("masked").value = "";
    $("summary").textContent = "";
    $("copy-masked").disabled = true;
    $("insert").disabled = true;
    const reply = await working($("mask"), () => send(request, "mask"));
    if (!reply.ok) return say(reply.error, true);
    $("masked").value = reply.text;
    $("scope").value = reply.scope;
    saveScope(reply.scope);
    $("summary").textContent = describeCounts(reply.markersByKind);
    $("copy-masked").disabled = false;
    $("insert").disabled = false;
    say("");
  }

  function clearRestored() {
    $("restored").value = "";
    $("restore-summary").textContent = "";
    $("warnings").replaceChildren();
    $("problems").hidden = true;
    $("copy-restored").disabled = true;
    $("copy-restored").textContent = "Copy";
  }

  async function onRestore() {
    let request;
    try {
      request = P.buildRestoreRequest($("answer").value, $("scope").value.trim());
    } catch (error) {
      return say(error.message, true);
    }
    clearRestored();
    const reply = await working($("run-restore"), () => send(request, "restore"));
    if (!reply.ok) return say(reply.error, true);
    const problems = [
      ...reply.unknown.map((marker) => `${marker} - no such placeholder in this scope, left as it is`),
      ...reply.suspicious.map((marker) => `${marker} - looks like a placeholder but was changed, left as it is`),
    ];
    for (const problem of problems) {
      const item = document.createElement("li");
      item.textContent = problem;
      $("warnings").append(item);
    }
    $("problems").hidden = problems.length === 0;
    $("restored").value = reply.text;
    $("copy-restored").disabled = false;
    $("copy-restored").textContent = problems.length ? "Copy anyway" : "Copy";
    if (problems.length) $("restore-summary").textContent = "Some placeholders were not restored.";
    else $("restore-summary").textContent = reply.text === $("answer").value ? "No placeholders found in this answer." : "Placeholders restored.";
    say("");
  }

  async function onCopy(field) {
    try {
      await navigator.clipboard.writeText(field.value);
      say("Copied.");
    } catch {
      say("The browser blocked copying. Select the text and copy it by hand.", true);
    }
  }

  async function onInsert() {
    const text = $("masked").value;
    if (!text) return;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !P.isAiSite(tab.url)) {
        return say("Open ChatGPT, Claude, Gemini, DeepSeek or Z.ai in this window first.", true);
      }
      const [injection] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: P.insertIntoActiveInput,
        args: [text],
      });
      const result = injection && injection.result;
      const known = typeof result === "string" && Object.hasOwn(INSERTED, result);
      say(INSERTED[known ? result : "failed"], result !== "inserted");
    } catch {
      say("Could not reach the page. Reload the chat tab, or use Copy.", true);
    }
  }

  function renderObserved(entries) {
    const items = (Array.isArray(entries) ? entries : []).flatMap((entry) => {
      const result = P.describeObserved(entry);
      if (result === null) return [];
      const item = document.createElement("li");
      item.textContent = `${new Date(entry.time).toLocaleTimeString()} ${entry.site}: ${result}`;
      return [item];
    });
    $("observed").replaceChildren(...items);
    $("observed-empty").hidden = items.length > 0;
  }

  async function showObserved() {
    try {
      renderObserved((await chrome.storage.session.get({ [P.OBSERVED_KEY]: [] }))[P.OBSERVED_KEY]);
    } catch {
      renderObserved([]);
    }
  }

  async function showSwitch() {
    try {
      $("observe-on").checked = (await chrome.storage.local.get({ [P.OBSERVE_KEY]: false }))[P.OBSERVE_KEY] === true;
    } catch {
      $("observe-on").checked = false;
    }
  }

  async function onSwitch() {
    const on = $("observe-on").checked;
    try {
      await chrome.storage.local.set({ [P.OBSERVE_KEY]: on });
      say(on ? "Observation is on." : "Observation is off.");
    } catch {
      $("observe-on").checked = !on;
      say("The browser did not save the switch. Try again.", true);
    }
  }

  // The chats of the form: the program's list once it has answered, the five known ones before.
  function fillProviders(providers) {
    const select = $("check-provider");
    const chosen = select.value;
    select.replaceChildren(
      ...providers.map((provider) => {
        const option = document.createElement("option");
        option.value = provider;
        option.textContent = provider;
        return option;
      }),
    );
    if (providers.includes(chosen)) select.value = chosen;
  }

  async function onOpenSetting(url) {
    try {
      await chrome.tabs.create({ url });
    } catch {
      say("Could not open the page.", true);
    }
  }

  function checkRow(check) {
    const row = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = `${check.provider} - ${check.account}`;
    row.append(name);
    if (check.due) {
      const mark = document.createElement("span");
      mark.className = "mark";
      mark.textContent = "Check again";
      row.append(mark);
    }
    const detail = document.createElement("p");
    detail.className = "hint";
    detail.textContent = P.describeCheck(check);
    row.append(detail);
    if (check.settingsUrl) {
      const open = document.createElement("button");
      open.type = "button";
      open.textContent = "Open setting";
      open.setAttribute("aria-label", `Open the setting of ${check.provider}, account ${check.account}`);
      open.addEventListener("click", () => onOpenSetting(check.settingsUrl));
      row.append(open);
    }
    return row;
  }

  // The pages of data controls that the program named for the chats, from its last answer; none before it has answered.
  let knownSettings = {};

  function showOpenSetting() {
    $("check-open").hidden = P.settingsFor(knownSettings, $("check-provider").value) === null;
  }

  let checksRun = 0;

  async function loadChecks() {
    const run = ++checksRun;
    const reply = await send(P.buildChecksRequest(), "checks");
    if (run !== checksRun) return; // a newer request is on its way and will draw the list
    const checks = reply.ok ? reply.checks : [];
    $("checks").replaceChildren(...checks.map(checkRow));
    $("checks-note").textContent = reply.ok ? reply.note : "";
    $("checks-status").textContent = reply.ok ? "Nothing recorded yet." : reply.error;
    $("checks-status").className = reply.ok ? "hint" : "hint bad";
    $("checks-status").hidden = reply.ok && checks.length > 0;
    if (reply.ok) fillProviders(reply.providers);
    knownSettings = reply.ok ? reply.settings : {};
    showOpenSetting();
  }

  async function onSaveCheck(event) {
    event.preventDefault();
    let request;
    try {
      request = P.buildCheckSetRequest($("check-provider").value, $("check-account").value.trim(), $("check-training").value, $("check-memory").value);
    } catch (error) {
      return say(error.message, true);
    }
    const reply = await working($("check-save"), () => send(request, "check-set"));
    if (!reply.ok) return say(reply.error, true);
    say("Saved.");
    loadChecks();
  }

  TABS.forEach((tab, i) => {
    tab.button.addEventListener("click", () => selectTab(i));
    tab.button.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      event.preventDefault();
      selectTab((i + (event.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length, true);
    });
  });
  $("mask").addEventListener("click", onMask);
  $("run-restore").addEventListener("click", onRestore);
  $("copy-masked").addEventListener("click", () => onCopy($("masked")));
  $("copy-restored").addEventListener("click", () => onCopy($("restored")));
  $("insert").addEventListener("click", onInsert);
  $("observe-on").addEventListener("change", onSwitch);
  $("check-form").addEventListener("submit", onSaveCheck);
  $("check-provider").addEventListener("change", showOpenSetting);
  $("check-open").addEventListener("click", () => {
    const url = P.settingsFor(knownSettings, $("check-provider").value);
    if (url) onOpenSetting(url);
  });
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "session" && changes[P.OBSERVED_KEY]) renderObserved(changes[P.OBSERVED_KEY].newValue);
  });
  window.addEventListener("pagehide", closePort); // the panel is closing: the program must not outlive it

  fillProviders(P.SITE_IDS);
  showSwitch();
  showObserved();
  $("scope").value = savedScope() || P.defaultScope();
  send({ cmd: "ping" }, "ping").then((reply) => {
    $("status").textContent = reply.ok ? `Connected to boxed.si ${reply.version}` : reply.error;
    $("status").className = reply.ok ? "status ok" : "status bad";
  });
})();
