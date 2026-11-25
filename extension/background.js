// The toolbar button opens the side panel. When the person has turned Observe on, this worker also watches the requests
// that send a message from the five chats and gives the text to the boxed.si program on this computer. It never holds
// a request back or changes it, and it keeps no text: only the site, the time, the counts the program found and the coverage.
// A module so that it can import the shared libraries; they publish themselves on self.
import "./lib/protocol.js";
import "./lib/observe.js";

const P = self.boxedProtocol;
const O = self.boxedObserve;
const KEEP = 20; // results kept in this browser session
const MAX_PENDING = 5; // sends waiting for the program, the one it is answering included; each holds its request body
const ANSWER_MS = 20000; // how long the program may take over one send

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch((error) => console.error(error));

// The program is asked about one send at a time, and the list of results is read, changed and written back one change at a time.
let queue = Promise.resolve();
let pending = 0;
let writing = Promise.resolve();

async function enabled() {
  try {
    return (await chrome.storage.local.get({ [P.OBSERVE_KEY]: false }))[P.OBSERVE_KEY] === true;
  } catch {
    return false;
  }
}

// One question to the program, through a port so that it can be given up on. The port is closed once the answer has
// come, or has not come in time, which also ends the program's process. Resolves to what parseReply makes of the
// answer, to {ok: false} when the program is missing or exits, and to {ok: false, late: true} when it is too slow.
function ask(request) {
  return new Promise((resolve) => {
    let port;
    let timer;
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        port.disconnect();
      } catch {
        // there is no port to close
      }
      resolve(result);
    };
    try {
      port = chrome.runtime.connectNative(P.HOST_NAME);
      port.onMessage.addListener((reply) => finish(P.parseReply(reply, "observe")));
      port.onDisconnect.addListener(() => {
        void chrome.runtime.lastError; // read, so that the browser does not log it; its text is not needed
        finish({ ok: false });
      });
      timer = setTimeout(() => finish({ ok: false, late: true }), ANSWER_MS);
      port.postMessage(request);
    } catch {
      finish({ ok: false });
    }
  });
}

function record(entry) {
  writing = writing.then(() => remember(entry)).catch(() => {});
  return writing;
}

async function remember(entry) {
  const stored = (await chrome.storage.session.get({ [P.OBSERVED_KEY]: [] }))[P.OBSERVED_KEY];
  // newest send first, also when an answer for an older one comes in late
  const results = [entry, ...(Array.isArray(stored) ? stored : [])].sort((a, b) => b.time - a.time);
  await chrome.storage.session.set({ [P.OBSERVED_KEY]: results.slice(0, KEEP) });
}

async function observe(site, requestBody, time) {
  if (!(await enabled())) return; // switched off while this send was waiting for its turn
  const { text, coverage } = O.extractPrompt(site, requestBody);
  const reply = await ask(P.buildObserveRequest(site, text, coverage));
  await record({ site, time, found: reply.ok ? reply.found : null, coverage: reply.late ? "not checked" : coverage });
}

function accept(site, requestBody, time) {
  if (pending >= MAX_PENDING) {
    // too many are waiting for the program: this send is kept as a gap and its body is let go of here
    record({ site, time, found: null, coverage: "not checked" });
    return;
  }
  pending += 1;
  queue = queue
    .then(() => observe(site, requestBody, time))
    .catch(() => {})
    .finally(() => {
      pending -= 1;
    });
}

// Registered here, at the top level, so the browser can wake the worker for it. Not blocking: the listener returns nothing.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const site = O.matchRequest(details);
    if (!site) return;
    const time = Date.now();
    // The switch is read before a send is let into the line, so that a send is never held, body and all, while it is off.
    enabled().then((on) => {
      if (on) accept(site, details.requestBody, time);
    });
  },
  { urls: P.SITES, types: ["xmlhttprequest"] }, // the chats send with fetch or XHR; nothing else is shown to this worker
  ["requestBody"],
);
