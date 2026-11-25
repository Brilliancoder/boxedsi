import { invoke } from "@tauri-apps/api/core";

import { createFlow, levelHelp, LEVELS } from "./flow.js";

// The window shows text through .value and .textContent only, never as markup. The one thing it can ask of the program is a
// request to the masking engine (capabilities/default.json). It keeps no text: the only thing it stores is the names of the
// scopes, which are not text (a short list in local storage, so that an answer that comes tomorrow can still be restored).
const MODES = { masked: "Masked text", restored: "Restored text - stays in this window" };
const SCOPES_KEY = "boxed.scopes";

const $ = (id) => document.getElementById(id);
const store = {
  load: () => JSON.parse(localStorage.getItem(SCOPES_KEY) ?? "[]"),
  save: (names) => localStorage.setItem(SCOPES_KEY, JSON.stringify(names)),
};
const flow = createFlow((cmd, fields) => invoke("sidecar_request", { cmd, fields }), { store });

const text = $("text");
const scope = $("scope");
const level = $("level");
const buttons = [$("mask"), $("restore"), $("new-scope"), level, scope];
let detects = { known: false, ru: false, en: false };

for (const { level: value, name } of LEVELS) {
  level.append(new Option(`${value} - ${name}`, String(value), false, value === 2));
}

function showLevelHelp() {
  $("level-help").textContent = levelHelp(Number(level.value), detects);
}

function showScopes() {
  $("scopes").replaceChildren(...[...flow.state.scopes].reverse().map((name) => new Option(name)));
}

function show(view) {
  if (view.text !== null) text.value = view.text;
  if (view.mode) $("mode").textContent = MODES[view.mode];
  if (view.scope) scope.value = view.scope;
  const status = $("status");
  status.textContent = view.status;
  status.dataset.error = String(view.error);
  $("retry").hidden = !view.retry;
  showScopes();
  $("notes").replaceChildren(
    ...view.notes.map(({ title, items }) => {
      const section = document.createElement("section");
      const heading = document.createElement("h2");
      heading.textContent = title;
      const list = document.createElement("ul");
      list.append(
        ...items.map((item) => {
          const entry = document.createElement("li");
          entry.textContent = item;
          return entry;
        }),
      );
      section.append(heading, list);
      return section;
    }),
  );
}

function showEngine(view) {
  $("engine").textContent = view.status;
  $("retry").hidden = !view.retry;
  detects = view.detects;
  showLevelHelp();
}

async function run(action) {
  for (const button of buttons) button.disabled = true;
  $("status").textContent = "Working...";
  $("status").dataset.error = "false";
  $("retry").hidden = true;
  try {
    show(await action());
  } finally {
    for (const button of buttons) button.disabled = false;
  }
}

$("mask").addEventListener("click", () => run(() => flow.mask(text.value, Number(level.value), scope.value.trim())));
$("restore").addEventListener("click", () => run(() => flow.restore(text.value, scope.value.trim())));
$("new-scope").addEventListener("click", () => {
  scope.value = "";
  $("status").textContent = "The next Mask starts a new scope.";
  $("status").dataset.error = "false";
});
$("retry").addEventListener("click", async () => {
  $("retry").hidden = true;
  $("engine").textContent = "Starting the masking engine...";
  showEngine(await flow.retry());
});
level.addEventListener("change", showLevelHelp);
showLevelHelp();
showScopes();

flow.ping().then(showEngine);
