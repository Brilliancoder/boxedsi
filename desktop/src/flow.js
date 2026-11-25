// The logic of the one screen, with no DOM and no Tauri: what to ask the masking engine and what to show. main.js wires it to
// the page. It keeps the names of the scopes it has seen (names, not text) and nothing else: the text of a request or an answer
// lives in the call that carried it and on the screen, not here.

// The levels, as the core does them (boxed.detect.KINDS_BY_LEVEL). Level 4 is a plan, not a masking: not offered.
export const LEVELS = [
  { level: 0, name: "As is" },
  { level: 1, name: "Personal data" },
  { level: 2, name: "Company" },
  { level: 3, name: "Strict" },
];

// People and companies are found only by a name model, and which models there are is the engine's to say (ping): the patterns of
// the core find e-mail addresses, numbers and the like, but no name. So what a level promises about names comes from `detects`
// ({ known, ru, en }, see detection()): never a promise the engine cannot keep.
const BARE = { known: false, ru: false, en: false };

function peopleClause({ known, ru, en }) {
  if (ru && en) return "People's names are found by the Russian and English models; a name can still be missed.";
  if (ru) {
    return "Russian names are found by a small model, and some can be missed. English names are not reliably found: that needs the ner-en extra, which this program does not include.";
  }
  if (en) return "Names are found by the English model, which reads Russian too; a name can still be missed.";
  if (known) return "People's names are not found: the masking engine has no name model.";
  return "People's names: it is not known whether they are found, because the masking engine did not say.";
}

function companyClause({ known, ru, en }) {
  if (ru && en) return "Company names are found by the same models.";
  if (ru) return "Russian company names are found by the same small model; English ones are not reliably found.";
  if (en) return "Company names are found by the English model.";
  if (known) return "Company names are not found.";
  return "Company names: it is not known whether they are found.";
}

export function levelHelp(level, detects = BARE) {
  switch (level) {
    case 0:
      return "Replaced: secrets, keys, tokens and card numbers.";
    case 1:
      return `Replaced: also e-mail addresses, phone numbers, IP addresses, bank and tax numbers. ${peopleClause(detects)}`;
    case 2:
      return (
        `Replaced: also hosts, links and the terms of your dictionary. ${companyClause(detects)}` +
        (detects.ru || detects.en ? " Context can still identify a person." : "")
      );
    default:
      return "Replaced: also all amounts, percentages, dates and numbers.";
  }
}

// What the ping of the engine says about the name models it runs: `ner` (on for this process) and `ner_installed` (their
// libraries are there). A model that runs without its library finds nothing.
function detection(reply) {
  if (!Array.isArray(reply?.ner)) return BARE;
  const installed = Array.isArray(reply.ner_installed) ? reply.ner_installed : null;
  const works = (name) => reply.ner.includes(name) && (installed === null || installed.includes(name));
  return { known: true, ru: works("ru"), en: works("en") };
}

function namesLabel({ known, ru, en }) {
  if (ru && en) return "Russian and English models";
  if (ru) return "Russian model";
  if (en) return "English model";
  return known ? "none" : "not known";
}

const UNREACHABLE = "The program could not reach its masking engine.";
const UNEXPECTED = "The masking engine gave an unexpected answer.";
const NO_TEXT = "Type or paste some text first.";
const BAD_LEVEL = "Choose a level from 0 to 3.";
const BAD_SCOPE = "A scope name is letters, digits, dots, underscores and hyphens, up to 64 characters, and starts with a letter or a digit.";
const NO_SCOPE = "Enter the scope of the masked text first: it is shown after Mask, and the list holds the earlier ones.";
const SCOPE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_NOTES = 50;
const MAX_SCOPES = 20;

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;
const strings = (value) => (Array.isArray(value) ? value.filter((item) => typeof item === "string").slice(0, MAX_NOTES) : []);

// How the engine has been doing, in numbers only: the sidecar's own words never reach the page.
function details(reply) {
  if (!Number.isInteger(reply.restarts)) return "";
  const how = Number.isInteger(reply.exit_code)
    ? `, last exit code ${reply.exit_code}`
    : Number.isInteger(reply.signal)
      ? `, ended by signal ${reply.signal}`
      : "";
  return ` Restarted ${plural(reply.restarts, "time", "times")}${how}.`;
}

// request(cmd, fields) resolves to the reply object of the engine, or throws. Returns { reply } or { failure, retry }.
async function ask(request, cmd, fields) {
  let reply;
  try {
    reply = await request(cmd, fields);
  } catch {
    return { failure: UNREACHABLE }; // never the text of the exception: it could quote what was sent
  }
  if (!reply || typeof reply !== "object" || typeof reply.ok !== "boolean") return { failure: UNEXPECTED };
  if (!reply.ok) {
    const sentence = typeof reply.error === "string" && reply.error ? reply.error : UNEXPECTED;
    return { failure: sentence + details(reply), retry: reply.code === "gave-up" };
  }
  return { reply };
}

// store: { load() -> names, save(names) } for the scope names that outlive the window; it may fail, and then the names are kept
// for this run only.
export function createFlow(request, { store } = {}) {
  const attempt = (action, fallback) => {
    try {
      return action();
    } catch {
      return fallback;
    }
  };
  const loaded = attempt(() => store?.load() ?? [], []);
  const state = { scopes: (Array.isArray(loaded) ? loaded : []).filter((name) => typeof name === "string" && SCOPE_NAME.test(name)).slice(-MAX_SCOPES) };

  const remember = (scope) => {
    if (!state.scopes.includes(scope)) state.scopes = [...state.scopes, scope].slice(-MAX_SCOPES);
    attempt(() => store?.save(state.scopes));
  };

  // text: null leaves the text on the screen as it is
  const failed = (status, retry = false) => ({ text: null, mode: null, status, error: true, retry, notes: [], scope: null });

  return {
    state,

    async ping() {
      const { reply, failure, retry } = await ask(request, "ping", {});
      if (failure) return { ready: false, status: failure, detects: BARE, retry: retry === true };
      const detects = detection(reply);
      const version = typeof reply.version === "string" ? ` (version ${reply.version.slice(0, 32)})` : "";
      return { ready: true, status: `Masking engine ready${version}. Names: ${namesLabel(detects)}.`, detects, retry: false };
    },

    // The shell forgets the failures and starts the engine again; then it is asked again.
    async retry() {
      const { failure } = await ask(request, "restart", {});
      if (failure) return { ready: false, status: failure, detects: BARE, retry: false };
      return this.ping();
    },

    // scope: "" for a new scope (the engine makes one and says its name), or the name of the one the masks of this working
    // session share, so that a placeholder stays one thing across them.
    async mask(text, level, scope = "") {
      if (typeof text !== "string" || text.trim() === "") return failed(NO_TEXT);
      if (!Number.isInteger(level) || level < 0 || level > 3) return failed(BAD_LEVEL);
      if (typeof scope !== "string" || (scope !== "" && !SCOPE_NAME.test(scope))) return failed(BAD_SCOPE);
      const fields = scope === "" ? { text, level } : { text, level, scope };
      const { reply, failure, retry } = await ask(request, "mask", fields);
      if (failure) return failed(failure, retry);
      if (typeof reply.text !== "string" || typeof reply.scope !== "string" || !SCOPE_NAME.test(reply.scope)) return failed(UNEXPECTED);
      remember(reply.scope);
      const counts = Object.values(reply.markers_by_kind ?? {});
      const items = counts.reduce((sum, count) => sum + (Number.isInteger(count) ? count : 0), 0);
      return {
        text: reply.text,
        mode: "masked",
        status: `Masked ${plural(items, "item", "items")} at level ${level}. Copy the text above and send it, then paste the answer here and press Restore.`,
        error: false,
        retry: false,
        notes: [],
        scope: reply.scope,
      };
    },

    // scope: the scope of the text that was sent, which is not always the last one: an answer may come for an older one.
    async restore(text, scope = "") {
      if (typeof text !== "string" || text.trim() === "") return failed(NO_TEXT);
      if (typeof scope !== "string" || (scope !== "" && !SCOPE_NAME.test(scope))) return failed(BAD_SCOPE);
      if (scope === "") return failed(NO_SCOPE);
      const { reply, failure, retry } = await ask(request, "restore", { text, scope });
      if (failure) return failed(failure, retry);
      if (typeof reply.text !== "string") return failed(UNEXPECTED);
      const notes = [];
      const unknown = strings(reply.unknown);
      const suspicious = strings(reply.suspicious);
      if (unknown.length) notes.push({ title: "Not found for this scope", items: unknown });
      if (suspicious.length) notes.push({ title: "Look changed, check by hand", items: suspicious });
      const count = Number.isInteger(reply.restored) ? reply.restored : 0;
      const status =
        `Restored ${plural(count, "placeholder", "placeholders")}.` +
        (notes.length ? " Some could not be restored, see below." : "") +
        " This text stays in this window.";
      return { text: reply.text, mode: "restored", status, error: false, retry: false, notes, scope };
    },
  };
}
