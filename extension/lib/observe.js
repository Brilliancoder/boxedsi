// Which request sends a chat message, and what text is in it. This file only reads: it keeps nothing,
// sends nothing and never throws on what a page puts in a request.
// A plain script, like protocol.js: the service worker imports it for its side effect, require() loads it under node --test.
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.boxedObserve = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const MAX_BODY = 900000; // bytes; a message to the program holds at most 1 MB and the text travels inside it

  // Best effort. The paths and body shapes below come from public knowledge of the five sites, not from a contract:
  // every entry here and in EXTRACTORS must be re-checked on the live site before a release (see the README).
  const SENDS = {
    chatgpt: { host: "chatgpt.com", path: /^\/backend-api\/(?:f\/)?conversation$/ },
    claude: {
      host: "claude.ai",
      path: /^\/api\/organizations\/[\w-]+\/chat_conversations\/[\w-]+\/(?:completion|retry_completion)$/,
    },
    gemini: { host: "gemini.google.com", path: /^\/_\/BardChatUi\/data\/assistant\.lamda\.BardFrontendService\/StreamGenerate$/ },
    deepseek: { host: "chat.deepseek.com", path: /^\/api\/v0\/chat\/completion$/ },
    zai: { host: "chat.z.ai", path: /^\/api\/(?:v\d+\/)?chat\/completions$/ },
  };

  // The site whose message this request sends, or null. Only a POST over https to the exact host and path counts.
  function matchSend(url, method) {
    if (method !== "POST") return null;
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (parsed.protocol !== "https:" || parsed.port !== "") return null;
    for (const site of Object.keys(SENDS)) {
      if (parsed.hostname === SENDS[site].host && SENDS[site].path.test(parsed.pathname)) return site;
    }
    return null;
  }

  // A send as the browser reports it (the details chrome.webRequest gives), or null. The address and the method are not
  // enough: any page can post a form into a hidden frame at the same address, and the browser then reports a sub_frame
  // started by that page. The chats send with fetch or XHR from their own pages, so only a request of that type whose
  // initiator is the origin of the chat it goes to counts.
  function matchRequest(details) {
    if (details === null || typeof details !== "object") return null;
    const site = matchSend(details.url, details.method);
    if (site === null || details.type !== "xmlhttprequest") return null;
    return details.initiator === "https://" + SENDS[site].host ? site : null;
  }

  // The bytes of a body the browser did not parse as a form: all chunks joined (a chunk can end inside a character),
  // or null when a chunk is not plain bytes or the whole is over the limit.
  function rawBytes(body) {
    const chunks = body && body.raw;
    if (!Array.isArray(chunks) || chunks.length === 0) return null;
    let size = 0;
    for (const chunk of chunks) {
      const bytes = chunk && chunk.bytes;
      if (Object.prototype.toString.call(bytes) !== "[object ArrayBuffer]") return null;
      size += bytes.byteLength;
      if (size > MAX_BODY) return null;
    }
    const joined = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(new Uint8Array(chunk.bytes), offset);
      offset += chunk.bytes.byteLength;
    }
    return joined;
  }

  // The body as a JSON object, or null. A parse error is never passed on: its text can quote the start of the message.
  function jsonObject(body) {
    const bytes = rawBytes(body);
    if (!bytes) return null;
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  }

  function stringField(body, name) {
    const data = jsonObject(body);
    return data && typeof data[name] === "string" ? data[name] : null;
  }

  // A string of N UTF-16 units has at least N bytes in UTF-8, so a long one is refused without being encoded.
  const tooBig = (text) => text.length > MAX_BODY || new TextEncoder().encode(text).length > MAX_BODY;

  // One per site: the text of the message in the request body, or null when the body is not what the site sends.
  // Text only: attachments travel in other requests and are not looked at.
  const EXTRACTORS = {
    // The strings in content.parts of every message by the user; an image or file part is an object and is skipped.
    // A message with no string in it at all is not read: its text may have moved to a shape this does not know.
    chatgpt(body) {
      const data = jsonObject(body);
      const messages = data && data.messages;
      if (!Array.isArray(messages)) return null;
      const texts = [];
      let users = 0;
      for (const message of messages) {
        if (!message || !message.author || message.author.role !== "user") continue;
        const parts = message.content && message.content.parts;
        const strings = Array.isArray(parts) ? parts.filter((part) => typeof part === "string") : [];
        if (strings.length === 0) return null;
        users += 1;
        texts.push(...strings);
      }
      return users > 0 ? texts.join("\n") : null;
    },
    claude: (body) => stringField(body, "prompt"),
    // the form field f.req is JSON whose element 1 is a string of JSON whose [0][0] is the prompt
    gemini(body) {
      const field = body && body.formData && body.formData["f.req"];
      if (!Array.isArray(field) || typeof field[0] !== "string" || tooBig(field[0])) return null;
      const outer = JSON.parse(field[0]);
      if (!Array.isArray(outer) || typeof outer[1] !== "string") return null;
      const inner = JSON.parse(outer[1]);
      const prompt = Array.isArray(inner) && Array.isArray(inner[0]) ? inner[0][0] : null;
      return typeof prompt === "string" ? prompt : null;
    },
    deepseek: (body) => stringField(body, "prompt"),
    // The last message by the user (earlier ones are history): a string, or a list of parts of which the text ones count.
    // A list without a single text part is not read, for the same reason as above.
    zai(body) {
      const data = jsonObject(body);
      const messages = data && data.messages;
      if (!Array.isArray(messages)) return null;
      const last = messages.findLast((message) => message && message.role === "user");
      if (!last) return null;
      if (typeof last.content === "string") return last.content;
      if (!Array.isArray(last.content)) return null;
      const texts = last.content.filter((part) => part && part.type === "text" && typeof part.text === "string").map((part) => part.text);
      return texts.length > 0 ? texts.join("\n") : null;
    },
  };

  // requestBody: what chrome.webRequest gives, {raw: [{bytes}]} or {formData}. Returns {text, coverage}; a send that cannot
  // be read, whatever the reason, is {text: "", coverage: "not checked"}. So is text with a lone surrogate in it: it cannot
  // be sent to the program as UTF-8, and it is no text a person typed.
  function extractPrompt(site, requestBody) {
    try {
      const text = Object.hasOwn(EXTRACTORS, site) ? EXTRACTORS[site](requestBody) : null;
      if (typeof text === "string" && text.isWellFormed()) return { text, coverage: "checked" };
    } catch {
      // fall through: the error is dropped on purpose
    }
    return { text: "", coverage: "not checked" };
  }

  return { matchSend, matchRequest, extractPrompt };
});
