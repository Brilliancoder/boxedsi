"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const O = require("../lib/observe.js");
const P = require("../lib/protocol.js");

const enc = new TextEncoder();
// What chrome.webRequest hands over for a body that is not a form: raw bytes in ArrayBuffers.
const bodyOf = (value) => ({ raw: [{ bytes: enc.encode(typeof value === "string" ? value : JSON.stringify(value)).buffer }] });
const checked = (text) => ({ text, coverage: "checked" });
const NOT_CHECKED = { text: "", coverage: "not checked" };

const ORG = "5a1b2c3d-0000-4000-8000-000000000001";
const CHAT = "6e7f8a9b-0000-4000-8000-000000000002";
const SENDS = [
  ["chatgpt", "https://chatgpt.com/backend-api/conversation"],
  ["chatgpt", "https://chatgpt.com/backend-api/f/conversation"],
  ["chatgpt", "https://chatgpt.com/backend-api/conversation?oai-device-id=1"],
  ["claude", `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/completion`],
  ["claude", `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/retry_completion`],
  ["gemini", "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=boq_x&f.sid=1&hl=en&_reqid=100&rt=c"],
  ["deepseek", "https://chat.deepseek.com/api/v0/chat/completion"],
  ["zai", "https://chat.z.ai/api/chat/completions"],
  ["zai", "https://chat.z.ai/api/v1/chat/completions"],
];

test("matchSend names the site of each send", () => {
  for (const [site, url] of SENDS) assert.equal(O.matchSend(url, "POST"), site, url);
});

test("every send that matchSend recognises is on a host the manifest lets the extension see", () => {
  assert.deepEqual([...new Set(SENDS.map(([site]) => site))].sort(), ["chatgpt", "claude", "deepseek", "gemini", "zai"]);
  for (const [, url] of SENDS) assert.equal(P.isAiSite(url), true, url);
});

test("matchSend is null for anything but a POST", () => {
  for (const [, url] of SENDS) {
    for (const method of ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "", undefined, null, 5]) {
      assert.equal(O.matchSend(url, method), null, `${method} ${url}`);
    }
  }
});

test("matchSend is null for the other requests of the same pages", () => {
  const others = [
    "https://chatgpt.com/backend-api/conversations",
    "https://chatgpt.com/backend-api/conversation/6e7f8a9b/title",
    "https://chatgpt.com/backend-api/f/conversation/prepare",
    "https://chatgpt.com/backend-api/conversation/",
    "https://chatgpt.com/backend-api/me",
    "https://chatgpt.com/api/chat/completions", // another site's path
    `https://claude.ai/api/organizations/${ORG}/chat_conversations`,
    `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}`,
    `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/title`,
    `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/completion/stop`,
    `https://claude.ai/api/organizations/${ORG}/chat_conversations/${CHAT}/extra/completion`,
    `https://claude.ai/api/organizations//chat_conversations/${CHAT}/completion`,
    "https://claude.ai/backend-api/conversation", // another site's path
    "https://gemini.google.com/_/BardChatUi/data/batchexecute?rpcids=x",
    "https://gemini.google.com/app",
    "https://chat.deepseek.com/api/v0/chat/completion/abc",
    "https://chat.deepseek.com/api/v0/chat/history_messages",
    "https://chat.deepseek.com/api/v0/chat_session/create",
    "https://chat.z.ai/api/chat/completions/abc",
    "https://chat.z.ai/api/chat/completed",
    "https://chat.z.ai/api/v1/chats/new",
    "https://chat.z.ai/api/vx/chat/completions",
  ];
  for (const url of others) assert.equal(O.matchSend(url, "POST"), null, url);
});

test("matchSend is null for look-alike origins and anything that is not a URL", () => {
  const lookalikes = [
    "https://chatgpt.com.evil.com/backend-api/conversation",
    "https://evilchatgpt.com/backend-api/conversation",
    "https://chatgpt.com@evil.com/backend-api/conversation",
    "https://evil.com/backend-api/conversation?u=https://chatgpt.com/",
    "http://chatgpt.com/backend-api/conversation",
    "https://chatgpt.com:8443/backend-api/conversation",
    "https://www.claude.ai/api/organizations/o/chat_conversations/c/completion",
    "https://chat.deepseek.com.evil.io/api/v0/chat/completion",
    "wss://chat.z.ai/api/chat/completions",
    "",
    "not a url",
    "//chatgpt.com/backend-api/conversation",
    undefined,
    null,
    5,
    {},
  ];
  for (const url of lookalikes) assert.equal(O.matchSend(url, "POST"), null, String(url));
});

// What chrome.webRequest reports for a send the chat's own page makes with fetch: the initiator is the page's origin.
const originOf = (url) => new URL(url).origin;
const sentBy = (url, props = {}) => ({ url, method: "POST", type: "xmlhttprequest", initiator: originOf(url), tabId: 7, frameId: 0, ...props });

test("matchRequest names the site of a send that the chat's own page makes with fetch or XHR", () => {
  for (const [site, url] of SENDS) assert.equal(O.matchRequest(sentBy(url)), site, url);
});

test("matchRequest refuses a send that is not made with fetch or XHR, such as a form posted into a frame", () => {
  const types = ["sub_frame", "main_frame", "other", "ping", "script", "image", "stylesheet", "object", "font", "media", "websocket", "csp_report", "", undefined, null, 5];
  for (const [, url] of SENDS) {
    for (const type of types) assert.equal(O.matchRequest(sentBy(url, { type })), null, `${type} ${url}`);
  }
});

test("matchRequest refuses a send that the chat's own origin did not start", () => {
  const [claude] = SENDS.filter(([site]) => site === "claude");
  const foreign = ["https://evil.example", "null", "", undefined, null, 5, {}, "http://claude.ai", "https://claude.ai.evil.com", "https://claude.ai:8443", "https://www.claude.ai", "https://claude.ai/", "https://claude.ai/path"];
  for (const initiator of foreign) assert.equal(O.matchRequest(sentBy(claude[1], { initiator })), null, String(initiator));
  // a page of one chat posting to the send address of another chat
  for (const [, url] of SENDS) {
    for (const [, other] of SENDS) {
      if (originOf(url) !== originOf(other)) assert.equal(O.matchRequest(sentBy(url, { initiator: originOf(other) })), null, `${originOf(other)} -> ${url}`);
    }
  }
});

test("matchRequest still needs the address and the method, and takes nothing but request details", () => {
  assert.equal(O.matchRequest(sentBy(SENDS[3][1], { method: "GET" })), null);
  assert.equal(O.matchRequest(sentBy("https://claude.ai/api/organizations/o/chat_conversations")), null);
  for (const details of [undefined, null, "https://claude.ai", 5, [], {}]) assert.equal(O.matchRequest(details), null, String(details));
});

test("chatgpt: the text of the user messages, not the system's or the assistant's", () => {
  const body = {
    action: "next",
    messages: [
      { id: "m1", author: { role: "system" }, content: { content_type: "text", parts: ["be brief"] } },
      { id: "m2", author: { role: "user" }, content: { content_type: "text", parts: ["Mail ivan.petrov@acme.com", "and call +7 912 345-67-89"] } },
      { id: "m3", author: { role: "assistant" }, content: { content_type: "text", parts: ["Sure"] } },
      { id: "m4", author: { role: "user" }, content: { content_type: "text", parts: ["Thanks"] } },
    ],
    parent_message_id: "p1",
    model: "auto",
  };
  assert.deepEqual(O.extractPrompt("chatgpt", bodyOf(body)), checked("Mail ivan.petrov@acme.com\nand call +7 912 345-67-89\nThanks"));
});

test("chatgpt: a part that is not text, such as an image, is skipped", () => {
  const body = {
    messages: [
      {
        author: { role: "user" },
        content: {
          content_type: "multimodal_text",
          parts: [{ content_type: "image_asset_pointer", asset_pointer: "file-service://file-abc", width: 10, height: 10 }, "what is in this picture?"],
        },
      },
    ],
  };
  assert.deepEqual(O.extractPrompt("chatgpt", bodyOf(body)), checked("what is in this picture?"));
});

test("claude: the prompt field", () => {
  const body = { prompt: "Call +7 912 345-67-89", timezone: "Europe/Moscow", attachments: [], files: [], rendering_mode: "messages" };
  assert.deepEqual(O.extractPrompt("claude", bodyOf(body)), checked("Call +7 912 345-67-89"));
});

test("deepseek: the prompt field", () => {
  const body = { chat_session_id: "s1", parent_message_id: null, prompt: "key AKIAIOSFODNN7EXAMPLE", ref_file_ids: [], thinking_enabled: true };
  assert.deepEqual(O.extractPrompt("deepseek", bodyOf(body)), checked("key AKIAIOSFODNN7EXAMPLE"));
});

test("zai: the last user message, earlier ones are history", () => {
  const body = {
    stream: true,
    model: "glm-4.6",
    chat_id: "c1",
    messages: [
      { role: "system", content: "be brief" },
      { role: "user", content: "first question" },
      { role: "assistant", content: "first answer" },
      { role: "user", content: "second question about ivan@acme.com" },
    ],
  };
  assert.deepEqual(O.extractPrompt("zai", bodyOf(body)), checked("second question about ivan@acme.com"));
});

test("zai: a message made of parts gives its text parts and skips the images", () => {
  const body = {
    messages: [
      { role: "user", content: [{ type: "text", text: "describe" }, { type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } }, { type: "text", text: "this" }] },
    ],
  };
  assert.deepEqual(O.extractPrompt("zai", bodyOf(body)), checked("describe\nthis"));
});

// The form as the browser parses it: f.req is JSON whose element 1 is a string of JSON that starts with the prompt.
const geminiField = (prompt) => {
  const inner = JSON.stringify([[prompt, 0, null, [], null, null, 0], ["en"], ["", "", ""], null, null, null, [0], 0, [], [], 1, 0]);
  return JSON.stringify([null, inner]);
};
const geminiForm = (prompt) => ({ formData: { "f.req": [geminiField(prompt)], at: ["AB_token:123"] } });

test("gemini: the prompt inside the JSON inside the JSON of the f.req form field", () => {
  const prompt = 'Say "hi"\nthen \\ and 日本語, card 4111 1111 1111 1111';
  assert.deepEqual(O.extractPrompt("gemini", geminiForm(prompt)), checked(prompt));
});

test("text is read as UTF-8", () => {
  assert.deepEqual(O.extractPrompt("claude", bodyOf({ prompt: "Привет, мой email ivan@acme.com" })), checked("Привет, мой email ivan@acme.com"));
});

test("a body that arrives in several chunks is joined before it is decoded", () => {
  const bytes = enc.encode(JSON.stringify({ prompt: "Привет, ivan@acme.com" }));
  const cut = bytes.indexOf(0xd0) + 1; // between the two bytes of the first Cyrillic letter
  const body = { raw: [{ bytes: bytes.slice(0, cut).buffer }, { bytes: bytes.slice(cut).buffer }] };
  assert.deepEqual(O.extractPrompt("claude", body), checked("Привет, ivan@acme.com"));
});

const JSON_SITES = ["chatgpt", "claude", "deepseek", "zai"];
const NO_BODY = [
  undefined,
  null,
  {},
  { raw: [] },
  { error: "Unknown error" },
  { raw: [{ file: "/tmp/upload" }] },
  { raw: [{ bytes: "text, not a buffer" }] },
  { formData: { prompt: ["x"] } },
];
const NOT_JSON = ["", "{not json", "{", "<html></html>", "prompt=x&other=y"];
const NOT_AN_OBJECT = ["null", "[]", '"text"', "5", "true", "{}"];

test("a body that is missing, unreadable or not JSON is not checked", () => {
  for (const site of [...JSON_SITES, "gemini"]) {
    for (const body of NO_BODY) assert.deepEqual(O.extractPrompt(site, body), NOT_CHECKED, `${site} ${JSON.stringify(body)}`);
  }
  for (const site of JSON_SITES) {
    for (const text of NOT_JSON) assert.deepEqual(O.extractPrompt(site, bodyOf(text)), NOT_CHECKED, `${site} ${text}`);
    for (const text of NOT_AN_OBJECT) assert.deepEqual(O.extractPrompt(site, bodyOf(text)), NOT_CHECKED, `${site} ${text}`);
  }
});

test("bytes that are not UTF-8 are not checked", () => {
  const bad = { raw: [{ bytes: new Uint8Array([0x7b, 0x22, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]).buffer }] };
  assert.deepEqual(O.extractPrompt("claude", bad), NOT_CHECKED);
});

test("a body of another shape than the site's is not checked", () => {
  const user = (parts) => ({ messages: [{ author: { role: "user" }, content: { parts } }] });
  const shapes = {
    chatgpt: [
      { messages: "x" },
      { messages: [] },
      { messages: [null] },
      { messages: [{ author: { role: "assistant" }, content: { parts: ["x"] } }] },
      { messages: [{ author: { role: "user" } }] },
      { messages: [{ role: "user", content: "x" }] },
      user("x"),
      { prompt: "x" },
    ],
    claude: [{ prompt: 5 }, { prompt: ["x"] }, { prompt: null }, { text: "x" }, { messages: [{ role: "user", content: "x" }] }],
    deepseek: [{ prompt: 5 }, { prompt: ["x"] }, { prompt: null }, { text: "x" }],
    zai: [
      { messages: "x" },
      { messages: [] },
      { messages: [null] },
      { messages: [{ role: "assistant", content: "x" }] },
      { messages: [{ role: "user" }] },
      { messages: [{ role: "user", content: 5 }] },
      { prompt: "x" },
    ],
  };
  for (const [site, bodies] of Object.entries(shapes)) {
    for (const body of bodies) assert.deepEqual(O.extractPrompt(site, bodyOf(body)), NOT_CHECKED, `${site} ${JSON.stringify(body)}`);
  }
});

test("a user message with parts or content but no text in them is not checked, because the shape may have changed", () => {
  const key = "AKIAIOSFODNN7EXAMPLE";
  const user = (parts) => ({ messages: [{ author: { role: "user" }, content: { content_type: "multimodal_text", parts } }] });
  const cases = [
    ["chatgpt", user([{ type: "text", text: key }])],
    ["chatgpt", user([])],
    ["chatgpt", user([{ content_type: "image_asset_pointer", asset_pointer: "file-service://file-abc" }])],
    ["chatgpt", { messages: [{ author: { role: "user" }, content: { content_type: "text", text: key, parts: [] } }] }],
    // one message that can be read does not cover another that cannot
    ["chatgpt", { messages: [{ author: { role: "user" }, content: { parts: ["fine"] } }, { author: { role: "user" }, content: { parts: [{ type: "text", text: key }] } }] }],
    ["zai", { messages: [{ role: "user", content: [{ type: "input_text", text: key }] }] }],
    ["zai", { messages: [{ role: "user", content: [{ type: "text", value: key }] }] }],
    ["zai", { messages: [{ role: "user", content: [] }] }],
    ["zai", { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "data:image/png;base64,AAAA" } }] }] }],
  ];
  for (const [site, body] of cases) assert.deepEqual(O.extractPrompt(site, bodyOf(body)), NOT_CHECKED, `${site} ${JSON.stringify(body)}`);
});

test("an empty text is still text: a send with only an attachment is checked, with nothing to find", () => {
  assert.deepEqual(O.extractPrompt("chatgpt", bodyOf({ messages: [{ author: { role: "user" }, content: { parts: [""] } }] })), checked(""));
  assert.deepEqual(O.extractPrompt("zai", bodyOf({ messages: [{ role: "user", content: "" }] })), checked(""));
  assert.deepEqual(O.extractPrompt("claude", bodyOf({ prompt: "", files: ["f1"] })), checked(""));
  assert.deepEqual(O.extractPrompt("deepseek", bodyOf({ prompt: "" })), checked(""));
});

test("text that is not well-formed Unicode, such as a lone surrogate, is not checked", () => {
  const json = (text) => ({ raw: [{ bytes: enc.encode(text).buffer }] }); // the escapes are written out: JSON allows a lone surrogate there
  const cases = [
    ["claude", '{"prompt":"key \\ud83d end"}'], // a lone high surrogate
    ["claude", '{"prompt":"key \\ude00 end"}'], // a lone low surrogate
    ["claude", '{"prompt":"\\ude00\\ud83d"}'], // a pair the wrong way round
    ["deepseek", '{"prompt":"\\ud83d"}'],
    ["chatgpt", '{"messages":[{"author":{"role":"user"},"content":{"parts":["fine","and \\ud83d"]}}]}'],
    ["zai", '{"messages":[{"role":"user","content":"x \\ud83d"}]}'],
    ["zai", '{"messages":[{"role":"user","content":[{"type":"text","text":"x \\ud83d"}]}]}'],
  ];
  for (const [site, text] of cases) assert.deepEqual(O.extractPrompt(site, json(text)), NOT_CHECKED, `${site} ${text}`);
  assert.deepEqual(O.extractPrompt("gemini", geminiForm("x \ud83d y")), NOT_CHECKED); // through both layers of JSON
  // a pair (an emoji) is well-formed, and a lone surrogate in a part that is skipped is not part of the text
  assert.deepEqual(O.extractPrompt("claude", json('{"prompt":"ok \\ud83d\\ude00 done"}')), checked("ok \u{1F600} done"));
  assert.deepEqual(O.extractPrompt("claude", bodyOf({ prompt: "emoji \u{1F600}" })), checked("emoji \u{1F600}"));
  const skipped = { messages: [{ author: { role: "user" }, content: { parts: [{ content_type: "image_asset_pointer", asset_pointer: "x \ud83d" }, "fine"] } }] };
  assert.deepEqual(O.extractPrompt("chatgpt", bodyOf(skipped)), checked("fine"));
});

test("a gemini form of another shape is not checked", () => {
  const freq = (value) => ({ formData: { "f.req": [typeof value === "string" ? value : JSON.stringify(value)] } });
  const nested = (inner) => freq([null, typeof inner === "string" ? inner : JSON.stringify(inner)]);
  const bad = [
    { formData: {} },
    { formData: { at: ["token"] } },
    { formData: { "f.req": [] } },
    { formData: { "f.req": [5] } },
    freq("{not json"),
    freq({ not: "an array" }),
    freq([null]),
    freq([null, 5]),
    freq([null, ["not", "a", "string"]]),
    nested("{not json"),
    nested({ not: "an array" }),
    nested([]),
    nested([[]]),
    nested([[5]]),
    bodyOf("f.req=%5Bnull%5D&at=x"), // the same form as raw bytes: the extension only reads what the browser parsed
  ];
  for (const body of bad) assert.deepEqual(O.extractPrompt("gemini", body), NOT_CHECKED, JSON.stringify(body));
});

test("a site the extension does not know is not checked", () => {
  assert.deepEqual(O.extractPrompt("bing", bodyOf({ prompt: "x" })), NOT_CHECKED);
  assert.deepEqual(O.extractPrompt(undefined, bodyOf({ prompt: "x" })), NOT_CHECKED);
});

test("a body over 900 000 bytes is not read, one of exactly 900 000 is", () => {
  const room = 900000 - enc.encode(JSON.stringify({ prompt: "" })).length;
  const atLimit = O.extractPrompt("claude", bodyOf({ prompt: "a".repeat(room) }));
  assert.equal(atLimit.coverage, "checked");
  assert.equal(atLimit.text.length, room);
  assert.deepEqual(O.extractPrompt("claude", bodyOf({ prompt: "a".repeat(room + 1) })), NOT_CHECKED);
});

test("the 900 000 bytes are counted over all chunks together", () => {
  const overhead = enc.encode(JSON.stringify({ prompt: "" })).length;
  const bytes = enc.encode(JSON.stringify({ prompt: "a".repeat(900001 - overhead) })); // valid JSON, one byte over
  assert.equal(bytes.length, 900001);
  const body = { raw: [{ bytes: bytes.slice(0, 450000).buffer }, { bytes: bytes.slice(450000).buffer }] };
  assert.deepEqual(O.extractPrompt("claude", body), NOT_CHECKED);
});

test("a gemini f.req field over 900 000 bytes is not read, one of exactly 900 000 is", () => {
  const overhead = enc.encode(geminiField("")).length;
  const atLimit = O.extractPrompt("gemini", geminiForm("a".repeat(900000 - overhead)));
  assert.equal(atLimit.coverage, "checked");
  assert.equal(atLimit.text.length, 900000 - overhead);
  assert.deepEqual(O.extractPrompt("gemini", geminiForm("a".repeat(900001 - overhead))), NOT_CHECKED);
  // 2 bytes each in UTF-8: under 900 000 characters, over 900 000 bytes
  const wide = geminiField("é".repeat(450001));
  assert.ok(wide.length < 900000 && enc.encode(wide).length > 900000);
  assert.deepEqual(O.extractPrompt("gemini", { formData: { "f.req": [wide] } }), NOT_CHECKED);
});

test("a failure while reading never escapes and never carries the text", () => {
  const hostile = {
    get raw() {
      throw new Error("secret ivan@acme.com");
    },
  };
  let result;
  assert.doesNotThrow(() => {
    result = O.extractPrompt("claude", hostile);
  });
  assert.deepEqual(result, NOT_CHECKED);
});
