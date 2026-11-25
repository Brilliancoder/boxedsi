"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const EXTENSION = path.join(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(EXTENSION, "manifest.json"), "utf8"));
const SIZES = ["16", "32", "48", "128"];

// Width and height from the IHDR chunk of a PNG file.
function pngSize(file) {
  const data = fs.readFileSync(file);
  assert.equal(data.subarray(0, 8).toString("hex"), "89504e470d0a1a0a", `${file} is not a PNG`);
  assert.equal(data.subarray(12, 16).toString("ascii"), "IHDR");
  return [data.readUInt32BE(16), data.readUInt32BE(20)];
}

test("the version is the version of the Python package", () => {
  const init = fs.readFileSync(path.join(EXTENSION, "..", "src", "boxed", "__init__.py"), "utf8");
  assert.equal(manifest.version, init.match(/__version__ = "([^"]+)"/)[1]);
});

test("the manifest names the extension and its project page", () => {
  assert.equal(manifest.homepage_url, "https://boxed.si");
  assert.equal(manifest.name, "boxed.si");
});

test("every icon the manifest names is a PNG of its declared size, for the extension and for the toolbar button", () => {
  assert.deepEqual(Object.keys(manifest.icons).sort(), [...SIZES].sort());
  assert.deepEqual(manifest.action.default_icon, manifest.icons);
  for (const [size, file] of Object.entries(manifest.icons)) {
    assert.deepEqual(pngSize(path.join(EXTENSION, file)), [Number(size), Number(size)], file);
  }
});
