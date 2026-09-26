"use strict";
// Unit tests for the installer mapping. No dependencies. Run: npm test
const assert = require("assert");
const { assetFor, resolveBinVersion, downloadUrl, VERSION, BIN_VERSION } = require("./install.js");
const pkg = require("./package.json");

assert.strictEqual(assetFor("linux-x64"), "heides-x86_64-unknown-linux-gnu");
assert.strictEqual(assetFor("linux-arm64"), "heides-aarch64-unknown-linux-gnu");
assert.strictEqual(assetFor("linux-arm64-termux"), "heides-aarch64-linux-android");
assert.strictEqual(assetFor("android-arm64"), "heides-aarch64-linux-android");
assert.strictEqual(assetFor("darwin-arm64"), "heides-aarch64-apple-darwin");
assert.strictEqual(assetFor("darwin-x64"), "heides-x86_64-apple-darwin");
assert.strictEqual(assetFor("win32-x64"), "heides-x86_64-pc-windows-msvc.exe");
assert.strictEqual(assetFor("freebsd-x64"), null);

// The installer used to hardcode 0.14.4 while the package said 0.14.5, so
// heides --version and the published version disagreed. One assertion locks it.
assert.strictEqual(VERSION, pkg.version, "VERSION must come from package.json");
assert.strictEqual(
  BIN_VERSION,
  VERSION,
  "BIN_VERSION must default to the package version, found " + BIN_VERSION + " vs " + VERSION
);

// A v prefixed pin used to build a vv0.14.4 tag and 404. Tolerated now.
assert.strictEqual(resolveBinVersion({ HEIDES_BIN_VERSION: "v0.14.4" }), "0.14.4");
assert.strictEqual(resolveBinVersion({ HEIDES_BIN_VERSION: "0.14.4" }), "0.14.4");
// The same variable the curl installer uses, so one pin works everywhere.
assert.strictEqual(resolveBinVersion({ HEIDES_VERSION: "0.13.0" }), "0.13.0");
assert.strictEqual(resolveBinVersion({}), pkg.version);
// The binary specific pin wins over the shared one.
assert.strictEqual(
  resolveBinVersion({ HEIDES_BIN_VERSION: "0.14.5", HEIDES_VERSION: "0.13.0" }),
  "0.14.5"
);
const url = downloadUrl("heides-aarch64-linux-android", resolveBinVersion({ HEIDES_BIN_VERSION: "v0.14.4" }));
assert.ok(url.includes("/releases/download/v0.14.4/"), url);
assert.ok(!url.includes("vv"), url);

console.log("heides installer mapping: 8/8 ok, version lock: " + VERSION + ", pin handling: ok");
