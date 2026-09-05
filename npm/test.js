"use strict";
// Unit tests for the installer mapping. No dependencies. Run: npm test
const assert = require("assert");
const { assetFor } = require("./install.js");

assert.strictEqual(assetFor("linux-x64"), "heides-x86_64-unknown-linux-gnu");
assert.strictEqual(assetFor("linux-arm64"), "heides-aarch64-unknown-linux-gnu");
assert.strictEqual(assetFor("linux-arm64-termux"), "heides-aarch64-linux-android");
assert.strictEqual(assetFor("darwin-arm64"), "heides-aarch64-apple-darwin");
assert.strictEqual(assetFor("darwin-x64"), "heides-x86_64-apple-darwin");
assert.strictEqual(assetFor("win32-x64"), "heides-x86_64-pc-windows-msvc.exe");
assert.strictEqual(assetFor("android-arm64"), null);
assert.strictEqual(assetFor("freebsd-x64"), null);

console.log("heides installer mapping: 8/8 ok");
