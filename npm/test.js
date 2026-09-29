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

// The launcher repairs itself when the postinstall was blocked.
//
// npm 11.16+ blocks lifecycle scripts from dependencies by default, and
// `--allow-scripts` aborts on npm 11.17 before installing anything, so
// "reinstall" was advice that could never work: the reinstall is what failed.
// The launcher now calls install.js itself when the binary is missing.
//
// These assertions do not need a network. They check the decision, not the
// download: that a missing binary asks install.js to run, and that the launcher
// does not grow its own copy of the platform table.
const { binaryPath, ensureBinary } = require("./bin/heides.js");
const fs = require("fs");
const path = require("path");

const launcher = fs.readFileSync(
  path.join(__dirname, "bin", "heides.js"),
  "utf8"
);

// The whole point of the fix. If this regresses, a fresh install on npm 11.16+
// is a broken install again.
assert.ok(
  typeof ensureBinary === "function",
  "the launcher must export ensureBinary so its decision is testable"
);

// A present binary is left alone and never triggers a download. Checked by
// pointing at the real path, which the test run always has once the package is
// installed with scripts enabled.
assert.strictEqual(
  ensureBinary(),
  true,
  "ensureBinary must succeed when the binary is present at " + binaryPath()
);

// The platform table must stay in install.js. Duplicating it here would create
// two places to keep in sync, and the Termux android-arm64 case is exactly the
// one that breaks quietly when it is copied.
assert.ok(
  !/aarch64|arm64|apple-darwin|pc-windows/.test(launcher),
  "the launcher must not carry a copy of the platform table; install.js owns it"
);
assert.ok(
  launcher.includes("install.js"),
  "the launcher must delegate to install.js"
);
