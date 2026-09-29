#!/usr/bin/env node
/* heides launcher. Runs the platform binary, downloading it if it is missing.
 *
 * The binary is normally fetched by the postinstall hook, but npm 11.16+ blocks
 * lifecycle scripts from dependencies by default, and `--allow-scripts` is not
 * usable on npm 11.17: passing the flag on the command line makes the CLI throw
 * `Cannot destructure property 'name' of '.for' as it is undefined` before the
 * install runs at all. So on those versions the postinstall never fires, the
 * package installs, and `heides` then fails at every command.
 *
 * Rather than tell the user to reinstall, the launcher repairs itself: if the
 * binary is absent, it runs the same install.js the postinstall would have run.
 * Detection logic is NOT duplicated here. install.js owns the platform table and
 * the Termux case; this only decides whether to call it.
 */
"use strict";

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function binaryPath() {
  const exe = process.platform === "win32" ? "heides.exe" : "heides";
  return path.join(__dirname, exe);
}

function installScript() {
  return path.join(__dirname, "..", "install.js");
}

function ensureBinary() {
  if (fs.existsSync(binaryPath())) return true;
  const script = installScript();
  if (!fs.existsSync(script)) {
    console.error(
      "heides: binary not found and install.js is missing."
    );
    console.error("Reinstall with: npm install -g heides");
    return false;
  }
  // npm normally hides this, and on a network failure the user is watching a
  // silent stall, so say what is happening before doing it.
  console.error(
    "heides: binary missing, fetching it now (npm blocked the postinstall hook)."
  );
  const r = spawnSync(process.execPath, [script], { stdio: "inherit" });
  if (r.error) {
    console.error(`heides: download failed (${r.error.message}).`);
    return false;
  }
  if (r.status !== 0) {
    console.error("heides: download failed. Check your network, then run:");
    console.error("  node \"$(npm root -g)/heides/install.js\"");
    return false;
  }
  if (!fs.existsSync(binaryPath())) {
    console.error("heides: install.js finished but no binary was produced.");
    console.error(
      "Build from source instead: cargo build --release"
    );
    return false;
  }
  return true;
}

function main() {
  if (!ensureBinary()) {
    console.error("Builds: https://github.com/AbduljabbarBXR/heides/releases");
    process.exit(1);
  }
  const result = spawnSync(binaryPath(), process.argv.slice(2), {
    stdio: "inherit",
  });
  if (result.error) {
    console.error(`heides: could not run the binary (${result.error.message}).`);
    console.error("Your platform may need a different build:");
    console.error("https://github.com/AbduljabbarBXR/heides/releases");
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

if (require.main === module) main();

module.exports = { binaryPath, ensureBinary };
