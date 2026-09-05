#!/usr/bin/env node
/*
 * heides npm installer.
 * Downloads the prebuilt HEIDES binary for the current platform from
 * GitHub Releases into ./bin/ next to the launcher.
 */
"use strict";

const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");

const VERSION = require("./package.json").version;
const REPO = "AbduljabbarBXR/heides";
const BIN_NAME = "heides";

const ASSETS = {
  "linux-x64": "heides-x86_64-unknown-linux-gnu",
  "linux-arm64": "heides-aarch64-unknown-linux-gnu",
  "linux-arm64-termux": "heides-aarch64-linux-android",
  "darwin-arm64": "heides-aarch64-apple-darwin",
  "darwin-x64": "heides-x86_64-apple-darwin",
  "win32-x64": "heides-x86_64-pc-windows-msvc.exe",
};

function currentKey() {
  if (process.env.HEIDES_TEST_PLATFORM) return process.env.HEIDES_TEST_PLATFORM;
  return `${process.platform}-${process.arch}`;
}

function assetFor(key) {
  return ASSETS[key] || null;
}

function exeName() {
  return process.platform === "win32" ? `${BIN_NAME}.exe` : BIN_NAME;
}

function isTermux() {
  try {
    if (process.env.PREFIX && process.env.PREFIX.includes("com.termux")) return true;
    if (fs.existsSync("/data/data/com.termux/files/usr/bin")) return true;
    return false;
  } catch {
    return false;
  }
}

function isMusl() {
  try {
    if (fs.existsSync("/etc/alpine-release")) return true;
    const osRelease = fs.readFileSync("/etc/os-release", "utf8");
    return /(^|\n)ID_LIKE=.*musl/.test(osRelease) || /(^|\n)ID=alpine/.test(osRelease);
  } catch {
    return false;
  }
}

function download(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "heides-npm-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          if (redirects === 0) return reject(new Error("too many redirects"));
          res.resume();
          return resolve(download(res.headers.location, dest, redirects - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`download failed: HTTP ${res.statusCode} for ${url}`));
        }
        const out = fs.createWriteStream(dest, { mode: 0o755 });
        res.pipe(out);
        out.on("finish", () => resolve());
        out.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const key = currentKey();
  let asset = assetFor(key);
  // Termux reports linux-arm64 but needs the bionic Android build.
  if (key === "linux-arm64" && isTermux()) {
    asset = assetFor("linux-arm64-termux");
  }
  if (!asset) {
    console.error(`heides: no prebuilt binary for ${process.platform}-${process.arch}.`);
    console.error("Install from source instead: cargo install heides");
    console.error(`Or pick a build manually: https://github.com/${REPO}/releases`);
    process.exit(1);
  }
  if (process.platform === "linux" && isMusl()) {
    console.error("heides: prebuilt binaries are glibc linked and will not run on musl (Alpine).");
    console.error("Install from source instead: cargo install heides");
    process.exit(1);
  }
  const binDir = path.join(__dirname, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const dest = path.join(binDir, exeName());
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
  console.log(`heides: downloading ${asset} ...`);
  await download(url, dest);
  if (process.platform !== "win32") fs.chmodSync(dest, 0o755);
  console.log(`heides: installed ${dest}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`heides install failed: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { assetFor, currentKey, exeName, isMusl, isTermux, VERSION };
