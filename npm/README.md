# heides (npm installer)

[![npm](https://img.shields.io/npm/v/heides)](https://www.npmjs.com/package/heides) [![license](https://img.shields.io/npm/l/heides)](LICENSE) [![MCP](https://img.shields.io/badge/MCP-compatible-blue)](https://modelcontextprotocol.io) [![Tawakkul Labs](https://img.shields.io/badge/by-Tawakkul%20Labs-0f766e)](https://tawakkul-labs.co.ke)

Installs the prebuilt [HEIDES](https://github.com/AbduljabbarBXR/heides) binary for your platform and exposes the `heides` command. HEIDES is a deterministic code analysis harness that gives AI agents senses, memory and judgment for code.

```bash
npm install -g heides
heides --help
```

On install, the matching binary is downloaded from GitHub Releases into the package `bin/` folder. No Rust toolchain needed.

## Supported platforms

| OS | Arch | Asset |
|----|------|-------|
| Linux (glibc) | x64 | `heides-x86_64-unknown-linux-gnu` |
| Linux (glibc) | arm64 | `heides-aarch64-unknown-linux-gnu` |
| Android (Termux) | arm64 | `heides-aarch64-linux-android` |
| macOS | arm64 | `heides-aarch64-apple-darwin` |
| macOS | x64 | `heides-x86_64-apple-darwin` |
| Windows | x64 | `heides-x86_64-pc-windows-msvc.exe` |

Linux arm64 and Android are mapped to real release assets, not errors. The one
family that stops the installer is musl, so Alpine needs a source build
(`cargo install heides`) or a manual pick from the
[releases page](https://github.com/AbduljabbarBXR/heides/releases). Any other
unmapped platform errors the same way.

## Pinning a version

The published package version is the single source of truth for which binary
tag gets downloaded, and a test fails the build if the two ever drift.

```bash
npm install -g heides                 # binary tag follows the package version
HEIDES_VERSION=0.14.4 npm install -g heides   # same variable the curl installer uses
HEIDES_BIN_VERSION=0.14.4 npm install -g heides   # binary specific pin, wins over HEIDES_VERSION
```

Both variables take a bare version such as `0.14.4`. A leading `v` is accepted
and stripped, so `v0.14.4` does not turn into a `vv0.14.4` tag that 404s.

## Usage

Same as the native binary:

```bash
heides scan .
heides check .
heides mcp   # MCP server over stdio for agents
```

## Versions

`package.json` is the single source of truth for the downloaded binary tag, and
`npm test` fails if it ever drifts from what the installer uses. `heides@0.14.4`
installs the HEIDES 0.14.4 binary. `HEIDES_BIN_VERSION` or `HEIDES_VERSION`
override it for a pin.

## Uninstall

```bash
npm uninstall -g heides
```

## License

MIT. See [LICENSE](./LICENSE). Binary builds follow the [HEIDES repo license](https://github.com/AbduljabbarBXR/heides).

---

Links: [npm](https://www.npmjs.com/package/heides) | [GitHub](https://github.com/AbduljabbarBXR/heides) | [Tawakkul Labs](https://tawakkul-labs.co.ke)
