# heides (npm installer)

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
| macOS | arm64 | `heides-aarch64-apple-darwin` |
| macOS | x64 | `heides-x86_64-apple-darwin` |
| Windows | x64 | `heides-x86_64-pc-windows-msvc.exe` |

Not listed, e.g. Linux arm64, Android, or musl/Alpine: the installer stops with a clear error. Install from source instead (`cargo install heides`) or pick a build from the [releases page](https://github.com/AbduljabbarBXR/heides/releases).

## Usage

Same as the native binary:

```bash
heides scan .
heides check .
heides mcp   # MCP server over stdio for agents
```

## Versions

npm package version tracks the HEIDES release version. `heides@0.13.1` installs HEIDES 0.13.1.

## Uninstall

```bash
npm uninstall -g heides
```

## License

MIT. See [LICENSE](./LICENSE). Binary builds follow the [HEIDES repo license](https://github.com/AbduljabbarBXR/heides).
