// Determinism gate.
//
// The spine must be a pure function of the code on disk. Two fresh scans of
// the same tree must print byte identical output and write a byte identical
// index. Parallel parsing only merges in file order, so no thread can race
// the result. This test pins that guarantee and fails the build on any drift.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_heides");

fn fixture() -> PathBuf {
    std::env::temp_dir().join(format!("heides_det_{}", std::process::id()))
}

fn write_fixture(dir: &std::path::Path) {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n\npub fn greet(name: &str) -> String {\n    format!(\"hi {}\", name)\n}\n",
    )
    .unwrap();
    std::fs::write(
        src.join("main.rs"),
        "mod lib;\n\nfn main() {\n    let x = lib::add(2, 3);\n    println!(\"{}\", x);\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.js"),
        "const cfg = {port: 8080};\nfunction get(k) { return cfg[k]; }\nget(\"port\");\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.py"),
        "def fetch(url):\n    return requests.get(url)\n\nfetch(\"https://example.com\")\n",
    )
    .unwrap();
}

fn fresh_scan(dir: &std::path::Path) -> (String, Vec<u8>) {
    let index = dir.join(".heides/index.bin");
    if index.exists() {
        std::fs::remove_file(&index).unwrap();
    }
    let out = Command::new(BIN)
        .arg("scan")
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let bytes = std::fs::read(&index).unwrap_or_default();
    (stdout, bytes)
}

#[test]
fn scan_is_byte_identical_across_runs() {
    let dir = fixture();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_fixture(&dir);

    let (out1, index1) = fresh_scan(&dir);
    let (out2, index2) = fresh_scan(&dir);

    assert_eq!(
        out1, out2,
        "two fresh scans printed different output, determinism broken"
    );
    assert!(!index1.is_empty(), "scan did not write the index");
    assert_eq!(
        index1, index2,
        "two fresh scans wrote different index bytes, determinism broken"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
