// The hostility suite.
//
// No panic, no crash, no hang. Random bytes, truncated code, deep nesting,
// huge single lines and binary garbage are fed to the parser and every
// guard in every language. A panic anywhere in this suite fails the build.

use heides::{edge, parser, practice, taint};
use std::path::Path;

const LANGS: [(&str, &str); 8] = [
    ("rust", ".rs"),
    ("javascript", ".js"),
    ("typescript", ".ts"),
    ("python", ".py"),
    ("php", ".php"),
    ("go", ".go"),
    ("java", ".java"),
    ("csharp", ".cs"),
];

/// Deterministic LCG so failures reproduce byte for byte.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// Random bytes from a fixed seed.
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Lcg(seed);
    (0..len).map(|_| rng.byte()).collect()
}

/// Random printable soup, mostly brackets and keywords, which is far harder
/// for a parser than pure binary noise.
fn code_soup(seed: u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789(){}[]<>;,\"'=+-*/\\\n\t _:$";
    let mut rng = Lcg(seed);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(ALPHABET[(rng.next() % ALPHABET.len() as u64) as usize] as char);
    }
    out
}

#[test]
fn parser_survives_random_bytes_in_every_language() {
    for (lang, ext) in LANGS {
        let fname = format!("fuzz_rand{}", ext);
        let path = Path::new(&fname);
        for round in 0..25u64 {
            let bytes = random_bytes(
                round * 31 + lang.len() as u64 * 7,
                (2_000 + (round % 40) * 500) as usize,
            );
            let content = String::from_utf8_lossy(&bytes).to_string();
            let _ = parser::parse_file(path, &content);
        }
    }
}

#[test]
fn parser_survives_code_soup_in_every_language() {
    for (lang, ext) in LANGS {
        let fname = format!("fuzz_soup{}", ext);
        let path = Path::new(&fname);
        for round in 0..25u64 {
            let content = code_soup(
                round * 17 + lang.len() as u64 * 13,
                (3_000 + (round % 30) * 700) as usize,
            );
            let _ = parser::parse_file(path, &content);
        }
    }
}

#[test]
fn parser_survives_truncated_real_code() {
    let real: Vec<&str> = vec![
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\nfn main() { println!(\"{}\", add(1, 2)); }\n",
        "function load() {\n  const q = db.query(req.body.id);\n  return JSON.parse(q);\n}\n",
        "def run():\n    name = input()\n    os.system(name)\n    print(name)\n",
        "<?php\nfunction load() {\n    $q = $_GET['id'];\n    mysqli_query($conn, $q);\n}\n",
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"x\") }\n",
        "class App { void load(String q) { stmt.executeQuery(q); } }\n",
        "class App { void Load() { var q = Request.QueryString[\"id\"]; cmd.ExecuteScalar(q); } }\n",
    ];
    for (i, src) in real.iter().enumerate() {
        for cut in 0..src.len().max(1) {
            let truncated = &src[..cut];
            let path = match i {
                0 => Path::new("t.rs"),
                1 => Path::new("t.js"),
                2 => Path::new("t.py"),
                3 => Path::new("t.php"),
                4 => Path::new("t.go"),
                5 => Path::new("t.java"),
                _ => Path::new("t.cs"),
            };
            let _ = parser::parse_file(path, truncated);
        }
    }
}

#[test]
fn parser_survives_deep_nesting() {
    // One hundred and fifty thousand nested brackets, far beyond any real
    // code and deep enough to crash the C parser itself. The pre check must
    // refuse the file before the parser ever sees it, no crash, no hang.
    for (lang, ext) in LANGS {
        let fname = format!("deep{}", ext);
        let path = Path::new(&fname);
        let depth = 150_000usize;
        let content = match lang {
            "python" => format!("x = {}{}", "[".repeat(depth), "]".repeat(depth)),
            "go" => format!(
                "package main\nvar x = {}{}",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
            _ => format!("let x = {}{};", "(".repeat(depth), ")".repeat(depth)),
        };
        assert!(
            parser::parse_file(path, &content).is_none(),
            "pathological nesting must be refused for {}",
            lang
        );
    }
}

#[test]
fn parser_accepts_sane_deep_code() {
    // Five hundred levels of nesting is already beyond real code, but well
    // inside the safe bound, so it must parse. The capped walker extracts
    // what it can and never overflows.
    for (lang, ext) in LANGS {
        let fname = format!("ok_deep{}", ext);
        let path = Path::new(&fname);
        let depth = 500usize;
        let content = match lang {
            "python" => format!("x = {}{}", "[".repeat(depth), "]".repeat(depth)),
            "go" => format!(
                "package main\nvar x = {}{}",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
            _ => format!("let x = {}{};", "(".repeat(depth), ")".repeat(depth)),
        };
        let parsed = parser::parse_file(path, &content);
        assert!(parsed.is_some(), "sane nesting must parse for {}", lang);
    }
}

#[test]
fn parser_survives_empty_and_absurd_files() {
    let giant = format!("fn main() {{ // {}\n", "a".repeat(800_000));
    let cases: Vec<(&str, &str)> = vec![
        ("empty.rs", ""),
        ("newlines.rs", "\n\n\n\n\n"),
        ("only_braces.rs", "{{{{{{}}}}}}"),
        ("spaces.rs", "   \t   \n\t\n"),
        ("nul.rs", "\u{0}\u{0}\u{0}"),
        ("emoji.rs", "fn \u{1F600}() { \u{1F680} }"),
        ("bom.rs", "\u{FEFF}fn main() {}"),
        ("giant_line.rs", &giant),
    ];
    for (name, content) in cases {
        let _ = parser::parse_file(Path::new(name), content);
    }
}

#[test]
fn guards_survive_garbage_in_every_language() {
    for (lang, ext) in LANGS {
        let fname = format!("guard_soup{}", ext);
        let path = Path::new(&fname);
        for round in 0..25u64 {
            let content = code_soup(
                round * 23 + lang.len() as u64 * 29,
                (2_000 + (round % 20) * 400) as usize,
            );
            let _ = taint::scan_file(path, &content);
            let _ = edge::scan_file(path, &content);
            let _ = practice::scan_file(path, &content, lang);
        }
    }
}

#[test]
fn guards_survive_brace_storms() {
    // A storm of closing braces exercises every block scanner. The scans
    // must return, never panic and never index out of bounds.
    let storm = format!("{}{}", "(".repeat(50_000), ")".repeat(50_000));
    let p = Path::new("storm.js");
    let _ = edge::scan_file(p, &storm);
    let _ = taint::scan_file(p, &storm);
    let _ = practice::scan_file(p, &storm, "javascript");
    let py = format!("x = {}\n", "[".repeat(50_000));
    let _ = edge::scan_file(Path::new("storm.py"), &py);
}
