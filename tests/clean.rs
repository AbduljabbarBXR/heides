// The clean corpus gate.
//
// Idiomatic, correct code in every deep language must produce ZERO findings
// from the taint, edge and practice guards. This is the permanent tripwire
// against cosmetics. If a rule fires on clean code, the rule is wrong.

use std::path::{Path, PathBuf};

fn scan_guards(path: &Path, content: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for r in heides::taint::scan_file(path, content) {
        findings.push(format!("taint: {}", r.message));
    }
    for r in heides::edge::scan_file(path, content) {
        findings.push(format!("edge: {}", r.message));
    }
    let lang = heides::parser::detect_language(path).unwrap_or_default();
    for r in heides::practice::scan_file(path, content, &lang) {
        findings.push(format!("practice: {}", r.message));
    }
    findings
}

fn check_clean(name: &str, file: &str, content: &str) {
    let path = PathBuf::from(file);
    let findings = scan_guards(&path, content);
    assert!(
        findings.is_empty(),
        "{} must be clean, got: {:?}",
        name,
        findings
    );
    println!("[PASS] clean corpus {}", name);
}

#[test]
fn clean_corpus_all_languages() {
    // Rust: idiomatic, no unwrap, with return types.
    check_clean(
        "rust",
        "clean.rs",
        r#"use std::collections::HashMap;

fn average(values: &[i64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let sum: i64 = values.iter().sum();
    Some(sum as f64 / values.len() as f64)
}

fn lookup(map: &HashMap<String, i64>, key: &str) -> i64 {
    map.get(key).copied().unwrap_or(0)
}

fn main() {
    let data = vec![1, 2, 3, 4];
    match average(&data) {
        Some(avg) => println!("average {}", avg),
        None => println!("no data"),
    }
    let mut map = HashMap::new();
    map.insert("x".to_string(), 7);
    println!("{}", lookup(&map, "x"));
}
"#,
    );

    // JavaScript: strict equality, radix, guarded storage, no debug output.
    check_clean(
        "javascript",
        "clean.js",
        r#"const MAX = 100;

function average(values) {
  if (values.length === 0) {
    return 0;
  }
  const sum = values.reduce((a, b) => a + b, 0);
  return sum / values.length;
}

function loadUser() {
  const raw = localStorage.getItem("user");
  if (raw == null) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function parsePort(value) {
  return parseInt(value, 10);
}

module.exports = { average, loadUser, parsePort };
"#,
    );

    // TypeScript: same discipline with types.
    check_clean(
        "typescript",
        "clean.ts",
        r#"interface User {
  id: number;
  name: string;
}

export function formatUser(user: User | null): string {
  if (user === null) {
    return "unknown";
  }
  return `${user.name} (${user.id})`;
}

export function safeDivide(a: number, b: number): number {
  if (b === 0) {
    return 0;
  }
  return a / b;
}
"#,
    );

    // TypeScript settings form. Field labels that mention secrets, password
    // attributes, type declarations, empty defaults, config path keys and env
    // driven keys are all idiomatic and must stay silent. This case regressed
    // once, when the secret rule fired on any line holding a keyword and any
    // quote anywhere on the line.
    check_clean(
        "typescript settings form",
        "settings_form.tsx",
        r#"interface PaystackSettings {
  secretKey: string;
  webhookSecret: string;
}

const defaults: PaystackSettings = {
  secretKey: "",
  webhookSecret: "",
};

const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;

function setNested(section: string, provider: string, values: object) {}

export function SettingsForm() {
  const onKey = (value: string) => {
    setNested("payments", "paystack", { secretKey: value });
  };
  return (
    <div>
      <Field label="Webhook secret">
        <input type="password" placeholder="Consumer secret" value={""} />
      </Field>
      <label className="token-hint">Keys are stored encrypted.</label>
    </div>
  );
}
"#,
    );

    // Python: named exceptions, with blocks, no mutable defaults, no prints.
    check_clean(
        "python",
        "clean.py",
        r#"""A clean module."""

def average(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def read_config(path):
    with open(path, "r") as handle:
        return handle.read()


def parse_number(text):
    try:
        return int(text)
    except ValueError as error:
        return None


def render_message(user, message):
    from django.utils.html import escape
    from django.utils.safestring import mark_safe

    safe_message = escape(message)
    author = escape(user)
    return mark_safe("<p>%s said %s</p>" % (author, safe_message))
"#,
    );

    // PHP: typed, no superglobals in sinks, no eval.
    check_clean(
        "php",
        "clean.php",
        r#"<?php

namespace App;

function average(array $values): float
{
    if (count($values) === 0) {
        return 0.0;
    }
    return array_sum($values) / count($values);
}

final class Calculator
{
    public function add(int $a, int $b): int
    {
        return $a + $b;
    }
}
"#,
    );

    // Blade template. CSRF tokens bound through template interpolation are
    // idiomatic Laravel, not hardcoded secrets. This case regressed once,
    // when a quoted value holding any template call looked like a literal.
    check_clean(
        "php blade template",
        "verify.blade.php",
        r#"<form method="post" action="{{ route('verify') }}">
    @csrf
    <input type="password" name="code" placeholder="Verification code">
    <button>Verify</button>
</form>
<script>
    $.post('{{ route('addons.activation') }}', {_token: '{{ csrf_token() }}', id: id}, function(data) {});
</script>
"#,
    );

    // PHP request validation. Rule variables that mention passwords are
    // validation keywords, not credentials. This case regressed once on a
    // real Laravel request class.
    check_clean(
        "php validation rules",
        "request_clean.php",
        r#"<?php

namespace App\Http\Requests;

class SellerProfileRequest
{
    public function rules()
    {
        $newPasswordRule = 'sometimes';
        $confirmPasswordRule = ['min:6'];
        $passwordConfirmation = 'confirmed';
        return [];
    }
}
"#,
    );

    // Go: handled errors, no exec of user input.
    check_clean(
        "go",
        "clean.go",
        r#"package main

import (
	"errors"
	"strings"
)

func average(values []int) (float64, error) {
	if len(values) == 0 {
		return 0, errors.New("empty input")
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values)), nil
}

func normalize(input string) string {
	return strings.TrimSpace(strings.ToLower(input))
}
"#,
    );

    // Java: prepared statements, no raw exec of input.
    check_clean(
        "java",
        "clean.java",
        r#"import java.util.List;

public class Calculator {
    public double average(List<Integer> values) {
        if (values.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        for (int value : values) {
            sum += value;
        }
        return sum / values.size();
    }

    public String normalize(String input) {
        if (input == null) {
            return "";
        }
        return input.trim().toLowerCase();
    }
}
"#,
    );

    // C#: parameterized queries, guarded console input.
    check_clean(
        "csharp",
        "clean.cs",
        r#"using System;
using System.Collections.Generic;
using System.Linq;

public class Calculator
{
    public double Average(List<int> values)
    {
        if (values.Count == 0)
        {
            return 0.0;
        }
        return values.Average();
    }

    public string Normalize(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }
        return input.Trim().ToLowerInvariant();
    }
}
"#,
    );

    // HTML: stylesheet and script references, a form with the CSP meta
    // present, no javascript URLs.
    check_clean(
        "html",
        "clean.html",
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self'">
  <link rel="stylesheet" href="/css/app.css">
  <script src="/js/app.js" defer></script>
</head>
<body>
  <form action="/checkout" method="post">
    <input name="card" type="text" required>
  </form>
  <a href="/pricing">pricing</a>
</body>
</html>
"#,
    );

    // CSS: url references and imports are edges, never findings.
    check_clean(
        "css",
        "clean.css",
        r#"@import "/base.css";

body {
  font-family: system-ui, sans-serif;
}

.hero {
  background: url("/img/hero.webp") no-repeat center;
}
"#,
    );
}
