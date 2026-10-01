// Config and secret indexing.
//
// A credential sitting in a committed .env, a Dockerfile, a Terraform variable or
// a Kubernetes Secret is the one class of finding where the code graph cannot
// help: the value is not in a language file, so nothing in the existing pipeline
// ever reads it. Today these files are not even collected, because a `.env` has
// no extension and `Dockerfile` has none either.
//
// The rule this layer follows is narrower than "does it look like a secret",
// because config files are full of things that look like secrets and are not.
// Every positive below is a value that is real, and the negatives are the cases
// that a keyword match alone would have reported: placeholders, references to an
// environment variable, URLs, file paths, and documentation.

use std::fs;
use std::path::{Path, PathBuf};

use heides::config::{self, ConfigFinding};

// Provider-shaped test values, assembled at runtime.
//
// A test needs the *shape* of a credential, not a value that resembles a real
// one. Written as a literal, this file would either be blocked by push
// protection or, worse, seed a value that looks live to the next reader. These
// are built from parts so the shape is exercised and the repository carries
// nothing that reads as a credential.
//
// The trailing characters are filler: a real token has entropy, and the
// classifier only inspects the prefix and the length.

/// A string shaped like a Stripe live key.
fn stripe_live() -> String {
    format!("sk_{}{}", "live_", "0".repeat(24))
}

/// A string shaped like a GitHub personal access token.
fn github_pat() -> String {
    format!("ghp_{}", "0".repeat(36))
}

/// A string shaped like an npm token.
fn npm_token() -> String {
    format!("npm_{}", "a".repeat(36))
}

fn fixture(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heides-config-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

fn findings(dir: &Path) -> Vec<ConfigFinding> {
    // A fixture directory is its own walk root, which is what `scan` expects.
    config::scan(dir)
}

fn messages(dir: &Path) -> Vec<String> {
    findings(dir).into_iter().map(|f| f.message).collect()
}

// --------------------------------------------------------- the file is found

#[test]
fn a_dot_env_file_with_no_extension_is_collected() {
    // The whole reason this layer exists. `detect_language` returns None for a
    // file with no extension, so `.env` was never read.
    let dir = fixture("dotenv");
    write(&dir, ".env", "DATABASE_URL=postgres://u:p@db:5432/app\n");
    let found = messages(&dir);
    assert!(
        found.iter().any(|m| m.contains("DATABASE_URL")),
        "a .env must be read: {found:?}"
    );
}

#[test]
fn a_dockerfile_with_no_extension_is_collected() {
    let dir = fixture("dockerfile");
    write(
        &dir,
        "Dockerfile",
        &format!("FROM node:20\nENV API_KEY={}\n", stripe_live()),
    );
    let found = messages(&dir);
    assert!(
        found.iter().any(|m| m.contains("API_KEY")),
        "a Dockerfile must be read: {found:?}"
    );
}

#[test]
fn a_terraform_file_is_collected() {
    let dir = fixture("tf");
    write(
        &dir,
        "main.tf",
        "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n\
         variable \"db_password\" {\n  default = \"hunter2Correct-Horse\"\n}\n",
    );
    let found = messages(&dir);
    assert!(
        found.iter().any(|m| m.contains("db_password")),
        "a terraform default holding a credential must be found: {found:?}"
    );
}

#[test]
fn a_kubernetes_secret_manifest_is_collected() {
    let dir = fixture("k8s");
    write(
        &dir,
        "k8s/secret.yaml",
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: c3VwZXJzZWNyZXQxMjM=\n",
    );
    let found = messages(&dir);
    assert!(
        !found.is_empty(),
        "a Secret manifest must be reported: {found:?}"
    );
}

// ---------------------------------------------------------- real credentials

#[test]
fn a_live_stripe_key_is_reported() {
    let dir = fixture("stripe");
    write(&dir, ".env", &format!("STRIPE_KEY={}\n", stripe_live()));
    let f = findings(&dir);
    assert_eq!(f.len(), 1, "one finding, got {f:?}");
    assert_eq!(f[0].key, "STRIPE_KEY");
    assert_eq!(f[0].kind, "credential");
    assert_eq!(f[0].file, ".env");
    assert_eq!(f[0].line, 1);
}

#[test]
fn a_github_token_is_reported() {
    let dir = fixture("gh");
    write(&dir, ".env", &format!("GITHUB_TOKEN={}\n", github_pat()));
    let f = findings(&dir);
    assert!(f.iter().any(|x| x.kind == "credential"), "{f:?}");
}

#[test]
fn an_aws_access_key_id_is_reported() {
    let dir = fixture("aws");
    write(
        &dir,
        "creds.env",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    );
    let f = findings(&dir);
    assert!(
        f.iter().any(|x| x.key.contains("AWS_ACCESS_KEY_ID")),
        "{f:?}"
    );
}

#[test]
fn a_private_key_block_is_reported() {
    let dir = fixture("pem");
    write(
        &dir,
        "id_rsa",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
    );
    let f = findings(&dir);
    assert!(
        f.iter().any(|x| x.kind == "private_key"),
        "a private key must be its own kind: {f:?}"
    );
}

#[test]
fn a_url_with_a_credential_in_it_is_reported() {
    // A connection string is the most common real leak in a .env and no keyword
    // rule catches it, because the key is DATABASE_URL and the secret is the
    // password field inside it.
    let dir = fixture("conn");
    write(
        &dir,
        ".env",
        "DATABASE_URL=postgres://admin:s3cr3tP4ss@prod-db:5432/app\n",
    );
    let f = findings(&dir);
    // The kind is `connection_string` rather than `credential`, which is more
    // precise: a reader can tell a working login from a bare token without
    // looking at the value, which the finding deliberately does not show.
    assert!(
        f.iter()
            .any(|x| x.kind == "connection_string" && x.key == "DATABASE_URL"),
        "a credential inside a connection string must be found: {f:?}"
    );
}

// --------------------------------------------------- the benign side, strictly

#[test]
fn a_placeholder_value_is_not_a_credential() {
    let dir = fixture("placeholder");
    write(
        &dir,
        ".env",
        "API_KEY=your-api-key-here\nPASSWORD=changeme\nSECRET=xxx\nTOKEN=\n",
    );
    let f = findings(&dir);
    assert!(f.is_empty(), "placeholders are not credentials: {f:?}");
}

#[test]
fn a_value_read_from_the_environment_is_not_a_credential() {
    // `API_KEY=${API_KEY}` is the correct way to write it and must stay quiet.
    let dir = fixture("envref");
    write(
        &dir,
        ".env",
        "API_KEY=${API_KEY}\nDB_PASSWORD=$DB_PASSWORD\nAWS_SECRET_ACCESS_KEY={{vault:secret}}\n",
    );
    let f = findings(&dir);
    assert!(f.is_empty(), "a reference is not a credential: {f:?}");
}

#[test]
fn a_path_or_a_url_without_a_credential_is_not_reported() {
    let dir = fixture("paths");
    write(
        &dir,
        ".env",
        "HOME=/root\nPWD=/app\nCERT_PATH=/etc/ssl/certs/ca.pem\n\
         API_URL=https://api.example.com/v1\nDOCS=https://example.com/docs#token\n",
    );
    let f = findings(&dir);
    assert!(f.is_empty(), "paths and urls are not credentials: {f:?}");
}

#[test]
fn a_documentation_line_is_not_a_credential() {
    let dir = fixture("docs");
    write(
        &dir,
        ".env.example",
        "# set API_KEY to your key from the dashboard\n\
         # the password must be at least 12 characters\n\
         API_KEY=\n",
    );
    let f = findings(&dir);
    assert!(f.is_empty(), "prose is not a credential: {f:?}");
}

#[test]
fn an_example_env_file_is_reported_but_labelled() {
    // `.env.example` is often committed on purpose, so a real credential in one
    // is still worth seeing; the file kind says what it is rather than hiding it.
    let dir = fixture("example");
    write(
        &dir,
        ".env.example",
        &format!("API_KEY={}\n", stripe_live()),
    );
    let f = findings(&dir);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].file, ".env.example");
}

// ------------------------------------------------------------- a real sink

#[test]
fn a_credential_copied_into_a_docker_image_is_reported() {
    // The shape that matters most: a secret baked into a layer, where it stays
    // in the image history even after the layer is rebuilt.
    let dir = fixture("baked");
    write(
        &dir,
        "Dockerfile",
        &format!(
            "FROM node:20\nARG NPM_TOKEN\nENV NPM_TOKEN={}\n\n         COPY . /app\nRUN echo $NPM_TOKEN\n",
            npm_token()
        ),
    );
    let f = findings(&dir);
    assert!(
        f.iter().any(|x| x.kind == "credential"),
        "a token in a Dockerfile must be found: {f:?}"
    );
}

#[test]
fn a_terraform_variable_with_no_default_is_quiet() {
    let dir = fixture("tfnodefault");
    write(
        &dir,
        "vars.tf",
        "variable \"db_password\" {\n  type = string\n}\n",
    );
    let f = findings(&dir);
    assert!(
        f.is_empty(),
        "a variable with no value holds no secret: {f:?}"
    );
}

// ----------------------------------------------------------------- reporting

#[test]
fn a_workspace_with_no_config_says_so_rather_than_returning_empty() {
    let dir = fixture("noconfig");
    write(
        &dir,
        "a.js",
        "export function add(a, b) { return a + b; }\n",
    );
    let f = findings(&dir);
    assert!(f.is_empty());
    let summary = config::summarise(&dir);
    assert!(
        summary.contains("no configuration files") || summary.contains("no credentials"),
        "an empty result must be stated, not implied: {summary}"
    );
}

#[test]
fn a_secret_is_never_echoed_back_in_the_message() {
    // A finding that prints the credential is a finding that has now copied the
    // credential into every log, CI transcript and agent transcript that reads
    // the output. The value is reported by shape only.
    let dir = fixture("noecho");
    let secret = stripe_live();
    write(&dir, ".env", &format!("API_KEY={secret}\n"));
    let f = findings(&dir);
    assert_eq!(f.len(), 1);
    let rendered = format!("{:?}", f[0]);
    assert!(
        !rendered.contains(secret.as_str()),
        "the credential must not appear in the finding: {rendered}"
    );
    assert!(!f[0].message.contains(secret.as_str()));
}
