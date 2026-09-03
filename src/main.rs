use std::path::PathBuf;
use std::process::ExitCode;

use heides::{deps, grounding, harmony, indexer, server, spine, ui::Ui, watch};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    println!("HEIDES {}  the code nervous system", VERSION);
    println!();
    println!("A deterministic harness that gives AI agents senses, memory and judgment for code.");
    println!();
    println!("Commands");
    println!("  scan [dir]      map the codebase into the persistent spine index");
    println!("  status [dir]    report the state of the spine index");
    println!("  query [kind] [name]");
    println!("                  ask the spine: callers, imports, definition, calls");
    println!("  check [dir]     run every guard and print findings");
    println!("  staged [patch]  check a unified diff before it is applied");
    println!("  plan [text]     ground an objective against the codebase");
    println!("  scaffold [text] [dir]");
    println!("                  scaffold a new project from a plan and index it");
    println!("  deps [dir]      check dependencies for vulnerabilities and updates");
    println!("  describe [dir]  read the whole workspace manifest in one shot");
    println!("  export [dir] [out]");
    println!("                  write one self contained code map file");
    println!("  watch [dir]     watch for changes and reindex on demand");
    println!("  mcp             start the MCP server over stdio");
    println!("  version         print the version");
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let mut cleaned: Vec<String> = Vec::with_capacity(args.len());
    cleaned.push(args[0].clone());
    for a in args.iter().skip(1) {
        if !Ui::consume_flag(a) {
            cleaned.push(a.clone());
        }
    }
    args = cleaned;
    let ui = Ui::resolve();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let arg2 = args.get(2).map(|s| s.as_str()).unwrap_or(".");
    let arg3 = args.get(3).map(|s| s.as_str());

    match cmd {
        "scan" => {
            let root = PathBuf::from(arg2);
            let mut graph = match spine::load(&root) {
                Ok(g) => g,
                Err(_) => spine::CodeGraph::new(),
            };
            let touched = indexer::update_graph(&root, &mut graph);
            match spine::save(&graph, &root) {
                Ok(()) => {
                    println!(
                        "spine indexed {} files, {} symbols, {} call edges, {} imports ({} touched)",
                        graph.files.len(),
                        graph.symbols.len(),
                        graph.calls.len(),
                        graph.imports.len(),
                        touched
                    );
                    if let Some(mb) = indexer::peak_rss_mb() {
                        eprintln!("peak rss {} MB", mb);
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("could not save index: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "status" => {
            let root = PathBuf::from(arg2);
            if !spine::exists(&root) {
                println!("no spine index found. run heides scan");
                return ExitCode::FAILURE;
            }
            match spine::load(&root) {
                Ok(graph) => {
                    println!(
                        "spine index present: {} files, {} symbols, {} call edges, {} imports",
                        graph.files.len(),
                        graph.symbols.len(),
                        graph.calls.len(),
                        graph.imports.len()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "query" => {
            let root = PathBuf::from(".");
            let kind = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let name = args.get(3).map(|s| s.as_str()).unwrap_or("");
            if kind.is_empty() || name.is_empty() {
                println!(
                    "usage. heides query [callers|imports|definition|calls|neighbors|search] [name]"
                );
                return ExitCode::FAILURE;
            }
            let graph = match indexer::load_or_build(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
            match kind {
                "callers" => {
                    let callers = graph.callers_of(name);
                    if callers.is_empty() {
                        println!("no recorded callers for {}", name);
                    } else {
                        println!("{} call site(s)", callers.len());
                        for c in callers {
                            println!("{} calls {} at {}:{}", c.caller, c.callee, c.file, c.line);
                        }
                    }
                }
                "imports" => {
                    let importers = graph.importers_of(name);
                    if importers.is_empty() {
                        println!("no recorded imports of {}", name);
                    } else {
                        println!("{} importer(s)", importers.len());
                        for i in importers {
                            println!("{} imports {} at {}:{}", i.file, i.imported, i.file, i.line);
                        }
                    }
                }
                "definition" => {
                    let symbols = graph.symbols_named(name);
                    if symbols.is_empty() {
                        println!("no definition for {} in the spine", name);
                    } else {
                        for s in symbols {
                            println!(
                                "{} defined at {}:{} (kind {})",
                                s.name, s.file, s.line, s.kind
                            );
                            if !s.doc.is_empty() {
                                println!("  {}", s.doc);
                            }
                            if !s.signature.is_empty() {
                                println!("  {}", s.signature);
                            }
                        }
                    }
                }
                "calls" => {
                    let calls = graph.calls_from(name);
                    if calls.is_empty() {
                        println!("{} makes no recorded calls", name);
                    } else {
                        println!("{} call(s)", calls.len());
                        for c in calls {
                            println!("{} calls {} at {}:{}", c.caller, c.callee, c.file, c.line);
                        }
                    }
                }
                "neighbors" => {
                    // Everything the symbol touches in one shot, so an
                    // agent learns what talks to what without reading code.
                    let symbols = graph.symbols_named(name);
                    if symbols.is_empty() {
                        println!("no definition for {} in the spine", name);
                    } else {
                        for s in symbols {
                            println!(
                                "{} defined at {}:{} (kind {})",
                                s.name, s.file, s.line, s.kind
                            );
                            if !s.doc.is_empty() {
                                println!("  doc {}", s.doc);
                            }
                            if !s.signature.is_empty() {
                                println!("  {}", s.signature);
                            }
                        }
                        let callers = graph.callers_of(name);
                        if callers.is_empty() {
                            println!("no recorded callers");
                        } else {
                            println!("called by {} site(s)", callers.len());
                            for c in callers {
                                println!("  {} at {}:{}", c.caller, c.file, c.line);
                            }
                        }
                        let out_calls = graph.calls_from(name);
                        if !out_calls.is_empty() {
                            println!("{} call(s) out", out_calls.len());
                            for c in out_calls {
                                println!("  {} at {}:{}", c.callee, c.file, c.line);
                            }
                        }
                        let importers = graph.importers_of(name);
                        if !importers.is_empty() {
                            println!("imported by {} site(s)", importers.len());
                            for i in importers {
                                println!("  {} at {}:{}", i.file, i.imported, i.line);
                            }
                        }
                    }
                }
                "search" => {
                    let hits = spine::search(&root, name);
                    match hits {
                        Ok(hits) if hits.is_empty() => {
                            println!("no symbol matches {}", name);
                        }
                        Ok(hits) => {
                            println!("{} hit(s)", hits.len());
                            for h in hits {
                                let doc = if h.doc.is_empty() {
                                    String::new()
                                } else {
                                    format!(", doc {}", h.doc)
                                };
                                println!(
                                    "{} ({} {}) at {}:{}{}",
                                    h.name, h.kind, name, h.file, h.line, doc
                                );
                            }
                        }
                        Err(e) => {
                            println!("{}", e);
                            return ExitCode::FAILURE;
                        }
                    }
                }
                _ => {
                    println!(
                        "unknown query kind. use callers, imports, definition, calls, neighbors or search"
                    );
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        "check" => {
            let root = PathBuf::from(arg2);
            let graph = match indexer::load_or_build(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
            let reports = harmony::check_workspace(&root, &graph);
            if reports.is_empty() {
                println!("no findings. the workspace is clean.");
            } else {
                println!("{}", harmony::summarize(&reports));
                for r in &reports {
                    let loc = if r.file.is_empty() {
                        String::new()
                    } else {
                        format!(" at {}:{}", r.file, r.line)
                    };
                    println!(
                        "{} {} ({}){}",
                        ui.severity(&r.severity),
                        r.message,
                        r.guard,
                        loc
                    );
                }
            }
            ExitCode::SUCCESS
        }
        "staged" => {
            let patch_path = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if patch_path.is_empty() {
                println!("usage. heides staged [patch file]");
                return ExitCode::FAILURE;
            }
            let patch_text = match std::fs::read_to_string(patch_path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("could not read patch: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            let root = PathBuf::from(".");
            let graph = match indexer::load_or_build(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
            match harmony::check_staged(&root, &graph, &patch_text) {
                Ok(reports) => {
                    if reports.is_empty() {
                        println!("patch is safe to apply. no conflicts detected.");
                    } else {
                        println!("{}", harmony::summarize(&reports));
                        for r in &reports {
                            println!(
                                "{} {} at {}:{}",
                                ui.severity(&r.severity),
                                r.message,
                                r.file,
                                r.line
                            );
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("patch could not be parsed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "plan" => {
            let plan = arg3.map(|s| s.to_string()).unwrap_or_else(|| {
                let arg2s = args.get(2).map(|s| s.as_str()).unwrap_or("");
                arg2s.to_string()
            });
            let root = PathBuf::from(".");
            let graph = match indexer::load_or_build(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("{}", e);
                    return ExitCode::FAILURE;
                }
            };
            let verdict = grounding::evaluate(&plan, &graph, &root);
            println!("feasible {}", verdict.feasible);
            for n in &verdict.notes {
                println!("  {}", n);
            }
            ExitCode::SUCCESS
        }
        "scaffold" => {
            let plan = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
            if plan.is_empty() {
                println!("usage. heides scaffold [plan text] [dir]");
                return ExitCode::FAILURE;
            }
            match grounding::scaffold(plan, &PathBuf::from(dir)) {
                Ok(files) => {
                    for f in &files {
                        println!("created {}", f);
                    }
                    // The newborn workspace gets indexed immediately, so
                    // it reads back through the same spine as any other
                    // project and describe works from the first second.
                    let root = PathBuf::from(dir);
                    match indexer::load_or_build(&root) {
                        Ok(graph) => {
                            println!(
                                "indexed {} files, {} symbols, {} call(s) in {}",
                                graph.files.len(),
                                graph.symbols.len(),
                                graph.calls.len(),
                                dir
                            );
                            let _ = spine::save(&graph, &root);
                        }
                        Err(e) => eprintln!("index failed: {}", e),
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("scaffold failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "deps" => {
            let root = PathBuf::from(arg2);
            let (reports, _network) = deps::check(&root);
            if reports.is_empty() {
                println!("no dependency findings");
            } else {
                for r in &reports {
                    println!("{} {}", ui.severity(&r.severity), r.message);
                }
            }
            ExitCode::SUCCESS
        }
        "describe" => {
            let root = PathBuf::from(arg2);
            match indexer::load_or_build(&root) {
                Ok(graph) => {
                    describe_workspace(&graph);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "export" => {
            let root = PathBuf::from(arg2);
            match indexer::load_or_build(&root) {
                Ok(graph) => {
                    let out_path = match args.get(3) {
                        Some(p) => PathBuf::from(p),
                        None => root.join(".heides").join("heides-map.md"),
                    };
                    let mut md = String::new();
                    md.push_str(&format!(
                        "# code map for {}\n\ngenerated by heides, deterministic structure map, judgment is never stored\n\n",
                        root.display()
                    ));
                    md.push_str(&format!(
                        "{} files, {} symbols, {} call edges, {} imports\n",
                        graph.files.len(),
                        graph.symbols.len(),
                        graph.calls.len(),
                        graph.imports.len()
                    ));
                    let mut langs: Vec<&str> =
                        graph.files.iter().map(|f| f.lang.as_str()).collect();
                    langs.sort_unstable();
                    langs.dedup();
                    md.push_str(&format!("languages {}\n", langs.join(", ")));
                    md.push_str("\n## doc coverage\n");
                    let mut total_doc = 0usize;
                    for lang in &langs {
                        let syms: Vec<_> =
                            graph.symbols.iter().filter(|s| &s.lang == lang).collect();
                        let with_doc = syms.iter().filter(|s| !s.doc.is_empty()).count();
                        total_doc += with_doc;
                        md.push_str(&format!("{} {}/{}\n", lang, with_doc, syms.len()));
                    }
                    md.push_str(&format!("all {}/{}\n", total_doc, graph.symbols.len()));
                    // Presence ledger, every file the walker saw. Indexed
                    // files have map sheets below, the rest are listed with
                    // their size and reason, nothing is invisible.
                    let seen: std::collections::HashSet<String> = graph
                        .files
                        .iter()
                        .map(|f| f.path.trim_start_matches("./").to_string())
                        .collect();
                    let walked = indexer::collect_files(&root);
                    let mut unindexed: Vec<(String, u64)> = Vec::new();
                    for p in walked {
                        let key = p.display().to_string().trim_start_matches("./").to_string();
                        if seen.contains(&key) {
                            continue;
                        }
                        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                        unindexed.push((key, size));
                    }
                    unindexed.sort();
                    md.push_str(&format!(
                        "\n## presence\n\n{} file(s) walked, {} indexed, {} not indexed, only source files in the eight languages under 1MB are mapped, the ledger keeps every other file visible\n",
                        seen.len() + unindexed.len(),
                        seen.len(),
                        unindexed.len()
                    ));
                    if !unindexed.is_empty() {
                        md.push_str("\n## unindexed files\n\n");
                        for (p, size) in unindexed.iter().take(500) {
                            md.push_str(&format!("- {} ({} bytes)\n", p, size));
                        }
                        if unindexed.len() > 500 {
                            md.push_str(&format!("- and {} more\n", unindexed.len() - 500));
                        }
                    }
                    // Files sorted by path, each with its own symbol and
                    // edge inventory, a section per file reads like a map
                    // sheet.
                    let mut files: Vec<_> = graph.files.iter().collect();
                    files.sort_by(|a, b| a.path.cmp(&b.path));
                    let mut symbols: Vec<_> = graph.symbols.iter().collect();
                    symbols.sort_by(|a, b| {
                        a.file
                            .cmp(&b.file)
                            .then(a.line.cmp(&b.line))
                            .then(a.name.cmp(&b.name))
                    });
                    let mut per_file: Vec<Vec<&&spine::Symbol>> = vec![Vec::new(); files.len()];
                    let mut fi_by_path: std::collections::HashMap<&str, usize> =
                        std::collections::HashMap::new();
                    for (i, f) in files.iter().enumerate() {
                        fi_by_path.insert(f.path.as_str(), i);
                    }
                    for s in &symbols {
                        if let Some(&i) = fi_by_path.get(s.file.as_str()) {
                            per_file[i].push(s);
                        }
                    }
                    md.push_str("\n## files\n");
                    for (i, f) in files.iter().enumerate() {
                        md.push_str(&format!(
                            "\n### {}\n\n{} symbols, language {}, {} bytes\n",
                            f.path,
                            per_file[i].len(),
                            f.lang,
                            f.size
                        ));
                        let imports: Vec<_> = graph
                            .imports
                            .iter()
                            .filter(|im| im.file == f.path)
                            .map(|im| im.imported.as_str())
                            .collect();
                        if !imports.is_empty() {
                            md.push_str(&format!("imports {}\n", imports.join(", ")));
                        }
                        let edges = graph.calls.iter().filter(|c| c.file == f.path).count();
                        if edges > 0 {
                            md.push_str(&format!("{} call edge(s) in file\n", edges));
                        }
                        for s in &per_file[i] {
                            let sig = if s.signature.is_empty() {
                                String::new()
                            } else {
                                format!(" `{}`", s.signature)
                            };
                            let doc = if s.doc.is_empty() {
                                String::new()
                            } else {
                                let one: String = s.doc.chars().take(200).collect();
                                format!(", {}{}", one, if s.doc.len() > 200 { "..." } else { "" })
                            };
                            md.push_str(&format!(
                                "- {} ({} line {}){}{}\n",
                                s.name, s.kind, s.line, sig, doc
                            ));
                        }
                    }
                    md.push_str("\nvendored and generated trees are skipped by design, node_modules, .git, .heides, target, vendor, dist, build, .next, storage and their siblings, the index maps source only\n");
                    match std::fs::write(&out_path, md) {
                        Ok(()) => {
                            println!(
                                "code map exported to {}, {} files, {} symbols",
                                out_path.display(),
                                graph.files.len(),
                                graph.symbols.len()
                            );
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("could not write map: {}", e);
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "watch" => {
            let root = PathBuf::from(arg2);
            let max = args.get(3).and_then(|s| s.parse::<u64>().ok());
            watch::watch(&root, max, 2);
            ExitCode::SUCCESS
        }
        "mcp" => server::run(),
        "version" => {
            println!("{}", VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::SUCCESS
        }
    }
}

/// Workspace manifest, read only and deterministic. The output is a plain
/// text map an agent can read instead of walking the code: languages,
/// entrypoints, hubs, call cycles and which files talk to which.
fn describe_workspace(graph: &spine::CodeGraph) {
    println!(
        "{} files, {} symbols, {} call(s), {} import(s)",
        graph.files.len(),
        graph.symbols.len(),
        graph.calls.len(),
        graph.imports.len()
    );
    let mut langs: Vec<&str> = graph.files.iter().map(|f| f.lang.as_str()).collect();
    langs.sort_unstable();
    langs.dedup();
    println!("languages {}", langs.join(", "));

    // Doc coverage per language. How many symbols in each language carry a
    // captured comment, so gaps in the eyes are visible and measurable.
    let mut per_lang: Vec<(&str, usize, usize)> = Vec::new();
    for lang in &langs {
        let total = graph.symbols.iter().filter(|s| s.lang == *lang).count();
        let documented = graph
            .symbols
            .iter()
            .filter(|s| s.lang == *lang && !s.doc.is_empty())
            .count();
        per_lang.push((lang, documented, total));
    }
    for (lang, documented, total) in &per_lang {
        let pct = if *total > 0 {
            documented * 100 / total
        } else {
            0
        };
        println!("doc coverage {} {}/{} ({}%)", lang, documented, total, pct);
    }
    let mut undocumented: Vec<(&str, &str, usize, &str)> = Vec::new();
    for s in &graph.symbols {
        if !s.doc.is_empty() {
            continue;
        }
        if !is_fn_kind(&s.kind) && !s.kind.contains("field") && !s.kind.contains("constant") {
            continue;
        }
        undocumented.push((
            s.name.as_str(),
            s.file.as_str(),
            s.line as usize,
            s.kind.as_str(),
        ));
    }
    undocumented.sort_by(|a, b| a.1.cmp(b.1).then(a.2.cmp(&b.2)));
    if !undocumented.is_empty() {
        println!(
            "undocumented symbols, first {} of {}",
            15,
            undocumented.len()
        );
        for (name, file, line, kind) in undocumented.iter().take(15) {
            println!("  {} at {}:{} ({})", name, file, line, kind);
        }
    }

    // Entrypoints. A function nobody calls in the workspace is a root of
    // the call graph. Files with module level calls are script entry
    // points, their own top level code starts the run.
    let mut script_files: Vec<&str> = graph
        .calls
        .iter()
        .filter(|c| c.caller == "module level")
        .map(|c| c.file.as_str())
        .collect();
    script_files.sort_unstable();
    script_files.dedup();
    let mut entry_names: Vec<&str> = Vec::new();
    for s in &graph.symbols {
        if !is_fn_kind(&s.kind) {
            continue;
        }
        if graph.callers_of(&s.name).is_empty() && !entry_names.contains(&s.name.as_str()) {
            entry_names.push(s.name.as_str());
        }
    }
    entry_names.sort_unstable();
    if !script_files.is_empty() {
        println!("entrypoint files that run module level code");
        for f in script_files.iter().take(15) {
            println!("  {}", f);
        }
    }
    let print_entries = |names: Vec<&str>, label: &str, limit: usize| {
        if names.is_empty() {
            return;
        }
        println!("{}", label);
        for n in names.iter().take(limit) {
            if let Some(s) = graph.symbols_named(n).first() {
                println!("  {} at {}:{}", n, s.file, s.line);
            }
        }
    };
    let named: Vec<&str> = entry_names
        .iter()
        .filter(|n| ["main", "run", "start", "handler", "index"].contains(n))
        .copied()
        .collect();
    let rest: Vec<&str> = entry_names
        .iter()
        .filter(|n| !named.contains(n))
        .copied()
        .collect();
    print_entries(named, "named entrypoints", 10);
    print_entries(rest, "uncalled roots", 20);

    // Hubs, the symbols with the most wiring in and out.
    let mut hub_scores: Vec<(&str, usize)> = Vec::new();
    for s in &graph.symbols {
        if !is_fn_kind(&s.kind) {
            continue;
        }
        let score = graph.callers_of(&s.name).len() + graph.calls_from(&s.name).len();
        if score > 0 {
            hub_scores.push((s.name.as_str(), score));
        }
    }
    hub_scores.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    hub_scores.dedup_by(|a, b| a.0 == b.0);
    if !hub_scores.is_empty() {
        println!("most connected symbols");
        for (n, sc) in hub_scores.iter().take(8) {
            if let Some(s) = graph.symbols_named(n).first() {
                println!("  {} with {} edge(s) at {}:{}", n, sc, s.file, s.line);
            }
        }
    }

    // Call cycles, printed as name chains.
    let mut adj: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for c in &graph.calls {
        if is_any_known_fn(graph, &c.caller) && is_any_known_fn(graph, &c.callee) {
            let list = adj.entry(c.caller.as_str()).or_default();
            if !list.contains(&c.callee.as_str()) {
                list.push(c.callee.as_str());
            }
        }
    }
    let cycles = find_cycles(&adj);
    if !cycles.is_empty() {
        println!("call cycles");
        for cyc in cycles.iter().take(5) {
            println!("  {}", cyc.join(" calls "));
        }
    }

    // File level map, which files talk to which by resolved calls.
    let mut def_file: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for s in &graph.symbols {
        def_file.entry(s.name.as_str()).or_insert(s.file.as_str());
    }
    let mut pairs: Vec<(&str, &str, usize)> = Vec::new();
    for c in &graph.calls {
        if let Some(dst) = def_file.get(c.callee.as_str()) {
            let src = c.file.as_str();
            if src != *dst {
                if let Some(p) = pairs.iter_mut().find(|(a, b, _)| *a == src && *b == *dst) {
                    p.2 += 1;
                } else {
                    pairs.push((src, *dst, 1));
                }
            }
        }
    }
    pairs.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)));
    if !pairs.is_empty() {
        println!("files that talk to each other");
        for (a, b, n) in pairs.iter().take(30) {
            println!("  {} talks to {}, {} call(s)", a, b, n);
        }
    }
}

fn is_fn_kind(kind: &str) -> bool {
    kind.contains("function") || kind == "method_definition" || kind == "method_declaration"
}

fn is_any_known_fn(graph: &spine::CodeGraph, name: &str) -> bool {
    graph
        .symbols_named(name)
        .iter()
        .any(|s| is_fn_kind(&s.kind))
}

/// Simple colored DFS cycle finder over the symbol call graph. Returns up
/// to five cycles, each rendered as an ordered name chain.
fn find_cycles<'a>(adj: &std::collections::HashMap<&'a str, Vec<&'a str>>) -> Vec<Vec<String>> {
    const COLOR_WHITE: u8 = 0;
    const COLOR_GRAY: u8 = 1;
    const COLOR_BLACK: u8 = 2;
    let mut color: std::collections::HashMap<&str, u8> = std::collections::HashMap::new();
    let mut found: Vec<Vec<String>> = Vec::new();
    let mut names: Vec<&&str> = adj.keys().collect();
    names.sort_unstable();
    let mut idx = 0usize;
    while idx < names.len() && found.len() < 5 {
        let start = *names[idx];
        if *color.entry(start).or_insert(COLOR_WHITE) != COLOR_WHITE {
            idx += 1;
            continue;
        }
        // Iterative DFS with explicit path stack.
        let mut path: Vec<&str> = Vec::new();
        let mut dfs: Vec<(&str, usize)> = vec![(start, 0)];
        color.insert(start, COLOR_GRAY);
        path.push(start);
        while let Some(&(node, ci)) = dfs.last() {
            let children = adj.get(node).cloned().unwrap_or_default();
            if ci < children.len() {
                let next = children[ci];
                dfs.last_mut().unwrap().1 += 1;
                match color.get(next).copied().unwrap_or(COLOR_WHITE) {
                    COLOR_GRAY => {
                        // Back edge, extract the cycle from the path.
                        let pos = path.iter().position(|p| *p == next).unwrap_or(0);
                        let cyc: Vec<String> = path[pos..].iter().map(|s| s.to_string()).collect();
                        if cyc.len() >= 2 && found.len() < 5 && !found.contains(&cyc) {
                            found.push(cyc);
                        }
                    }
                    COLOR_WHITE => {
                        color.insert(next, COLOR_GRAY);
                        path.push(next);
                        dfs.push((next, 0));
                    }
                    _ => {}
                }
            } else {
                color.insert(node, COLOR_BLACK);
                path.pop();
                dfs.pop();
            }
        }
        idx += 1;
    }
    found
}
