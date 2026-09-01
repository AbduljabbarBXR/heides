use std::path::PathBuf;
use std::process::ExitCode;

mod deps;
mod edge;
mod grounding;
mod harmony;
mod indexer;
mod parser;
mod practice;
mod server;
mod spine;
mod staged;
mod taint;
mod watch;
mod web;

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
    println!("  watch [dir]     watch for changes and reindex on demand");
    println!("  mcp             start the MCP server over stdio");
    println!("  version         print the version");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let arg2 = args.get(2).map(|s| s.as_str()).unwrap_or(".");
    let arg3 = args.get(3).map(|s| s.as_str());

    match cmd {
        "scan" => {
            let root = PathBuf::from(arg2);
            let (graph, count) = indexer::build_graph(&root);
            match spine::save(&graph, &root) {
                Ok(()) => {
                    println!(
                        "spine indexed {} files, {} symbols, {} call edges, {} imports ({} parsed)",
                        graph.files.len(),
                        graph.symbols.len(),
                        graph.calls.len(),
                        graph.imports.len(),
                        count
                    );
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
                println!("no spine index found. run: heides scan");
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
                println!("usage: heides query [callers|imports|definition|calls] [name]");
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
                            println!("{} defined at {}:{} (kind {})", s.name, s.file, s.line, s.kind);
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
                _ => {
                    println!("unknown query kind. use callers, imports, definition or calls");
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
                    println!("[{}] {} ({}){}", r.severity, r.message, r.guard, loc);
                }
            }
            ExitCode::SUCCESS
        }
        "staged" => {
            let patch_path = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if patch_path.is_empty() {
                println!("usage: heides staged [patch file]");
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
                            println!("[{}] {} at {}:{}", r.severity, r.message, r.file, r.line);
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
            println!("feasible: {}", verdict.feasible);
            for n in &verdict.notes {
                println!("  {}", n);
            }
            ExitCode::SUCCESS
        }
        "scaffold" => {
            let plan = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let dir = args.get(3).map(|s| s.as_str()).unwrap_or(".");
            if plan.is_empty() {
                println!("usage: heides scaffold [plan text] [dir]");
                return ExitCode::FAILURE;
            }
            match grounding::scaffold(plan, &PathBuf::from(dir)) {
                Ok(files) => {
                    for f in &files {
                        println!("created {}", f);
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
                    println!("[{}] {}", r.severity, r.message);
                }
            }
            ExitCode::SUCCESS
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
