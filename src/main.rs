use std::process::ExitCode;

mod grounding;
mod harmony;
mod server;
mod spine;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    println!("HEIDES {}  the code nervous system", VERSION);
    println!();
    println!("A deterministic harness that gives AI agents senses, memory and judgment for code.");
    println!();
    println!("Commands");
    println!("  mcp       start the MCP server over stdio (connect any agent or tool)");
    println!("  scan      map the current codebase into the persistent spine index");
    println!("  status    report the state of the spine index");
    println!("  version   print the version");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("mcp") => server::run(),
        Some("scan") => spine::scan(&args),
        Some("status") => spine::status(),
        Some("version") => {
            println!("{}", VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::SUCCESS
        }
    }
}
