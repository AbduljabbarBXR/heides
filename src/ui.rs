// Display layer for HEIDES.
//
// Every cosmetic terminal effect lives behind this gate. Color and
// progress only ever render on a real terminal, never on a pipe, so the
// byte identical stdout promise, the MCP protocol stream and every log
// that automation captures stay plain. Colors encode the severity
// semantics, red blocker and critical, yellow warning, green info.

use std::io::IsTerminal;
use std::sync::Mutex;

static COLOR_OVERRIDE: Mutex<Option<bool>> = Mutex::new(None);
static GROUPED_OVERRIDE: Mutex<bool> = Mutex::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ui {
    pub color: bool,
    pub progress: bool,
    pub grouped: bool,
}

impl Ui {
    /// Resolve the display settings from the environment plus the flags
    /// that were consumed from the command line.
    pub fn resolve() -> Ui {
        let tty_stdout = std::io::stdout().is_terminal();
        let tty_stderr = std::io::stderr().is_terminal();
        let no_color_env = std::env::var_os("NO_COLOR").is_some()
            || std::env::var_os("TERM")
                .map(|t| t == "dumb")
                .unwrap_or(false);
        let forced = *COLOR_OVERRIDE.lock().unwrap();
        let color = match forced {
            Some(on) => on,
            None => tty_stdout && !no_color_env,
        };
        Ui {
            color,
            progress: tty_stderr && !no_color_env,
            grouped: *GROUPED_OVERRIDE.lock().unwrap(),
        }
    }

    /// Consume a display flag from the argument list. Returns true when
    /// the argument was a flag and should be dropped from the positionals.
    pub fn consume_flag(arg: &str) -> bool {
        match arg {
            "--no-color" => {
                *COLOR_OVERRIDE.lock().unwrap() = Some(false);
                true
            }
            "--color=always" => {
                *COLOR_OVERRIDE.lock().unwrap() = Some(true);
                true
            }
            "--group" => {
                *GROUPED_OVERRIDE.lock().unwrap() = true;
                true
            }
            _ => false,
        }
    }

    /// Wrap a severity token in its color when color is on.
    pub fn severity(&self, severity: &str) -> String {
        let code = match severity {
            "blocker" | "critical" => Some("31"),
            "warning" => Some("33"),
            "info" => Some("32"),
            _ => None,
        };
        match code {
            Some(code) if self.color => format!("\x1b[{}m[{}]\x1b[0m", code, severity),
            _ => format!("[{}]", severity),
        }
    }

    /// Wrap one count token in green for zero, red for anything that
    /// blocks, used by the grouped guard view.
    pub fn count(&self, label: &str, n: usize) -> String {
        let code = match label {
            "blocker" | "critical" => {
                if n == 0 {
                    "32"
                } else {
                    "31"
                }
            }
            "warning" => {
                if n == 0 {
                    "32"
                } else {
                    "33"
                }
            }
            "info" => "32",
            _ => "0",
        };
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, n)
        } else {
            format!("{}", n)
        }
    }
}

/// A running pulse for long lived commands. Only exists when progress is
/// allowed, writes exclusively to stderr, ticks once a second with a
/// carriage return, and clears its own line when the operation ends.
pub struct Stopwatch {
    ui: Ui,
    what: String,
    start: std::time::Instant,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
}

impl Stopwatch {
    pub fn start(ui: &Ui, what: &str) -> Option<Stopwatch> {
        if !ui.progress {
            return None;
        }
        eprintln!("{} running", what);
        eprint!("\x1b]2;heides {}\x07", what);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = std::sync::Arc::clone(&stop);
        let started = std::time::Instant::now();
        let what_owned = what.to_string();
        let ticker = std::thread::spawn(move || {
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let secs = started.elapsed().as_secs();
                eprint!("\r\x1b[2K{} running for {}s", what_owned, secs);
            }
        });
        Some(Stopwatch {
            ui: *ui,
            what: what.to_string(),
            start: std::time::Instant::now(),
            stop,
            ticker: Some(ticker),
        })
    }

    /// Stop the pulse, restore the terminal title and report the elapsed
    /// time on stderr when the operation took at least a second. A bell
    /// rings when the operation ran past ten seconds so a task finished
    /// behind another window announces itself.
    pub fn finish(mut self) {
        let secs = self.start.elapsed().as_secs_f64();
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
        eprint!("\x1b]2;\x07");
        if secs >= 10.0 {
            eprint!("\x07");
        }
        let clear = if self.ui.progress { "\r\x1b[2K" } else { "" };
        if secs >= 1.0 {
            let colored = if self.ui.color {
                "\x1b[32m".to_string()
            } else {
                String::new()
            };
            let reset = if self.ui.color { "\x1b[0m" } else { "" };
            eprintln!(
                "{}{} finished in {:.1}s{}{}",
                clear, colored, secs, reset, self.what
            );
        }
    }
}

impl Drop for Stopwatch {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.ticker.take() {
            let _ = t.join();
        }
        eprint!("\x1b]2;\x07");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_ui() -> Ui {
        *COLOR_OVERRIDE.lock().unwrap() = None;
        *GROUPED_OVERRIDE.lock().unwrap() = false;
        Ui::resolve()
    }

    #[test]
    fn default_resolve_is_plain_in_tests() {
        assert!(!plain_ui().color);
    }

    #[test]
    fn force_color_paints_tokens_force_off_keeps_plain() {
        *COLOR_OVERRIDE.lock().unwrap() = Some(true);
        let ui = Ui::resolve();
        assert!(ui.color);
        assert_eq!(ui.severity("critical"), "\x1b[31m[critical]\x1b[0m");
        assert_eq!(ui.severity("warning"), "\x1b[33m[warning]\x1b[0m");
        assert_eq!(ui.severity("info"), "\x1b[32m[info]\x1b[0m");
        assert_eq!(ui.severity("edge"), "[edge]");
        *COLOR_OVERRIDE.lock().unwrap() = Some(false);
        let ui = Ui::resolve();
        assert_eq!(ui.severity("critical"), "[critical]");
        *COLOR_OVERRIDE.lock().unwrap() = None;
    }

    #[test]
    fn count_reflects_semantics() {
        *COLOR_OVERRIDE.lock().unwrap() = Some(true);
        let ui = Ui::resolve();
        assert_eq!(ui.count("critical", 3), "\x1b[31m3\x1b[0m");
        assert_eq!(ui.count("critical", 0), "\x1b[32m0\x1b[0m");
        assert_eq!(ui.count("warning", 1), "\x1b[33m1\x1b[0m");
        assert_eq!(ui.count("info", 4), "\x1b[32m4\x1b[0m");
        *COLOR_OVERRIDE.lock().unwrap() = None;
    }

    #[test]
    fn flags_are_consumed_and_positionals_kept() {
        assert!(Ui::consume_flag("--no-color"));
        assert!(Ui::consume_flag("--color=always"));
        assert!(Ui::consume_flag("--group"));
        assert!(!Ui::consume_flag("src/main.rs"));
        let ui = Ui::resolve();
        assert!(ui.color);
        assert!(ui.grouped);
        *COLOR_OVERRIDE.lock().unwrap() = None;
        *GROUPED_OVERRIDE.lock().unwrap() = false;
    }
}
