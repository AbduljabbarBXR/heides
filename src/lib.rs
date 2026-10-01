// HEIDES, the code nervous system.
//
// A deterministic harness that gives AI agents senses, memory and judgment
// for code. The library exposes every organ so tests and embeddings can call
// the guards directly.

pub mod config;
pub mod db;
pub mod deadcode;
pub mod deps;
pub mod edge;
pub mod frameworks;
pub mod grounding;
pub mod harmony;
pub mod indexer;
pub mod interproc;
pub mod lockgraph;
pub mod lockparse;
pub mod osv_cache;
pub mod parser;
pub mod practice;
pub mod server;
pub mod spine;
pub mod staged;
pub mod taint;
pub mod ui;
pub mod verify;
pub mod watch;
pub mod web;
