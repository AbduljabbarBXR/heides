# Contributing

Thank you for helping HEIDES grow. This file explains how to contribute safely.

## Ground rules

* Every change must pass the gate. cargo build, cargo test, and the serial battle suite.
* Keep the harness deterministic. If a rule can prove a fact, do not replace it with a model call.
* Every new guard or parser must come with a test.

## Ways to contribute

* Report bugs with a minimal reproduction.
* Suggest new taint sources and sinks per language.
* Add tree sitter support for another language.
* Improve the battle suite with new scenarios.
* Write documentation and examples.

## Development flow

1. Fork the repository.
2. Create a branch.
3. Make your change and add a test for it.
4. Run cargo build and cargo test.
5. Open a pull request with a clear description.

## Code of conduct

Be respectful. Review code on its merits.
