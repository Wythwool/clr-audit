# Changelog

## Unreleased

## [0.2.0] - 2026-07-06
- Reworked the CLI into a deterministic `audit` command with strict argument parsing.
- Added JSON, SARIF, CSV, and Markdown report outputs.
- Added `--recursive`, `--fail-on`, `--version`, and structured exit behavior.
- Added nested type scanning and more IL checks for loaders, P/Invoke, process creation, binary serialization, dynamic code, native marshaling, network fetches, URL literals, encoded strings, and executable-looking resources.
- Added generated sample-assembly tests and CI on Windows and Linux.
