# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.3.0] - 2026-07-16

### Added
- **Baseline / allowlist** (`.agent-rules-audit.json`): accept specific known
  findings (docs that describe attacks, payload fixtures) without disabling
  the scanner. Entries match by `ruleId` + path suffix (`"*"` for any path),
  never by line number; each carries a `reason`. Auto-loaded from the working
  directory, override with `--baseline PATH`, disable with `--no-baseline`.
  Suppressed findings are removed before grading/exit codes, surfaced as a
  count in human output and a `suppressed` field in `--json`.
- **Pre-commit support**: `.pre-commit-hooks.yaml` for the pre-commit
  framework (`repo: …/agent-rules-audit`, `id: agent-rules-audit`) plus a
  plain git-hook recipe in the README.
- 8 new tests (suite 27 → 35).

### Fixed
- CLI argument parsing: first positional path is no longer swallowed when no
  `--baseline` flag is present (caught by the test suite during development).

## [0.2.0] - 2026-07-16

### Added
- **SARIF 2.1.0 output** (`--sarif`): new `lib/sarif.js` reporter converting audit
  reports into SARIF logs consumable by GitHub Code Scanning, the VS Code SARIF
  Viewer, and other SARIF tooling.
  - Full rule metadata (11 rules) with `defaultConfiguration.level` and
    `security-severity` properties, so GitHub renders Critical/High/Medium/Low badges.
  - Severity mapping: critical/high → `error`, medium → `warning`, low → `note`
    (per-finding level overrides the rule default, e.g. low-severity `encoded-payload`).
  - Paths relativized to the working directory with forward slashes; `line 0`
    findings clamped to `startLine: 1` per SARIF minimum.
  - Stable `partialFingerprints` for alert deduplication across runs.
- 6 new tests (4 unit, 2 CLI integration) covering SARIF shape, severity/level
  mapping, rule-index consistency, line clamping, and end-to-end CLI output — suite
  now 27 tests.
- Code Scanning workflow example in the README and a SARIF upload job in CI.

### Changed
- `--help` now documents all flags.
- Report `version` bumped to 0.2.0.

## [0.1.0] - 2026-07-16

### Added
- Initial release: 10 detection rule classes, A-F grading, file discovery for
  AGENTS.md / CLAUDE.md / GEMINI.md / .cursorrules / .windsurfrules / .clinerules /
  Copilot instructions / `.claude` skills & agents / MCP configs.
- CLI with `--json`, `--strict`, `--quiet`; grade-based exit codes.
- 21-test suite (node:test); GitHub Actions CI (Node 18/20/22) with dogfood self-scan.
- MIT license.
