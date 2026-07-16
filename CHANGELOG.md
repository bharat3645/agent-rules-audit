# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

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
