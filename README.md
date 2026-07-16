# agent-rules-audit

**Your AI agent takes instructions from files in your repo. Who audits the files?**

`agent-rules-audit` is an offline scanner for agent instruction files - `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `.claude/skills/**`, Copilot instructions, MCP configs. It flags the patterns used in real instruction-file poisoning attacks: hidden Unicode smuggling, encoded payloads, instruction overrides, exfiltration directives, silent-execution and permission-bypass phrasing.

Zero dependencies. Zero network calls. Node >= 18.

## Why

Instruction files are executed as trusted context by coding agents, but reviewed as "just docs" by humans - when they're reviewed at all. In-the-wild supply-chain campaigns have already used poisoned `.cursorrules` and MCP-related injection as attack vectors, and skills/marketplace ecosystems have shipped hundreds of malicious agent skills. A dependency you vendored, a template you cloned, a skill you installed - any of them can carry instructions your agent will follow and you will never see.

This tool makes those files reviewable in CI, the same way you lint code.

## Install / Run

```bash
# from a checkout (no install needed)
node bin/cli.js /path/to/repo

# or via npx once published
npx agent-rules-audit .
```

## Usage

```bash
agent-rules-audit [paths...] [--json] [--sarif] [--strict] [--quiet]
```

- Scans given paths (default `.`) recursively for known instruction files; skips `node_modules`, `.git`, `dist`, `build`, `vendor`, `target`.
- `--json` - machine-readable report.
- `--sarif` - SARIF 2.1.0 output for GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF consumers.
- `--strict` - exit 1 on **any** finding (for CI gates).
- `--quiet` - hide clean files in human output.

Exit codes: `0` grade A/B; `2` grade C/D; `3` grade F; `1` any finding under `--strict`; `4` usage error.

## What it detects

| Rule | Severity | Example trigger |
|---|---|---|
| `hidden-unicode` | critical | zero-width chars, bidi overrides, Unicode tag-block (ASCII smuggling) |
| `instruction-override` | critical | "ignore all previous instructions" |
| `concealment` | critical | "do not tell the user" |
| `exfil-network` | critical | `curl https://...`, webhook.site / ngrok / raw-IP endpoints |
| `exfil-data` | critical | "send the API keys to ..." |
| `secret-access` | high | `~/.ssh/id_rsa`, `.aws/credentials`, "cat .env" |
| `dangerous-exec` | high | `curl ... \| sh`, `rm -rf ~`, "run silently" |
| `encoded-payload` | high/low | base64/hex blobs that decode to readable (suspicious) text |
| `autonomy-escalation` | medium | "without asking", "always allow", `--dangerously-skip-permissions` |
| `role-hijack` | medium | "you are now in developer mode" |

Files are graded **A-F** (critical=25, high=15, medium=8, low=3 points), plus an overall grade.

## CI example (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 22 }
- run: npx agent-rules-audit . --strict
```

## GitHub Code Scanning (SARIF)

`--sarif` emits SARIF 2.1.0 with per-rule `security-severity` metadata, so findings show up as native Code Scanning alerts on the Security tab and inline on pull requests:

```yaml
name: agent-rules-audit
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - name: Scan instruction files
        run: npx agent-rules-audit . --sarif > results.sarif
        continue-on-error: true # exit code reflects grade; upload alerts regardless
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
```

Severity mapping: critical/high → `error`, medium → `warning`, low → `note`; `security-severity` scores (9.5 / 8.0 / 5.0-6.0 / 3.0) drive GitHub's Critical/High/Medium/Low badges.

## Honest limitations

- **Pattern-based.** It catches known attack shapes, not novel semantics. An A grade is *not* a security guarantee.
- **It will have false positives** - security docs that *describe* attacks (like this README) will trigger it. That's what human review of findings is for; use `--json` or `--sarif` to build allowlists downstream.
- It scans instruction files only, by filename/location convention. It does not execute anything or phone home - by design.

## Roadmap

- pre-commit hook recipe
- allowlist/baseline file (`.agent-rules-audit.json`)
- MCP tool-description drift detection (see sibling project `mcp-sentinel`)
- npm publish

## Related projects by the same author

[`mcp-sentinel`](https://github.com/bharat3645/mcp-sentinel) | [`agent-tool-audit`](https://github.com/bharat3645/agent-tool-audit) | [`ollama-audit`](https://github.com/bharat3645/ollama-audit) | [`dep-graveyard`](https://github.com/bharat3645/dep-graveyard)

## License

MIT (c) 2026 Bharat Singh Parihar
