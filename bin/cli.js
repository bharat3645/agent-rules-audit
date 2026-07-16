#!/usr/bin/env node
/**
 * agent-rules-audit — offline scanner for AI agent instruction files.
 *
 * Usage:
 *   agent-rules-audit [paths...] [--json] [--sarif] [--strict] [--quiet]
 *
 * Exit codes:
 *   0  overall grade A or B (or no findings with --strict)
 *   2  overall grade C or D
 *   3  overall grade F
 *   1  any finding at all, when --strict is set (overrides above)
 */

import { audit } from "../lib/scanner.js";
import { toSarif } from "../lib/sarif.js";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--")));
const paths = args.filter((a) => !a.startsWith("--"));
if (paths.length === 0) paths.push(".");

if (flags.has("--help") || flags.has("-h")) {
  console.log(
    "agent-rules-audit [paths...] [--json] [--sarif] [--strict] [--quiet]\n" +
      "Scans AGENTS.md / CLAUDE.md / .cursorrules / .claude skills & agents /\n" +
      "MCP configs for injection, exfiltration and hidden-Unicode patterns.\n\n" +
      "  --json    machine-readable report\n" +
      "  --sarif   SARIF 2.1.0 output (GitHub Code Scanning, VS Code)\n" +
      "  --strict  exit 1 on any finding (CI gate)\n" +
      "  --quiet   hide clean files in human output",
  );
  process.exit(0);
}

let report;
try {
  report = audit(paths);
} catch (err) {
  console.error(`agent-rules-audit: ${err.message}`);
  process.exit(4);
}

const SEV_ICON = { critical: "✖", high: "▲", medium: "●", low: "·" };

if (flags.has("--sarif")) {
  console.log(JSON.stringify(toSarif(report), null, 2));
} else if (flags.has("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`agent-rules-audit v${report.version} — ${report.scannedFiles} file(s) scanned\n`);
  for (const f of report.files) {
    if (f.findings.length === 0 && flags.has("--quiet")) continue;
    console.log(`${f.grade}  ${f.path}  (score ${f.score})`);
    for (const fd of f.findings) {
      console.log(
        `   ${SEV_ICON[fd.severity]} [${fd.severity}] L${fd.line} ${fd.ruleId}: ${fd.message}`,
      );
      if (fd.excerpt) console.log(`     ${fd.excerpt}`);
    }
  }
  const c = report.overall.counts;
  console.log(
    `\nOVERALL: ${report.overall.grade} (score ${report.overall.score}) — ` +
      `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low`,
  );
  if (report.overall.grade !== "A") {
    console.log(
      "Review flagged lines before letting an agent consume these files.\n" +
        "Pattern-based detection: findings need human judgment; absence of findings is not a guarantee.",
    );
  }
}

const anyFindings = report.files.some((f) => f.findings.length > 0);
if (flags.has("--strict") && anyFindings) process.exit(1);
const g = report.overall.grade;
process.exit(g === "A" || g === "B" ? 0 : g === "F" ? 3 : 2);
