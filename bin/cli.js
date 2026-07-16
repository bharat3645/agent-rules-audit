#!/usr/bin/env node
/**
 * agent-rules-audit — offline scanner for AI agent instruction files.
 *
 * Usage:
 *   agent-rules-audit [paths...] [--json] [--sarif] [--strict] [--quiet]
 *                     [--baseline PATH] [--no-baseline]
 *
 * Exit codes:
 *   0  overall grade A or B (or no findings with --strict)
 *   2  overall grade C or D
 *   3  overall grade F
 *   1  any finding at all, when --strict is set (overrides above)
 *   4  usage/config error
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { audit } from "../lib/scanner.js";
import { toSarif } from "../lib/sarif.js";
import {
  BASELINE_FILENAME,
  BaselineError,
  applyBaseline,
  loadBaseline,
} from "../lib/baseline.js";

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith("--") && !a.includes("=")));
const baselineArgIdx = args.indexOf("--baseline");
const baselinePathArg =
  baselineArgIdx !== -1 ? args[baselineArgIdx + 1] : undefined;
const paths = args.filter(
  (a, i) =>
    !a.startsWith("--") && (baselineArgIdx === -1 || i !== baselineArgIdx + 1),
);
if (paths.length === 0) paths.push(".");

if (flags.has("--help") || flags.has("-h")) {
  console.log(
    "agent-rules-audit [paths...] [--json] [--sarif] [--strict] [--quiet]\n" +
      "                  [--baseline PATH] [--no-baseline]\n" +
      "Scans AGENTS.md / CLAUDE.md / .cursorrules / .claude skills & agents /\n" +
      "MCP configs for injection, exfiltration and hidden-Unicode patterns.\n\n" +
      "  --json           machine-readable report\n" +
      "  --sarif          SARIF 2.1.0 output (GitHub Code Scanning, VS Code)\n" +
      "  --strict         exit 1 on any finding (CI gate)\n" +
      "  --quiet          hide clean files in human output\n" +
      `  --baseline PATH  allowlist file (default: ${BASELINE_FILENAME} in cwd)\n` +
      "  --no-baseline    ignore any baseline file",
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

// Baseline: explicit --baseline PATH, else auto-discover in cwd unless --no-baseline.
let suppressed = 0;
try {
  let baselinePath = null;
  if (baselinePathArg) {
    baselinePath = baselinePathArg;
  } else if (!flags.has("--no-baseline") && existsSync(resolve(BASELINE_FILENAME))) {
    baselinePath = resolve(BASELINE_FILENAME);
  }
  if (baselinePath) {
    const baseline = loadBaseline(baselinePath);
    const applied = applyBaseline(report, baseline);
    report = applied.report;
    suppressed = applied.suppressed;
  }
} catch (err) {
  if (err instanceof BaselineError) {
    console.error(`agent-rules-audit: ${err.message}`);
    process.exit(4);
  }
  throw err;
}

const SEV_ICON = { critical: "✖", high: "▲", medium: "●", low: "·" };

if (flags.has("--sarif")) {
  console.log(JSON.stringify(toSarif(report), null, 2));
} else if (flags.has("--json")) {
  console.log(JSON.stringify({ ...report, suppressed }, null, 2));
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
      `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low` +
      (suppressed ? ` (${suppressed} suppressed by baseline)` : ""),
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
