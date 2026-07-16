/**
 * Baseline / allowlist support (.agent-rules-audit.json).
 *
 * A baseline lets a repo accept specific known findings (e.g. a security
 * README that *describes* attacks) without turning the scanner off. Each
 * ignore entry must name a ruleId and a path ("*" for any path), and should
 * carry a human reason -- baselines are reviewable security decisions, not
 * silencers.
 *
 * {
 *   "version": 1,
 *   "ignore": [
 *     { "ruleId": "exfil-network", "path": "README.md", "reason": "docs describe attacks" },
 *     { "ruleId": "encoded-payload", "path": "*", "reason": "fixture blobs" }
 *   ]
 * }
 *
 * Matching is by ruleId + path suffix (so absolute vs relative scan paths
 * both work), never by line number -- lines shift on every edit.
 */

import { readFileSync } from "node:fs";
import { sep } from "node:path";
import { scoreFindings, grade } from "./rules.js";

export const BASELINE_FILENAME = ".agent-rules-audit.json";
export const BASELINE_VERSION = 1;

export class BaselineError extends Error {}

function normalize(p) {
  return String(p).split(sep).join("/").replace(/^\.\//, "");
}

/** Load and validate a baseline file. */
export function loadBaseline(path) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new BaselineError(`Cannot read baseline ${path}: ${err.message}`);
  }
  if (typeof doc !== "object" || doc === null || !Array.isArray(doc.ignore)) {
    throw new BaselineError(
      `${path}: baseline must be an object with an "ignore" array.`,
    );
  }
  if (doc.version !== BASELINE_VERSION) {
    throw new BaselineError(
      `${path}: unsupported baseline version ${JSON.stringify(doc.version)} ` +
        `(this build supports ${BASELINE_VERSION}).`,
    );
  }
  doc.ignore.forEach((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new BaselineError(`${path}: ignore[${i}] must be an object.`);
    }
    if (typeof entry.ruleId !== "string" || entry.ruleId.length === 0) {
      throw new BaselineError(`${path}: ignore[${i}] needs a "ruleId" string.`);
    }
    if (typeof entry.path !== "string" || entry.path.length === 0) {
      throw new BaselineError(
        `${path}: ignore[${i}] needs a "path" string ("*" for any path).`,
      );
    }
  });
  return doc;
}

function matches(entry, filePath, finding) {
  if (entry.ruleId !== finding.ruleId) return false;
  if (entry.path === "*") return true;
  const file = normalize(filePath);
  const want = normalize(entry.path);
  return file === want || file.endsWith("/" + want);
}

/**
 * Apply a baseline to a report from audit(). Returns a NEW report with
 * suppressed findings removed and scores/grades recomputed, plus counts.
 */
export function applyBaseline(report, baseline) {
  let suppressed = 0;
  const files = report.files.map((f) => {
    const kept = f.findings.filter((fd) => {
      const hit = baseline.ignore.some((entry) => matches(entry, f.path, fd));
      if (hit) suppressed++;
      return !hit;
    });
    const score = scoreFindings(kept);
    return { ...f, findings: kept, score, grade: grade(score) };
  });

  const totalScore = files.reduce((s, f) => s + f.score, 0);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of files) for (const fd of f.findings) counts[fd.severity]++;

  return {
    report: {
      ...report,
      files,
      overall: { score: totalScore, grade: grade(totalScore), counts },
    },
    suppressed,
  };
}
