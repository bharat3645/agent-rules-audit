/**
 * File discovery + orchestration for agent-rules-audit.
 * Finds agent instruction files under given paths, scans each,
 * and produces a scored report. No network. No dependencies.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { scanText, scoreFindings, grade } from "./rules.js";

const KNOWN_FILENAMES = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "GEMINI.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  "copilot-instructions.md",
  "SKILL.md",
  ".mcp.json",
  "mcp.json",
]);

const KNOWN_DIR_HINTS = [
  [".cursor", "rules"], // .cursor/rules/*
  [".claude", "skills"], // .claude/skills/**
  [".claude", "agents"], // .claude/agents/*
];

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "vendor",
  "target",
  ".next",
  "__pycache__",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

function isInsideHintDir(relParts) {
  for (const hint of KNOWN_DIR_HINTS) {
    for (let i = 0; i + hint.length <= relParts.length; i++) {
      if (hint.every((seg, j) => relParts[i + j] === seg)) return true;
    }
  }
  return false;
}

/** Recursively collect candidate instruction files under root. */
export function findTargets(root) {
  const out = [];
  const st = statSync(root);
  if (st.isFile()) return [root];

  const walk = (dir, relParts) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        walk(join(dir, e.name), [...relParts, e.name]);
      } else if (e.isFile()) {
        const inHintDir = isInsideHintDir(relParts);
        if (
          KNOWN_FILENAMES.has(e.name) ||
          (inHintDir && (e.name.endsWith(".md") || e.name.endsWith(".mdc") || e.name.endsWith(".json")))
        ) {
          out.push(join(dir, e.name));
        }
      }
    }
  };
  walk(root, []);
  return out.sort();
}

/** Scan one file → { path, findings, score, grade } */
export function scanFile(path) {
  const size = statSync(path).size;
  if (size > MAX_FILE_BYTES) {
    return {
      path,
      findings: [
        {
          ruleId: "oversize-file",
          severity: "low",
          line: 0,
          excerpt: `${size} bytes`,
          message: "Instruction file unusually large; skipped deep scan",
        },
      ],
      score: 3,
      grade: "B",
    };
  }
  const text = readFileSync(path, "utf8");
  const findings = scanText(text);
  const score = scoreFindings(findings);
  return { path, findings, score, grade: grade(score) };
}

/** Scan a list of root paths → full report object. */
export function audit(paths) {
  const targets = [];
  for (const p of paths) targets.push(...findTargets(p));
  const unique = [...new Set(targets)];
  const files = unique.map(scanFile);

  const totalScore = files.reduce((s, f) => s + f.score, 0);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of files) for (const fd of f.findings) counts[fd.severity]++;

  return {
    version: "0.2.0",
    scannedFiles: files.length,
    files,
    overall: {
      score: totalScore,
      grade: grade(totalScore),
      counts,
    },
  };
}

export { basename };
