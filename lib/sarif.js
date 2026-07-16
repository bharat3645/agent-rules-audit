/**
 * SARIF 2.1.0 reporter for agent-rules-audit.
 *
 * Converts an audit report (from lib/scanner.js) into a SARIF log that
 * GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF consumers
 * can ingest. Zero dependencies, pure transformation — no I/O.
 *
 * Severity mapping:
 *   critical / high -> "error"
 *   medium          -> "warning"
 *   low             -> "note"
 *
 * Each rule also carries a "security-severity" property so GitHub Code
 * Scanning displays Critical/High/Medium/Low badges (CVSS-style scale).
 */

import { relative, isAbsolute, sep } from "node:path";

const TOOL_NAME = "agent-rules-audit";
const INFO_URI = "https://github.com/bharat3645/agent-rules-audit";

/** Static metadata for every rule the scanner can emit. */
export const RULE_METADATA = [
  {
    id: "instruction-override",
    description: "Attempts to override the agent's existing instructions",
    level: "error",
    securitySeverity: "9.5",
  },
  {
    id: "concealment",
    description: "Instructs the agent to conceal actions from the user",
    level: "error",
    securitySeverity: "9.5",
  },
  {
    id: "exfil-network",
    description: "Network call to an external/attacker-style endpoint",
    level: "error",
    securitySeverity: "9.5",
  },
  {
    id: "exfil-data",
    description: "Directs sending secrets or credentials somewhere",
    level: "error",
    securitySeverity: "9.5",
  },
  {
    id: "hidden-unicode",
    description:
      "Hidden Unicode (zero-width, bidi override, or tag-block) invisible to human reviewers",
    level: "error",
    securitySeverity: "9.5",
  },
  {
    id: "secret-access",
    description: "References reading credential/secret storage paths",
    level: "error",
    securitySeverity: "8.0",
  },
  {
    id: "dangerous-exec",
    description: "Dangerous or silent command execution pattern",
    level: "error",
    securitySeverity: "8.0",
  },
  {
    id: "encoded-payload",
    description: "Base64/hex blob that decodes to readable (possibly suspicious) text",
    level: "warning",
    securitySeverity: "6.0",
  },
  {
    id: "autonomy-escalation",
    description: "Pushes the agent to skip permission/confirmation gates",
    level: "warning",
    securitySeverity: "5.0",
  },
  {
    id: "role-hijack",
    description: "Role/authority hijack phrasing",
    level: "warning",
    securitySeverity: "5.0",
  },
  {
    id: "oversize-file",
    description: "Instruction file unusually large; deep scan skipped",
    level: "note",
    securitySeverity: "3.0",
  },
];

const LEVEL_BY_SEVERITY = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/** Make a path SARIF-friendly: relative to cwd when possible, forward slashes. */
function toArtifactUri(path, cwd) {
  let p = path;
  if (isAbsolute(p)) {
    const rel = relative(cwd, p);
    if (rel && !rel.startsWith("..")) p = rel;
  }
  return p.split(sep).join("/");
}

/**
 * Convert an audit report to a SARIF 2.1.0 log object.
 * @param {object} report - output of audit() from lib/scanner.js
 * @param {object} [opts]
 * @param {string} [opts.cwd] - base for relativizing file paths (default process.cwd())
 */
export function toSarif(report, opts = {}) {
  const cwd = opts.cwd ?? process.cwd();
  const ruleIndexById = new Map(RULE_METADATA.map((r, i) => [r.id, i]));

  const results = [];
  for (const file of report.files) {
    const uri = toArtifactUri(file.path, cwd);
    for (const f of file.findings) {
      results.push({
        ruleId: f.ruleId,
        ruleIndex: ruleIndexById.get(f.ruleId) ?? -1,
        level: LEVEL_BY_SEVERITY[f.severity] ?? "warning",
        message: {
          text: f.excerpt ? `${f.message}: ${f.excerpt}` : f.message,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri, uriBaseId: "SRCROOT" },
              region: { startLine: Math.max(1, f.line) },
            },
          },
        ],
        partialFingerprints: {
          // Stable across runs for the same file/line/rule.
          primaryLocationLineHash: `${f.ruleId}:${uri}:${f.line}`,
        },
      });
    }
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: INFO_URI,
            version: report.version,
            rules: RULE_METADATA.map((r) => ({
              id: r.id,
              name: r.id
                .split("-")
                .map((w) => w[0].toUpperCase() + w.slice(1))
                .join(""),
              shortDescription: { text: r.description },
              helpUri: `${INFO_URI}#what-it-detects`,
              defaultConfiguration: { level: r.level },
              properties: {
                "security-severity": r.securitySeverity,
                tags: ["security", "prompt-injection", "ai-agents"],
              },
            })),
          },
        },
        originalUriBaseIds: {
          SRCROOT: { uri: "file:///" },
        },
        results,
      },
    ],
  };
}
