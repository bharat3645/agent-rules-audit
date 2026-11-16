/**
 * Detection rules for AI agent instruction-file poisoning.
 *
 * Each rule targets a pattern class observed in real-world instruction-file
 * and MCP supply-chain attacks (hidden Unicode smuggling, encoded payloads,
 * instruction overrides, exfiltration directives, silent-execution and
 * autonomy-escalation phrasing).
 *
 * Severity model: critical=25, high=15, medium=8, low=3 points.
 * Grades: A=0, B<=8, C<=20, D<=40, F>40 (per file and overall).
 */

export const SEVERITY_POINTS = { critical: 25, high: 15, medium: 8, low: 3 };

// Hidden-character detection is driven by Unicode properties, not a
// hand-maintained range list: every Default_Ignorable_Code_Point or
// Bidi_Control character renders as nothing, so each one can carry text a
// human reviewer cannot see.
const HIDDEN_RE = /[\p{Default_Ignorable_Code_Point}\p{Bidi_Control}]/u;
const BIDI_RE = /\p{Bidi_Control}/u;
const TAG_BLOCK_RE = /[\u{E0000}-\u{E007F}]/u;
const VARIATION_SELECTOR_RE = /\p{Variation_Selector}/u;
const PICTOGRAPHIC_RE = /\p{Extended_Pictographic}/u;
const EMOJI_MODIFIER_RE = /\p{Emoji_Modifier}/u;
const VS_TEXT_BASE_RE = /[\p{Extended_Pictographic}\p{Emoji}\p{S}\p{Script=Han}\p{Script=Myanmar}\p{Script=Phags_Pa}]/u;
const HAN_RE = /\p{Script=Han}/u;
const MONGOLIAN_RE = /\p{Script=Mongolian}/u;

// A variation selector is legitimate only directly after a base it can
// actually vary (emoji presentation, keycaps, CJK/Mongolian variants).
// After ASCII text, after another selector, or at line start it selects
// nothing and is a pure data channel (variation-selector smuggling).
function isLegitVariationSelector(cps, i) {
  const prev = cps[i - 1];
  if (prev === undefined) return false;
  const cp = cps[i].codePointAt(0);
  if (cp >= 0xe0100) return HAN_RE.test(prev);
  if (cp < 0xfe00) return MONGOLIAN_RE.test(prev);
  if (/[0-9#*]/.test(prev)) return cp === 0xfe0f && cps[i + 1] === "\u20e3";
  if (prev.codePointAt(0) < 0x80) return false;
  return VS_TEXT_BASE_RE.test(prev);
}

// ZWJ between two pictographs is an ordinary emoji sequence (family, flag,
// profession emoji) and hides nothing.
function isEmojiJoiner(cps, i) {
  let j = i - 1;
  while (j >= 0 && (cps[j] === "\ufe0f" || EMOJI_MODIFIER_RE.test(cps[j]))) j--;
  return j >= 0 && PICTOGRAPHIC_RE.test(cps[j]) && cps[i + 1] !== undefined && PICTOGRAPHIC_RE.test(cps[i + 1]);
}

/** Returns a description of the hidden characters on a line, or null. */
export function hiddenUnicodeKind(lineText) {
  if (!HIDDEN_RE.test(lineText)) return null;
  const cps = Array.from(lineText);
  let tag = false, bidi = false, selector = false, invisible = false;
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    if (!HIDDEN_RE.test(ch)) continue;
    if (VARIATION_SELECTOR_RE.test(ch)) {
      if (!isLegitVariationSelector(cps, i)) selector = true;
    } else if (ch === "\u200d" && isEmojiJoiner(cps, i)) {
      continue;
    } else if (TAG_BLOCK_RE.test(ch)) {
      tag = true;
    } else if (BIDI_RE.test(ch)) {
      bidi = true;
    } else {
      invisible = true;
    }
  }
  if (tag) return "Unicode tag-block characters (ASCII smuggling)";
  if (bidi) return "bidirectional-override characters";
  if (selector) return "variation-selector characters (invisible data smuggling)";
  if (invisible) return "zero-width/invisible characters";
  return null;
}

const BASE64_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
const HEX_RE = /(?:[0-9a-fA-F]{2}){24,}/g;

const SUSPICIOUS_DECODED_RE =
  /(https?:|curl |wget |token|secret|password|api[_-]?key|ignore previous|\.ssh|\.env)/i;

function printableRatio(s) {
  if (s.length === 0) return 0;
  let printable = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x0a || c === 0x0d || c === 0x09) printable++;
  }
  return printable / s.length;
}

function tryBase64Decode(s) {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}

/** Line-based regex rules: { id, severity, re, message } */
const LINE_RULES = [
  {
    id: "instruction-override",
    severity: "critical",
    re: /(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|earlier|above|system)\s+(instructions?|rules?|prompts?|constraints?)/i,
    message: "Attempts to override the agent's existing instructions",
  },
  {
    id: "concealment",
    severity: "critical",
    re: /do\s+not\s+(tell|inform|mention|reveal|show|notify|alert)\s+(this\s+to\s+)?(the\s+)?(user|human|developer|owner)|without\s+(the\s+)?user('s)?\s+(knowledge|noticing)|keep\s+this\s+(secret|hidden)\s+from/i,
    message: "Instructs the agent to conceal actions from the user",
  },
  {
    id: "exfil-network",
    severity: "critical",
    re: /(curl|wget|fetch|httpx?|Invoke-WebRequest|requests\.(get|post))\s[^\n]*https?:\/\/|https?:\/\/(\d{1,3}\.){3}\d{1,3}|https?:\/\/[^\s"')]*(webhook\.site|requestbin|pipedream\.net|ngrok\.(io|app)|burpcollaborator|interact\.sh|oastify\.com)/i,
    message: "Network call to an external/attacker-style endpoint",
  },
  {
    id: "exfil-data",
    severity: "critical",
    re: /(send|post|upload|transmit|forward|exfiltrate)\s[^\n]*(env(ironment)?\s+var|credentials?|secrets?|tokens?|api[_-]?keys?|passwords?|\.ssh|\.env|keychain)/i,
    message: "Directs sending secrets or credentials somewhere",
  },
  {
    id: "secret-access",
    severity: "high",
    re: /(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.netrc|\.npmrc|authorized_keys|\.kube\/config|(read|cat|open|dump|print)\s[^\n]*\.env\b)/i,
    message: "References reading credential/secret storage paths",
  },
  {
    id: "dangerous-exec",
    severity: "high",
    re: /(curl|wget)\s[^\n|]*\|\s*(ba)?sh|rm\s+-rf\s+[~/]|chmod\s+777|powershell\s[^\n]*-enc(odedcommand)?|(run|execute)\s[^\n]*(silently|quietly|in\s+the\s+background\s+without)/i,
    message: "Dangerous or silent command execution pattern",
  },
  {
    id: "autonomy-escalation",
    severity: "medium",
    re: /without\s+(asking|confirmation|approval|prompting)|automatically\s+(approve|accept|allow|confirm)|always\s+allow|--dangerously-skip-permissions|never\s+ask\s+(for\s+)?(permission|confirmation)/i,
    message: "Pushes the agent to skip permission/confirmation gates",
  },
  {
    id: "role-hijack",
    severity: "medium",
    re: /(pretend|act\s+as\s+if)\s[^\n]*(authorized|admin|root|no\s+restrictions)|you\s+are\s+now\s+(in\s+)?(developer|god|unrestricted)\s*mode/i,
    message: "Role/authority hijack phrasing",
  },
];

/**
 * Scan a text document. Returns an array of findings:
 * { ruleId, severity, line, excerpt, message }
 */
export function scanText(text) {
  const findings = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((lineText, idx) => {
    const line = idx + 1;
    const excerpt =
      lineText.length > 120 ? lineText.slice(0, 117) + "..." : lineText;

    for (const rule of LINE_RULES) {
      if (rule.re.test(lineText)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          line,
          excerpt: excerpt.trim(),
          message: rule.message,
        });
      }
    }

    const kind = hiddenUnicodeKind(lineText);
    if (kind) {
      findings.push({
        ruleId: "hidden-unicode",
        severity: "critical",
        line,
        excerpt: "(contains invisible characters)",
        message: `Hidden ${kind} - text invisible to human reviewers`,
      });
    }

    for (const m of lineText.matchAll(BASE64_RE)) {
      const decoded = tryBase64Decode(m[0]);
      if (printableRatio(decoded) > 0.85) {
        const suspicious = SUSPICIOUS_DECODED_RE.test(decoded);
        findings.push({
          ruleId: "encoded-payload",
          severity: suspicious ? "high" : "low",
          line,
          excerpt: m[0].slice(0, 40) + "...",
          message: suspicious
            ? "Base64 blob decodes to suspicious instructions"
            : "Opaque base64 blob in an instruction file",
        });
      }
    }

    for (const m of lineText.matchAll(HEX_RE)) {
      const decoded = Buffer.from(m[0], "hex").toString("utf8");
      if (printableRatio(decoded) > 0.85) {
        findings.push({
          ruleId: "encoded-payload",
          severity: SUSPICIOUS_DECODED_RE.test(decoded) ? "high" : "low",
          line,
          excerpt: m[0].slice(0, 40) + "...",
          message: "Hex blob decodes to readable text",
        });
      }
    }
  });

  return findings;
}

export function scoreFindings(findings) {
  return findings.reduce((sum, f) => sum + (SEVERITY_POINTS[f.severity] ?? 0), 0);
}

export function grade(score) {
  if (score === 0) return "A";
  if (score <= 8) return "B";
  if (score <= 20) return "C";
  if (score <= 40) return "D";
  return "F";
}
