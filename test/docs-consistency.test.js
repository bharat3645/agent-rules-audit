import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { grade } from "../lib/rules.js";
import { RULE_METADATA } from "../lib/sarif.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const docPath = join(
  __dirname,
  "..",
  "skills",
  "audit-agent-instructions",
  "references",
  "detection-patterns.md",
);

// The skill's reference doc tells an auditing agent to compute grades by
// hand from the scanner's own point weights, and explicitly claims the
// result agrees with a CI run of the real scanner ("Severity weights match
// the agent-rules-audit scanner so a skill-based audit and a CI run
// agree"). That claim only holds if the documented A/B/C/D/F cutoffs are
// the same cutoffs lib/rules.js actually uses -- otherwise the same set of
// findings gets a different grade depending on which path produced it.
test("skill reference doc's grade thresholds match the scanner's grade()", () => {
  const doc = readFileSync(docPath, "utf8");
  const m = doc.match(
    /Grades:\s*A\s*(?:=|≤)\s*(\d+),\s*B\s*≤\s*(\d+),\s*C\s*≤\s*(\d+),\s*D\s*≤\s*(\d+),\s*F\s*>\s*(\d+)/,
  );
  assert.ok(
    m,
    "detection-patterns.md should state grade cutoffs as 'Grades: A = N, B ≤ N, C ≤ N, D ≤ N, F > N'",
  );
  const [a, b, c, d, f] = m.slice(1).map(Number);

  assert.equal(grade(a), "A", `doc's A cutoff (${a}) does not grade A in the real scanner`);
  assert.equal(grade(b), "B", `doc's B cutoff (${b}) does not grade B in the real scanner`);
  assert.equal(grade(c), "C", `doc's C cutoff (${c}) does not grade C in the real scanner`);
  assert.equal(grade(d), "D", `doc's D cutoff (${d}) does not grade D in the real scanner`);
  // "F > N" means N itself is the top of D's range; N+1 is the first F.
  assert.equal(grade(f), "D", `doc's F threshold (${f}) should still grade D (F starts just above it)`);
  assert.equal(grade(f + 1), "F", `doc's F threshold (${f}) + 1 does not grade F in the real scanner`);
});

// The doc's opening line states the catalogue size in words ("Ten
// categories", "Eleven categories", ...). An auditor who trusts that count
// while skimming could miss a real rule the scanner emits but the doc never
// documents, or could flag a documented category the scanner no longer has.
const NUMBER_WORDS = {
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
};

test("skill reference doc's stated category count matches both its own headings and the scanner's rule metadata", () => {
  const doc = readFileSync(docPath, "utf8");

  const headingCount = (doc.match(/^### /gm) ?? []).length;
  assert.equal(
    headingCount,
    RULE_METADATA.length,
    `detection-patterns.md documents ${headingCount} rule(s) but the scanner ` +
      `(lib/sarif.js RULE_METADATA) emits ${RULE_METADATA.length} -- the catalogue ` +
      "is out of sync with what the tool actually detects",
  );

  const m = doc.match(/(\w+) categories,/);
  assert.ok(m, "detection-patterns.md should open with '<N-in-words> categories, ...'");
  const statedWord = m[1].toLowerCase();
  const statedCount = NUMBER_WORDS[statedWord];
  assert.ok(statedCount !== undefined, `unrecognized number word "${m[1]}" in docs-consistency test's NUMBER_WORDS map`);
  assert.equal(
    statedCount,
    headingCount,
    `doc's intro says "${m[1]} categories" (${statedCount}) but lists ${headingCount} "### " headings`,
  );
});
