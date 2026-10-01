import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { grade } from "../lib/rules.js";

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
