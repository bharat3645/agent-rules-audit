# The file nobody code-reviews

Every coding agent you run today reads at least one plain-text file before it
does anything else — `AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
`.windsurfrules`, a `skills/` folder, an MCP server config. The agent treats
that file's contents as close to system-prompt authority: instructions in it
shape every tool call it makes for the rest of the session. The human on the
other end of the terminal treats the same file as "just docs" — something you
skim once, if you open it at all, the way you'd skim a `CONTRIBUTING.md`.

That gap — near-system-prompt trust on one side, casual-skim scrutiny on the
other — is not a hypothetical. It is the specific mechanism a wave of 2026
supply-chain campaigns have been built around, and it is worth being precise
about what "poisoning an instruction file" actually looks like, because the
attack does not require compromising a registry or signing a bad package. It
only requires getting one text file into a repo a developer is about to point
an agent at.

## What the attack actually does

The shape reported across multiple 2026 write-ups is consistent: a
`.cursorrules` or `CLAUDE.md` shipped inside a dependency, template, or
"helpful" fork contains an instruction block asking the agent to read local
secrets (`~/.ssh/id_rsa`, `.env`, `.aws/credentials`) and send them to an
external endpoint — often framed innocuously, as a "sync step" or a
"telemetry check" — with an explicit instruction to suppress the output and
not mention it to the user. Because the agent is following what looks like a
legitimate project instruction, and because the exfiltration step is one line
in a much longer, plausible-looking file, nothing about the session looks
unusual from the human's side.

The technique for hiding the instruction from a human reviewer who *does*
open the file is just as mundane: zero-width Unicode characters, bidirectional
overrides, or Unicode tag-block smuggling — none of which render visibly in a
terminal, editor, or GitHub's file viewer, all of which are still bytes the
agent reads and follows. A file can look byte-for-byte identical to a clean
one in every rendering path a human would use to check it, while containing a
completely different set of instructions in the bytes themselves.

## This is not a fringe concern

Trade coverage in 2026 has treated this as a named, tracked category rather
than a one-off finding:

- CSO Online reported on attackers "crafting malicious AI instruction files"
  specifically to turn agentic coding workflows into exfiltration channels
  ([CSO Online](https://www.csoonline.com/article/4204731/attackers-are-crafting-malicious-ai-instruction-files-to-turn-your-agentic-workflows-into-quiet-criminal-helpers.html)).
- Security research aggregated by Phoenix Security counted 37 malicious-package
  supply-chain campaigns in H1 2026 — 2.6x the prior year's full-year campaign
  count — with AI-coding-agent-specific vectors (`.cursorrules` poisoning,
  `CLAUDE.md` hidden instructions, MCP server injection, agent hook abuse)
  confirmed across at least 14 of 59 tracked campaigns
  ([Phoenix Security](https://phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026/)).
- The Cloud Security Alliance's research note on the underlying trust model
  put the mechanism plainly: these files are loaded at session start and
  treated with a level of trust approximating system-prompt authority, so
  whoever can edit the file effectively controls the agent's behavioral
  policy for every subsequent interaction in that repo
  ([Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/)).
- Mitiga documented a concrete incident walkthrough of a poisoned coding
  exercise turning an agent against its own operator
  ([Mitiga](https://www.mitiga.io/blog/poisoned-coding-test-ai-agent-attack)).

*(Caveat, stated plainly rather than glossed over: these figures and
descriptions come from the outlets above, reached via search rather than a
direct fetch of each primary source — this session's network policy blocked
outbound access to all four of those domains directly. They are attributed to
the reporting outlet, not independently re-derived from a raw dataset. Treat
the specific counts as "as reported by," not as a re-verified figure.)*

## Why this doesn't get caught by the tools already in place

Secret scanners look at what's committed, not at what an agent is being told
to *do* with a secret it can already read. Dependency scanners look at code
that executes, not at prose an LLM interprets. Neither category was built to
answer "does this plain-text file contain an instruction, hidden or plain,
that changes what my agent will do?" — because until agents started reading
these files as behavioral policy, that wasn't a question worth asking. The
file format that made this attack possible (a repo-local, agent-read,
human-skimmed instructions file) is barely a year old in most of these tools'
threat models.

## The asymmetry is the whole problem

None of this requires a sophisticated payload. It requires exploiting the gap
between how much authority the file has with the agent and how much scrutiny
it gets from the human. Every other category of software supply-chain risk
this decade — typosquats, dependency confusion, malicious postinstall
scripts — has eventually been met with a scanner built for that exact
asymmetry. Instruction-file poisoning is the same category of problem,
one file format later, and it is still mostly being handled by "read it
carefully," which is precisely the control that hidden Unicode is designed to
defeat.

---

*This is the problem behind
[`agent-rules-audit`](https://github.com/bharat3645/agent-rules-audit), a
zero-dependency scanner (and coding-agent skill) for exactly this file class —
built because "read it carefully" isn't a control, it's a hope.*
