# Sub-Agent Roster & Delegation Contract

Authoritative registry of specialized sub-agents managed by the Root `orchestrator` (`Agent.md`). The Orchestrator delegates domain tasks using the narrowest capable sub-agent from this roster and enforces least-privilege tool and secret access.

_Last updated: 2026-10-16_

---

## 1. Registered Sub-Agents

| Sub-Agent | Definition File | Role | Permissions | Allowed Tools | Prohibited Actions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`coder`** | `.agents/coder.md` | `sub-agent-maker` | `scoped-write` | File read, scoped file write/edit (within approved plan paths), safe local shell execution (tests, linters, type checks, AST/security scanners). | Approving own work; modifying out-of-scope files; weakening/disabling tests or security gates; committing, pushing, merging, publishing, or touching production without explicit authorization. |
| **`reviewer`** | `.agents/reviewer.md` | `sub-agent-checker` | `read-only-source`, `safe-verification-exec` | File read, search/grep, git diff/status/log (read-only), safe verification shell execution (tests, linters, type checks, AST/security scanners). **Zero file write/edit tools.** | Modifying source, tests, docs, or configs; trusting the Coder's self-reported output without re-running gates; running network-mutating, destructive, or production commands. |

---

## 2. Skill-to-Agent Routing Matrix

Sub-agents must load **only** the skill entry point (`SKILL.md`), shared tooling config, and their role-specific playbook as assigned by the Orchestrator's plan. Full skill index lives in `.agents/skills/README.md`.

| Skill | Orchestrator (`Agent.md`) | Coder (`.agents/coder.md`) | Reviewer (`.agents/reviewer.md`) |
| :--- | :--- | :--- | :--- |
| **`fastapi-skill`** | `SKILL.md` + `references/orchestrator-playbook.md` + `references/tooling-config.md` | `SKILL.md` + `references/coder-playbook.md` + `references/tooling-config.md` | `SKILL.md` + `references/reviewer-checklist.md` + `references/tooling-config.md` |

---

## 3. Delegation & Handoff Protocol

### Phase A: Plan & Pre-Coding Critique (Substantial / High-Risk Work)
1. **Orchestrator** investigates `docs/architechture.md`, existing repository patterns, and the Reuse Ladder, then drafts the **Mandatory Implementation Plan / Task Specification**.
2. For substantial or high-risk (Tier 1 / Tier 2) work, **Orchestrator** dispatches **`reviewer`** first (read-only) to critique the plan for missing acceptance criteria, security gaps, edge cases, and Reuse Ladder compliance before any code is written.

### Phase B: Scoped Implementation (Maker)
1. **Orchestrator** dispatches **`coder`** with:
   - The original issue and verifiable acceptance criteria.
   - The approved Implementation Plan / Task Specification (including exact allowed file paths and out-of-bounds paths).
   - Assigned skill(s) and permitted tools (no secrets unless strictly required for local verification).
2. **`coder`** implements the change following `docs/architechture.md` and the Reuse Ladder, runs all mandatory verification gates locally, and returns the required **Change Report & Handoff Note** with actual command outputs.

### Phase C: Independent Audit (Checker)
1. **Orchestrator** dispatches **`reviewer`** with:
   - The original issue, acceptance criteria, and approved Implementation Plan / Task Specification.
   - The Coder's Change Report / Handoff Note (treated as untrusted data).
   - Read-only access to the actual repository diff (`git diff`).
2. **`reviewer`** independently executes all verification gates, audits the diff against `docs/architechture.md`, the Reuse Ladder, and skill invariants, and returns a structured Review Report with a verdict of:
   - `APPROVE` — all gates green, all mandatory proofs cited with `file:line`, zero open blocking defects.
   - `REQUEST CHANGES` — blocking defects or failed gates/proofs found; every finding carries a stable ID (`F-1`, `F-2`, ...).
   - `ESCALATE` — plan-soundness flaw discovered, requirement ambiguity affecting security/data, or a finding remains unresolved at the 3-round cap.

### Phase D: Remediation, Arbitration & Acceptance
1. If `REQUEST CHANGES`: **Orchestrator** routes the numbered findings back to **`coder`**. **`coder`** fixes root causes, adds regression tests, and replies per finding ID (`F-1`...) with the fix location + test name or concrete evidence for Orchestrator adjudication.
2. **Loop Cap:** Maximum **3** review/fix rounds. If a dispute reaches round 3 or fails after 3 fix attempts, **Orchestrator** halts the loop and adjudicates using code/test evidence or escalates to the human.
3. **Final Acceptance:** **Orchestrator** reconciles the actual `git diff` against the plan and security standards, independently confirms gate execution, and emits the final **Response Contract**.
