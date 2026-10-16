# Skill Roster & Rules

Single index of the skills available to agents in this repository. An agent (or a human) should be able to answer "which skill applies, who loads it, and how is it verified?" from this file alone.

_Last updated: 2026-10-16_

## Global Skill Rules

1. **Architecture Precedence:** `docs/architechture.md` is always the source of truth for repository layout and module placement. Python source code strictly resides under `src/open_enterprise_ai/`. Follow `docs/architechture.md` while enforcing the skill's architectural layer and security invariants.
2. **Role Isolation:** Each agent loads only `SKILL.md`, shared tooling config, and its own role playbook (`orchestrator`, `coder`, or `reviewer`) to prevent context dilution and role bleed.
3. **Reuse Ladder First:** Every skill implementation must stop at the earliest applicable rung of the Reuse & Simplicity Ladder: (1) YAGNI; (2) existing codebase helper; (3) standard library; (4) native platform/database feature; (5) installed dependency; (6) popular, maintained premade library; (7) minimum custom code.

## Registered Skills

| Skill | Path | Version | Status | Domain | Used by roles | Entry point |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `fastapi-skill` | `.agents/skills/fastapi-skill/` | 2.1.0 | Active | Backend / Python / FastAPI design, implementation, review, hardening | Orchestrator, Coder, Reviewer | `.agents/skills/fastapi-skill/SKILL.md` |

---

## `fastapi-skill`

**Purpose:** Production-grade, security-hardened FastAPI development via a 3-agent maker/checker workflow, with a deterministic AST audit as the first gate.

**Use when:** creating or changing FastAPI routes, services, ports/repositories/adapters, Pydantic v2 schemas, auth (JWT/roles), async/DB code, outbound HTTP, file uploads, webhooks, app bootstrap (lifespan, CORS, error handling), migrations, or reviewing any of these.

**Do not use for:** non-Python services, Django/Flask apps, pure data-science notebooks, or frontend work.

**Contents**

| File | Loaded by | Purpose |
| :--- | :--- | :--- |
| `SKILL.md` | all roles | 15 global invariants, role routing, handoff protocol, loop limits, suppression policy, audit rule index |
| `references/orchestrator-playbook.md` | Orchestrator only | Discovery (`docs/architechture.md`), risk tiers, Implementation Plan & Task Specification template, pre-coding plan review, dispute protocol, sign-off gate, Response Contract |
| `references/coder-playbook.md` | Coder only | Layered reference implementation (audited), bootstrap, security primitives, DB/migration rules, test matrix, Change Report & Handoff Note |
| `references/reviewer-checklist.md` | Reviewer only | Pre-coding plan review, gate execution, scope/ladder audit, 10 mandatory proof citations, adversarial probes, verdict rules, Review Report template |
| `references/tooling-config.md` | all roles | ruff/mypy/bandit/pytest config, CI job, container baseline, `.env.example` conventions |
| `scripts/audit_fastapi.py` | Coder, Reviewer, Orchestrator | Deterministic AST scanner (`--list-rules`, `--format json`) |
| `scripts/tests/` | CI / anyone editing the scanner | 54+ tests: rule behavior, CLI exit codes, and playbook-sample sync |

**Agent wiring**

| Agent | Loads | Recommended tool access |
| :--- | :--- | :--- |
| Orchestrator | `SKILL.md` + `orchestrator-playbook.md` | Read/search, task tracking, sub-agent dispatch. Delegates specialized domain implementation to `coder` per `Agent.md`. |
| Coder | `SKILL.md` + `coder-playbook.md` | Read, scoped edit/write, safe local shell (to run verification gates). |
| Reviewer | `SKILL.md` + `reviewer-checklist.md` | Read, search, safe shell for verification gates only. **No edit/write tools**, enforcing read-only checking by tooling. |

**Verification commands**

```bash
python .agents/skills/fastapi-skill/scripts/audit_fastapi.py <paths>     # exit 0 pass, 1 violations, 2 bad path/empty scan
python .agents/skills/fastapi-skill/scripts/audit_fastapi.py --list-rules
pytest .agents/skills/fastapi-skill/scripts/tests -q                      # must stay green when the scanner or playbook changes

```

**Maintenance rules**

1. Changing a rule in `audit_fastapi.py` requires updating its tests and the rule index in `SKILL.md` in the same change.
2. Changing sample code in `coder-playbook.md` (blocks marked `<!-- sample: ... -->`) is validated automatically by `test_playbook_samples.py`.
3. Bump `version` in `SKILL.md` and this roster, and add a `.agents/skills/fastapi-skill/CHANGELOG.md` entry, for any behavior change.
4. Never add global rule disables; use justified inline suppressions approved by the Orchestrator.

**Owner:** *(fill in team/person)*  **Review cadence:** quarterly, or on a FastAPI/Pydantic/SQLAlchemy major release.

---

## Adding a new skill

1. Create `.agents/skills/<name>/SKILL.md` with `name`, `description` (include a "Use when ..." trigger sentence) and `version` front matter.
2. Keep role-specific guidance in `references/` and load-by-role routing in `SKILL.md`.
3. Add deterministic checks under `scripts/` with tests where a rule can be automated.
4. Register it in the table above with status `Draft` until reviewed, then `Active`.
