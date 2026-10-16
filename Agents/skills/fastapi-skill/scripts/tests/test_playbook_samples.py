"""Keeps coder-playbook.md honest: its reference code must pass the scanner."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_fastapi as audit  # noqa: E402

PLAYBOOK = Path(__file__).resolve().parents[2] / "references" / "coder-playbook.md"
SAMPLE_RE = re.compile(r"<!-- sample: (\S+) -->\n```python\n(.*?)```", re.S)


def test_playbook_samples_exist_and_pass(tmp_path):
    samples = SAMPLE_RE.findall(PLAYBOOK.read_text(encoding="utf-8"))
    assert len(samples) >= 10, "playbook sample markers missing"
    for rel, code in samples:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
    assert audit.main([str(tmp_path), "--root", str(tmp_path)]) == 0


def test_scanner_catches_mutations_of_the_samples(tmp_path):
    """If the scanner went blind, the previous test would pass vacuously. Break the samples on purpose."""
    samples = dict(SAMPLE_RE.findall(PLAYBOOK.read_text(encoding="utf-8")))
    mutations = {
        "src/open_enterprise_ai/domains/orders/api/routes.py": ("principal: EditorPrincipal, ", "", "AUTH001"),
        "src/open_enterprise_ai/infrastructure/repositories/postgres_order_repository.py": ("await self._session.flush()", "await self._session.commit()", "ARCH003"),
        "src/open_enterprise_ai/domains/orders/services/order_service.py": ("from uuid import UUID", "from fastapi import HTTPException\nfrom uuid import UUID", "ARCH001"),
        "src/open_enterprise_ai/domains/orders/api/schemas.py": ('model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)',
                                  "pass", "PYD001"),
    }
    for rel, (old, new, rule) in mutations.items():
        assert old in samples[rel], f"mutation anchor missing in {rel}"
        root = tmp_path / rule
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(samples[rel].replace(old, new, 1), encoding="utf-8")
        found = {v.rule_id for v in audit.audit_source(target.read_text(), target, root)}
        assert rule in found, f"{rule} not detected after mutating {rel}"
