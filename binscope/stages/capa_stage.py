"""Stage: capability identification with capa (Mandiant/FLARE).

capa maps code patterns to ATT&CK techniques and Malware Behavior Catalog
entries — the clearest signal for "what can this binary do?" We run it with
JSON output and lift each matched rule to a finding, tagged by ATT&CK.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..report import Finding, Severity, StageResult, StageStatus
from ..util import run
from .base import Stage, StageContext

# Namespaces whose matches we treat as higher severity.
_HIGH_NS = ("injection", "persistence", "anti-analysis", "command-and-control",
            "credential-access", "impact", "lateral-movement")
_MED_NS = ("communication", "host-interaction", "data-manipulation", "collection",
           "discovery", "defense-evasion")


class CapaStage(Stage):
    name = "capa"
    tool = "capa"
    required_tool = "capa"

    def run(self, ctx: StageContext) -> StageResult:
        res = StageResult(name=self.name, tool=self.tool, status=StageStatus.OK)
        capa = ctx.tools["capa"].path or "capa"
        sdir = ctx.stage_dir(self.name)

        rr = run([capa, "-j", str(ctx.target)], timeout=ctx.config.per_tool_timeout)
        out_path = sdir / "capa.json"
        out_path.write_text(rr.stdout or rr.stderr, encoding="utf-8")
        res.artifacts.append(str(out_path))

        if not rr.stdout.strip():
            res.status = StageStatus.FAILED
            res.summary = f"capa produced no JSON (rc={rr.returncode}): {rr.stderr[:200]}"
            return res
        try:
            data = json.loads(rr.stdout)
        except json.JSONDecodeError:
            res.status = StageStatus.FAILED
            res.summary = "capa output was not valid JSON (version mismatch?)"
            return res

        rules = data.get("rules", {})
        attack_seen: set[str] = set()
        for rule_name, rule in rules.items():
            meta = rule.get("meta", {})
            ns = meta.get("namespace", "") or ""
            sev = Severity.INFO
            if any(k in ns for k in _HIGH_NS):
                sev = Severity.HIGH
            elif any(k in ns for k in _MED_NS):
                sev = Severity.MEDIUM

            attack = meta.get("attack", []) or meta.get("att&ck", [])
            attack_ids = []
            for a in attack:
                if isinstance(a, dict):
                    tid = a.get("id") or a.get("technique", "")
                    attack_ids.append(str(tid))
                    attack_seen.add(str(tid))
                else:
                    attack_ids.append(str(a))
            mbc = meta.get("mbc", [])
            tags = ["capa"]
            if ns:
                tags.append(ns)

            detail_bits = []
            if ns:
                detail_bits.append(f"namespace: {ns}")
            if attack_ids:
                detail_bits.append("ATT&CK: " + ", ".join(attack_ids))
            if mbc:
                detail_bits.append(f"MBC: {len(mbc)} entries")

            res.add(Finding(
                title=f"Capability: {meta.get('name', rule_name)}",
                detail="; ".join(detail_bits),
                severity=sev, tags=tags, knowledge="read"))

        res.summary = (f"{len(rules)} capabilities matched; "
                       f"{len(attack_seen)} distinct ATT&CK techniques")
        if not rules:
            res.status = StageStatus.EMPTY
            res.summary = "capa matched no capability rules"
        return res
