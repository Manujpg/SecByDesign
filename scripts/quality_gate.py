#!/usr/bin/env python3
"""Quality Gate der CI/CD-Pipeline (Aufgabe 3d, SR-06, SR-12).

Liest alle Scan-Berichte eines Pipeline-Laufs, bewertet sie nach festen Regeln und
beendet sich mit Exit-Code 1, wenn eine Regel verletzt ist. Nur dieses Skript
entscheidet über "bestanden"; die Scanner-Jobs selbst brechen nicht ab, sondern
liefern nur Berichte. So gibt es genau einen Status-Check für den Branch-Schutz.

Regeln (Abbruch bei):
  1. Secret-Scan    : mindestens ein Fund (Gitleaks)
  2. SCA            : Schwachstelle mit Severity HIGH/CRITICAL oder CVSS >= 7.0 (Trivy)
  3. SAST           : Semgrep-Fund mit Severity ERROR, Bandit-Fund mit Severity HIGH
  4. SBOM           : fehlt oder enthält keine Komponenten
  5. Vollständigkeit: ein erwarteter Bericht fehlt, ist leer oder unlesbar
                      (fail-closed: ein Scan, der still nichts prüft, darf nicht "grün" sein)
  6. Pipeline-Jobs  : ein vorgelagerter Job (z. B. Tests) ist nicht erfolgreich

Hinweise ohne Abbruch:
  - pip-audit liefert keine CVSS-Werte; Funde werden als Warnung gezeigt. Maßgeblich für
    die CVSS-Schwelle ist Trivy (begründet in docs/01-architektur.md).
  - Semgrep WARNING/INFO, Bandit MEDIUM/LOW, Trivy MEDIUM/LOW.

Nutzung:
  python scripts/quality_gate.py --reports reports --component backend \\
      --evidence-dir evidence-out --run-label 20261019-123-1
Nur Standardbibliothek, damit das Gate selbst keine Abhängigkeiten hat.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

CVSS_THRESHOLD = 7.0
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}

# Erwartete Berichte -> Unterordner in evidence/<component>/ (Struktur laut Aufgabe 7a.v)
EXPECTED: dict[str, str] = {
    "gitleaks.json": "secrets",
    "semgrep.json": "sast",
    "bandit.json": "sast",
    "trivy-fs.json": "sca",
    "pip-audit.json": "sca",
    "sbom-source.cdx.json": "sbom",
}
# Zusätzliche Dateien, die mitgesichert werden, wenn vorhanden
OPTIONAL: dict[str, str] = {
    "semgrep.sarif": "sast",
    "gitleaks.sarif": "secrets",
    "pytest.xml": "run",
}


@dataclass
class Result:
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, object] = field(default_factory=dict)

    def fail(self, msg: str) -> None:
        self.violations.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def find_reports(root: Path) -> dict[str, Path]:
    """Sucht Berichte rekursiv (Artefakte landen in Unterordnern)."""
    found: dict[str, Path] = {}
    for name in [*EXPECTED, *OPTIONAL]:
        matches = sorted(root.rglob(name))
        if matches:
            found[name] = matches[0]
    return found


def load_json(path: Path | None, name: str, res: Result) -> object | None:
    if path is None:
        res.fail(f"Bericht fehlt: {name}")
        return None
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            res.fail(f"Bericht ist leer: {name}")
            return None
        return json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        res.fail(f"Bericht unlesbar: {name} ({type(exc).__name__})")
        return None


# ---------------------------------------------------------------------------
# Einzelne Prüfungen
# ---------------------------------------------------------------------------


def check_gitleaks(data: object, res: Result) -> None:
    if data is None:
        return
    if not isinstance(data, list):
        res.fail("gitleaks.json hat ein unerwartetes Format")
        return
    res.stats["secrets"] = len(data)
    for leak in data:
        # Gitleaks wird mit --redact ausgeführt; hier nur Regel und Fundort ausgeben.
        res.fail(
            f"Secret gefunden: Regel {leak.get('RuleID')} in {leak.get('File')}:"
            f"{leak.get('StartLine')} (Commit {str(leak.get('Commit', ''))[:8]})"
        )


def _max_cvss(vuln: dict) -> float | None:
    scores = []
    for source in (vuln.get("CVSS") or {}).values():
        for key in ("V3Score", "V40Score", "V2Score"):
            if isinstance(source.get(key), (int, float)):
                scores.append(float(source[key]))
    return max(scores) if scores else None


def check_trivy(data: object, res: Result) -> None:
    if data is None:
        return
    if not isinstance(data, dict):
        res.fail("trivy-fs.json hat ein unerwartetes Format")
        return
    results = data.get("Results") or []
    packages = sum(len(r.get("Packages") or []) for r in results)
    res.stats["sca_packages"] = packages
    if packages == 0:
        # Ohne --list-all-pkgs oder bei nicht erkannten Lockfiles prüft Trivy gar nichts.
        res.fail("SCA hat keine Pakete erkannt (Lockfile nicht erkannt? --list-all-pkgs fehlt?)")
    counts: dict[str, int] = {}
    for r in results:
        for v in r.get("Vulnerabilities") or []:
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            counts[sev] = counts.get(sev, 0) + 1
            cvss = _max_cvss(v)
            if sev in BLOCKING_SEVERITIES or (cvss is not None and cvss >= CVSS_THRESHOLD):
                score = f", CVSS {cvss:.1f}" if cvss is not None else ""
                res.fail(
                    f"Schwachstelle {v.get('VulnerabilityID')} ({sev}{score}) in "
                    f"{v.get('PkgName')} {v.get('InstalledVersion')} "
                    f"-> Fix: {v.get('FixedVersion') or 'keiner verfügbar'} [{r.get('Target')}]"
                )
    res.stats["sca_vulnerabilities"] = counts


def check_pip_audit(data: object, res: Result) -> None:
    if data is None:
        return
    deps = data.get("dependencies", []) if isinstance(data, dict) else []
    if not deps:
        res.fail("pip-audit.json enthält keine Abhängigkeiten")
        return
    vulns = [(d.get("name"), v) for d in deps for v in d.get("vulns") or []]
    res.stats["pip_audit_vulnerabilities"] = len(vulns)
    for name, v in vulns:
        aliases = ", ".join(v.get("aliases") or [])
        res.warn(f"pip-audit: {v.get('id')} ({aliases}) in {name}; Fix: {v.get('fix_versions')}")


def check_semgrep(data: object, res: Result) -> None:
    if data is None:
        return
    if not isinstance(data, dict) or "results" not in data:
        res.fail("semgrep.json hat ein unerwartetes Format")
        return
    scanned = len((data.get("paths") or {}).get("scanned") or [])
    res.stats["semgrep_files"] = scanned
    if scanned == 0:
        res.fail("Semgrep hat keine Dateien gescannt")
    counts: dict[str, int] = {}
    for f in data["results"]:
        sev = f.get("extra", {}).get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        line = f.get("start", {}).get("line")
        msg = f"Semgrep {sev}: {f.get('check_id')} in {f.get('path')}:{line}"
        if sev == "ERROR":
            res.fail(msg)
        else:
            res.warn(msg)
    for err in data.get("errors") or []:
        res.warn(f"Semgrep konnte nicht alles parsen: {err.get('type')} {err.get('path', '')}")
    res.stats["semgrep_findings"] = counts


def check_bandit(data: object, res: Result) -> None:
    if data is None:
        return
    if not isinstance(data, dict) or "results" not in data:
        res.fail("bandit.json hat ein unerwartetes Format")
        return
    counts: dict[str, int] = {}
    for f in data["results"]:
        sev = f.get("issue_severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
        msg = (
            f"Bandit {sev}/{f.get('issue_confidence')}: {f.get('test_id')} "
            f"{f.get('test_name')} in {f.get('filename')}:{f.get('line_number')}"
        )
        if sev == "HIGH":
            res.fail(msg)
        else:
            res.warn(msg)
    res.stats["bandit_findings"] = counts


def check_sbom(data: object, res: Result) -> None:
    if data is None:
        return
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        res.fail("SBOM ist kein CycloneDX-Dokument")
        return
    components = data.get("components") or []
    # Nur echte Abhängigkeiten zählen (Package-URL), nicht das Projekt selbst oder Dateien.
    root = ((data.get("metadata") or {}).get("component") or {}).get("name")
    dependencies = [
        c for c in components if str(c.get("purl", "")).startswith("pkg:") and c.get("name") != root
    ]
    res.stats["sbom_components"] = len(components)
    res.stats["sbom_dependencies"] = len(dependencies)
    res.stats["sbom_spec"] = data.get("specVersion")
    if not dependencies:
        res.fail("SBOM enthält keine Abhängigkeiten (Lockfile nicht erkannt?)")


def check_jobs(needs_json: str | None, res: Result) -> None:
    """Prüft das Ergebnis der vorgelagerten Jobs (toJSON(needs) aus GitHub Actions)."""
    if not needs_json:
        return
    try:
        needs = json.loads(needs_json)
    except json.JSONDecodeError:
        res.fail("NEEDS_JSON ist kein gültiges JSON")
        return
    res.stats["jobs"] = {name: info.get("result") for name, info in needs.items()}
    for name, info in needs.items():
        if info.get("result") != "success":
            res.fail(f"Pipeline-Job '{name}' ist nicht erfolgreich ({info.get('result')})")


# ---------------------------------------------------------------------------
# Ausgabe
# ---------------------------------------------------------------------------


def to_markdown(component: str, res: Result) -> str:
    ok = not res.violations
    lines = [
        f"## Quality Gate {component}: {'BESTANDEN' if ok else 'NICHT BESTANDEN'}",
        "",
        "| Kennzahl | Wert |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in res.stats.items()]
    if res.violations:
        lines += ["", f"### Abbruchgründe ({len(res.violations)})", ""]
        lines += [f"- {v}" for v in res.violations]
    if res.warnings:
        lines += ["", f"### Hinweise ohne Abbruch ({len(res.warnings)})", ""]
        lines += [f"- {w}" for w in res.warnings[:50]]
        if len(res.warnings) > 50:
            lines.append(f"- ... und {len(res.warnings) - 50} weitere")
    return "\n".join(lines) + "\n"


def write_evidence(
    reports: dict[str, Path], out: Path, component: str, label: str, res: Result, md: str
) -> None:
    base = out / component
    for sub in ("run", "sast", "sbom", "sca", "secrets"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    for name, path in reports.items():
        sub = EXPECTED.get(name) or OPTIONAL[name]
        shutil.copy2(path, base / sub / f"{label}-{name}")
    gate = {
        "component": component,
        "run": label,
        "passed": not res.violations,
        "violations": res.violations,
        "warnings": res.warnings,
        "stats": res.stats,
        "rules": {
            "secrets": "Abbruch bei jedem Fund",
            "sca": f"Abbruch bei HIGH/CRITICAL oder CVSS >= {CVSS_THRESHOLD}",
            "sast": "Abbruch bei Semgrep ERROR oder Bandit HIGH",
            "sbom": "Abbruch, wenn SBOM fehlt oder leer ist",
            "completeness": "Abbruch, wenn ein Bericht fehlt, leer oder unlesbar ist",
        },
    }
    (base / "run" / f"{label}-quality-gate.json").write_text(
        json.dumps(gate, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (base / "run" / f"{label}-quality-gate.md").write_text(md, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reports", required=True, type=Path, help="Ordner mit allen Berichten")
    ap.add_argument("--component", default="backend")
    ap.add_argument("--evidence-dir", type=Path, help="Zielordner für die Evidence-Struktur")
    ap.add_argument("--run-label", default="local")
    args = ap.parse_args()

    res = Result()
    reports = find_reports(args.reports)

    check_gitleaks(load_json(reports.get("gitleaks.json"), "gitleaks.json", res), res)
    check_trivy(load_json(reports.get("trivy-fs.json"), "trivy-fs.json", res), res)
    check_pip_audit(load_json(reports.get("pip-audit.json"), "pip-audit.json", res), res)
    check_semgrep(load_json(reports.get("semgrep.json"), "semgrep.json", res), res)
    check_bandit(load_json(reports.get("bandit.json"), "bandit.json", res), res)
    check_sbom(load_json(reports.get("sbom-source.cdx.json"), "sbom-source.cdx.json", res), res)
    check_jobs(os.environ.get("NEEDS_JSON"), res)

    md = to_markdown(args.component, res)
    print(md)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    if args.evidence_dir:
        write_evidence(reports, args.evidence_dir, args.component, args.run_label, res, md)
    return 1 if res.violations else 0


if __name__ == "__main__":
    sys.exit(main())
