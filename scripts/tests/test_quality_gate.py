"""Tests für scripts/quality_gate.py: das Gate muss in jedem Fehlerfall abbrechen."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "quality_gate.py"


def _write(d: Path, name: str, data: object) -> None:
    (d / name).write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def clean_reports(tmp_path: Path) -> Path:
    """Ein vollständiger, sauberer Satz Berichte (Gate muss bestehen)."""
    _write(tmp_path, "gitleaks.json", [])
    _write(
        tmp_path,
        "trivy-fs.json",
        {"Results": [{"Target": "requirements.txt", "Packages": [{"Name": "fastapi"}]}]},
    )
    _write(tmp_path, "pip-audit.json", {"dependencies": [{"name": "fastapi", "vulns": []}]})
    _write(tmp_path, "semgrep.json", {"results": [], "errors": [], "paths": {"scanned": ["a.py"]}})
    _write(tmp_path, "bandit.json", {"results": []})
    _write(
        tmp_path,
        "sbom-source.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"name": "praxis-backend"}},
            "components": [{"name": "fastapi", "purl": "pkg:pypi/fastapi@0.146.0"}],
        },
    )
    return tmp_path


def run_gate(reports: Path, tmp_path: Path, env: dict | None = None):
    evidence = tmp_path / "evidence"
    proc = subprocess.run(  # nosec B603 - fester Aufruf des eigenen Skripts
        [
            sys.executable,
            str(SCRIPT),
            "--reports",
            str(reports),
            "--evidence-dir",
            str(evidence),
            "--run-label",
            "test-1",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**(env or {}), "PYTHONIOENCODING": "utf-8", "SYSTEMROOT": "C:\\Windows"},
        check=False,
    )
    return proc, evidence


def test_clean_reports_pass(clean_reports: Path, tmp_path: Path) -> None:
    proc, evidence = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 0, proc.stdout
    assert "BESTANDEN" in proc.stdout
    gate = json.loads(
        (evidence / "backend" / "run" / "test-1-quality-gate.json").read_text(encoding="utf-8")
    )
    assert gate["passed"] is True
    for sub, name in [
        ("secrets", "gitleaks.json"),
        ("sca", "trivy-fs.json"),
        ("sast", "semgrep.json"),
        ("sbom", "sbom-source.cdx.json"),
    ]:
        assert (evidence / "backend" / sub / f"test-1-{name}").exists()


def test_secret_finding_fails(clean_reports: Path, tmp_path: Path) -> None:
    _write(
        clean_reports,
        "gitleaks.json",
        [{"RuleID": "generic-api-key", "File": "x.py", "StartLine": 3, "Commit": "abc"}],
    )
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1
    assert "Secret gefunden" in proc.stdout


@pytest.mark.parametrize(
    ("severity", "cvss", "blocks"),
    [
        ("HIGH", None, True),
        ("CRITICAL", None, True),
        ("MEDIUM", 7.5, True),  # Severity niedrig eingestuft, CVSS aber über der Schwelle
        ("MEDIUM", 6.9, False),
        ("LOW", None, False),
    ],
)
def test_sca_threshold(clean_reports: Path, tmp_path: Path, severity, cvss, blocks) -> None:
    vuln = {
        "VulnerabilityID": "CVE-2026-0001",
        "PkgName": "demo",
        "InstalledVersion": "1.0",
        "Severity": severity,
    }
    if cvss is not None:
        vuln["CVSS"] = {"nvd": {"V3Score": cvss}}
    _write(
        clean_reports,
        "trivy-fs.json",
        {"Results": [{"Target": "r.lock", "Packages": [{}], "Vulnerabilities": [vuln]}]},
    )
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == (1 if blocks else 0), proc.stdout


def test_sca_without_packages_fails(clean_reports: Path, tmp_path: Path) -> None:
    # Trivy erkennt das Lockfile nicht -> 0 Pakete -> darf nicht als "sauber" gelten
    _write(clean_reports, "trivy-fs.json", {"Results": []})
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1
    assert "keine Pakete" in proc.stdout


@pytest.mark.parametrize(
    "name",
    [
        "gitleaks.json",
        "trivy-fs.json",
        "pip-audit.json",
        "semgrep.json",
        "bandit.json",
        "sbom-source.cdx.json",
    ],
)
def test_missing_report_fails(clean_reports: Path, tmp_path: Path, name: str) -> None:
    (clean_reports / name).unlink()
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1
    assert f"Bericht fehlt: {name}" in proc.stdout


def test_empty_or_broken_report_fails(clean_reports: Path, tmp_path: Path) -> None:
    (clean_reports / "semgrep.json").write_text("", encoding="utf-8")
    (clean_reports / "bandit.json").write_text("{kaputt", encoding="utf-8")
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1
    assert "leer" in proc.stdout
    assert "unlesbar" in proc.stdout


def test_sast_rules(clean_reports: Path, tmp_path: Path) -> None:
    _write(
        clean_reports,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "x.warn",
                    "path": "a.py",
                    "start": {"line": 1},
                    "extra": {"severity": "WARNING"},
                },
            ],
            "paths": {"scanned": ["a.py"]},
        },
    )
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 0  # WARNING nur als Hinweis
    _write(
        clean_reports,
        "bandit.json",
        {
            "results": [
                {
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "filename": "a.py",
                    "line_number": 5,
                }
            ]
        },
    )
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1


@pytest.mark.parametrize(
    "components",
    [
        [],
        # Nur das Projekt selbst und Dateien, aber keine Abhängigkeiten (Lockfile nicht erkannt)
        [
            {"name": "praxis-backend", "purl": "pkg:pypi/praxis-backend@0.1.0"},
            {"name": "/src/backend/pyproject.toml", "type": "file"},
        ],
    ],
)
def test_sbom_without_dependencies_fails(clean_reports: Path, tmp_path: Path, components) -> None:
    _write(
        clean_reports,
        "sbom-source.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"name": "praxis-backend"}},
            "components": components,
        },
    )
    proc, _ = run_gate(clean_reports, tmp_path)
    assert proc.returncode == 1
    assert "keine Abhängigkeiten" in proc.stdout


def test_failed_upstream_job_fails(clean_reports: Path, tmp_path: Path) -> None:
    needs = json.dumps({"test": {"result": "failure"}, "sast": {"result": "success"}})
    proc, _ = run_gate(clean_reports, tmp_path, env={"NEEDS_JSON": needs})
    assert proc.returncode == 1
    assert "'test'" in proc.stdout
