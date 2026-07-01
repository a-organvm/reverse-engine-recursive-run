"""Focused coverage for the command-line dispatcher in scripts/__main__.py."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "scripts" / "__main__.py"
    spec = importlib.util.spec_from_file_location("reverse_engine_cli_under_test", cli_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data))
    return path


def test_analyze_command_writes_ranked_top_hotspots(tmp_path, monkeypatch):
    cli = load_cli_module()
    for key, value in {
        "RISK_W_CHURN": "0.4",
        "RISK_W_COMPLEXITY": "0.4",
        "RISK_W_COVERAGE": "0.1",
        "RISK_W_CRITICALITY": "0.1",
    }.items():
        monkeypatch.setenv(key, value)

    churn = tmp_path / "churn.txt"
    churn.write_text("10 src/high.py\n1 src/low.py\n")
    complexity = write_json(
        tmp_path / "complexity.json",
        {
            "src/high.py": [{"complexity": 5}],
            "src/low.py": [{"complexity": 1}],
        },
    )
    coverage = write_json(
        tmp_path / "coverage.json",
        {"files": {"src/high.py": 0.0, "src/low.py": 1.0}},
    )
    out = tmp_path / "hotspots.json"

    rc = cli.main(
        [
            "analyze",
            "--churn",
            str(churn),
            "--complexity",
            str(complexity),
            "--coverage",
            str(coverage),
            "--out",
            str(out),
            "--top",
            "1",
        ]
    )

    assert rc == 0
    result = json.loads(out.read_text())
    assert result == {"hotspots": [{"file": "src/high.py", "risk_score": 1.0}]}


def test_risk_command_consolidates_hotspots_and_security_findings(tmp_path):
    cli = load_cli_module()
    hotspots = write_json(
        tmp_path / "hotspots.json",
        {"hotspots": [{"file": "src/auth.py", "risk_score": 0.8}]},
    )
    security = write_json(
        tmp_path / "security.json",
        [{"id": "SEC-42", "severity": "LOW"}],
    )
    out = tmp_path / "risk.json"

    rc = cli.main(
        [
            "risk",
            "--hotspots",
            str(hotspots),
            "--security",
            str(security),
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    result = json.loads(out.read_text())
    assert result["derived_risks"] == [
        {"id": "RISK-HOTSPOT-src/auth.py", "severity": "HIGH"},
        {"id": "SEC-42", "severity": "LOW"},
    ]
    assert result["timestamp"].endswith("Z")


def test_drift_command_returns_nonzero_when_churn_breaches_threshold(tmp_path):
    cli = load_cli_module()
    previous = write_json(
        tmp_path / "previous.json",
        {"edges": [{"from": "A", "to": "B", "type": "import"}]},
    )
    current = write_json(
        tmp_path / "current.json",
        {
            "edges": [
                {"from": "A", "to": "B", "type": "import"},
                {"from": "A", "to": "C", "type": "import"},
            ]
        },
    )

    rc = cli.main(
        [
            "drift",
            "--current",
            str(current),
            "--previous",
            str(previous),
            "--threshold",
            "0.5",
        ]
    )

    assert rc == 2


def test_drift_command_returns_zero_when_churn_is_below_threshold(tmp_path):
    cli = load_cli_module()
    graph = {"edges": [{"from": "A", "to": "B", "type": "import"}]}
    previous = write_json(tmp_path / "previous.json", graph)
    current = write_json(tmp_path / "current.json", graph)

    rc = cli.main(
        [
            "drift",
            "--current",
            str(current),
            "--previous",
            str(previous),
            "--threshold",
            "0.1",
        ]
    )

    assert rc == 0


def test_sbom_and_missing_command_return_documented_exit_codes(capsys):
    cli = load_cli_module()

    assert cli.main(["sbom"]) == 0
    assert "gen_sbom.sh" in capsys.readouterr().out

    assert cli.main([]) == 2
    assert "Security analysis toolkit" in capsys.readouterr().out
