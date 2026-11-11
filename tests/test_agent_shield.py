"""End-to-end tests over the bundled fixtures plus lock/diff round-trips."""
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_shield import lockfile, sbom  # noqa: E402
from agent_shield.cli import main  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(scope="module")
def report():
    return sbom.scan(FIXTURES)


def _artifact(report, name):
    for art in report["artifacts"]:
        if art["name"] == name:
            return art
    raise AssertionError("artifact %r not in report" % name)


def _severities(art):
    return [f["severity"] for f in art["findings"]]


def test_all_fixtures_discovered(report):
    names = {a["name"] for a in report["artifacts"]}
    assert names == {"benign-note-taker", "benign-web-summary",
                     "cloud-backup-helper", "friendly-formatter",
                     "bad-mcp", "good-mcp"}


def test_adversarial_exfil_caught(report):
    art = _artifact(report, "cloud-backup-helper")
    rules = {f["rule_id"] for f in art["findings"]}
    assert "critical" in _severities(art)
    assert "code.credential-access" in rules
    assert "secret.generic" in rules
    assert "code.network-egress" in rules
    assert "credential-access" in art["observed_capabilities"]


def test_adversarial_injection_flagged_suspicious(report):
    art = _artifact(report, "friendly-formatter")
    assert art["findings"], "injection fixture must produce findings"
    for f in art["findings"]:
        assert f["category"] == "suspicious-instruction"
        assert f["evidence"], "suspicious findings must quote evidence"
        assert "SUSPICIOUS" in f["message"]
    rules = {f["rule_id"] for f in art["findings"]}
    assert "instruction.ignore-previous" in rules
    assert "instruction.conceal-from-user" in rules
    assert "instruction.exfiltration" in rules


def test_benign_skills_have_no_critical_findings(report):
    for name in ("benign-note-taker", "benign-web-summary"):
        art = _artifact(report, name)
        assert "critical" not in _severities(art), (name, art["findings"])
        assert "high" not in _severities(art), (name, art["findings"])


def test_benign_note_taker_fully_clean(report):
    art = _artifact(report, "benign-note-taker")
    assert art["findings"] == []
    assert art["declared_capabilities"] == ["filesystem-write"]


def test_bad_mcp_caught(report):
    art = _artifact(report, "bad-mcp")
    rules = {f["rule_id"]: f for f in art["findings"]}
    assert rules["mcp.shell-command"]["severity"] == "critical"
    assert rules["mcp.secret-in-env"]["severity"] == "critical"
    # the literal secret value must never be echoed into a finding
    assert "sk-liveexample" not in json.dumps(art["findings"])
    assert rules["mcp.remote-plaintext"]["severity"] == "high"
    assert rules["mcp.unpinned-package"]["severity"] == "medium"
    assert rules["mcp.env-passthrough"]["severity"] == "low"


def test_good_mcp_clean(report):
    art = _artifact(report, "good-mcp")
    assert art["findings"] == []


def test_acbom_shape(report):
    art = _artifact(report, "benign-note-taker")
    for key in ("name", "kind", "source", "version", "files",
                "executable_components", "declared_capabilities",
                "observed_capabilities", "dependencies", "findings",
                "last_verified"):
        assert key in art, key
    skill_md = next(f for f in art["files"] if f["path"].endswith("SKILL.md"))
    assert len(skill_md["sha256"]) == 64
    assert "scripts/notes.py" in art["executable_components"]
    deps = {(d["name"], d["pinned"]) for d in art["dependencies"]}
    assert ("pyyaml", True) in deps


def test_scan_exit_code_nonzero_on_critical(capsys):
    assert main(["scan", FIXTURES]) == 1


def test_scan_exit_code_zero_on_clean_tree(tmp_path):
    shutil.copytree(os.path.join(FIXTURES, "skills", "benign-note-taker"),
                    tmp_path / "benign-note-taker")
    assert main(["scan", str(tmp_path)]) == 0


def test_sarif_output_is_valid(capsys):
    assert main(["scan", FIXTURES, "--format", "sarif"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-shield"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "code.credential-access" in rule_ids
    assert all(r["ruleId"] in rule_ids for r in run["results"])


def test_json_output_parses(capsys):
    main(["scan", FIXTURES, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings_by_severity"]["critical"] >= 4


def test_inspect_single_mcp_file(capsys):
    path = os.path.join(FIXTURES, "mcp", "bad-mcp.json")
    assert main(["inspect", path]) == 1
    out = capsys.readouterr().out
    assert "mcp.shell-command" in out


def test_inspect_benign_skill_dir(capsys):
    path = os.path.join(FIXTURES, "skills", "benign-note-taker")
    assert main(["inspect", path]) == 0
    assert "none detected" in capsys.readouterr().out


def test_lock_and_diff_roundtrip(tmp_path):
    tree = tmp_path / "tree"
    shutil.copytree(os.path.join(FIXTURES, "skills", "benign-note-taker"),
                    tree / "benign-note-taker")
    out_path, lock = lockfile.write_lock(str(tree))
    assert os.path.isfile(out_path)
    assert lock["artifacts"], "lock must contain the artifact"
    assert lockfile.diff(str(tree))["clean"]

    target = tree / "benign-note-taker" / "scripts" / "notes.py"
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("# tampered\n")
    result = lockfile.diff(str(tree))
    assert not result["clean"]
    assert any("notes.py" in p for p in result["changed_files"])

    with open(tree / "benign-note-taker" / "extra.py", "w") as fh:
        fh.write("print('new')\n")
    result = lockfile.diff(str(tree))
    assert any("extra.py" in p for p in result["added_files"])


def test_lock_diff_clean_when_lockfile_lives_in_artifact_root(tmp_path):
    # Regression: locking a directory that IS an artifact root writes the
    # lockfile inside the artifact; diff must not report it as an addition.
    tree = tmp_path / "skill"
    shutil.copytree(os.path.join(FIXTURES, "skills", "benign-note-taker"), tree)
    lockfile.write_lock(str(tree))
    assert lockfile.diff(str(tree))["clean"]


def test_cli_diff_exit_codes(tmp_path, capsys):
    tree = tmp_path / "tree"
    shutil.copytree(os.path.join(FIXTURES, "skills", "benign-note-taker"),
                    tree / "benign-note-taker")
    assert main(["lock", str(tree)]) == 0
    assert main(["diff", str(tree)]) == 0
    with open(tree / "benign-note-taker" / "SKILL.md", "a") as fh:
        fh.write("\nextra line\n")
    assert main(["diff", str(tree)]) == 1


def test_subprocess_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "agent_shield.cli", "scan",
         os.path.join(FIXTURES, "mcp")],
        capture_output=True, text=True,
        env={**os.environ,
             "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
    assert proc.returncode == 1
    assert "bad-mcp" in proc.stdout
