"""CLI smoke tests against a real SQLite file."""

from __future__ import annotations

from pathlib import Path

from aegis.cli import main


def test_init_status_and_admin(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    assert main(["--home", home, "init"]) == 0
    assert (tmp_path / "aegis.sqlite3").exists()

    assert (
        main(
            [
                "--home",
                home,
                "create-admin",
                "--email",
                "cli@aegis.test",
                "--display-name",
                "CLI Admin",
                "--password",
                "CliAdminPass123",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "CLI Admin" in captured.out or "cli@aegis.test" in captured.out

    assert main(["--home", home, "status"]) == 0
    status_out = capsys.readouterr().out
    assert "schema:" in status_out
    assert "users:" in status_out


def test_seed_demo_is_idempotent(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    assert main(["--home", home, "seed-demo"]) == 0
    assert main(["--home", home, "seed-demo"]) == 0
    output = capsys.readouterr().out
    assert "demo data loaded" in output
    assert "already present" in output


def test_create_user_requires_admin(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    assert (
        main(
            [
                "--home",
                home,
                "create-user",
                "--email",
                "member@aegis.test",
                "--display-name",
                "Member",
                "--password",
                "MemberPass123",
            ]
        )
        == 2
    )


def test_assets_import_and_export(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    csv_path = tmp_path / "extra.csv"
    csv_path.write_text(
        "name,category,confidentiality,integrity,availability\n"
        "CLI 导入资产,server,3,3,3\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "import",
                "--engagement",
                "ENG-2026-0001",
                "--file",
                str(csv_path),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "imported 1" in output

    export_path = tmp_path / "assets.csv"
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--out",
                str(export_path),
            ]
        )
        == 0
    )
    exported = export_path.read_text(encoding="utf-8")
    assert "CLI 导入资产" in exported
    assert "AST-0006" in exported


def test_assets_import_unknown_engagement(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    csv_path = tmp_path / "extra.csv"
    csv_path.write_text("name\n资产\n", encoding="utf-8")
    assert (
        main(
            [
                "--home",
                home,
                "assets",
                "import",
                "--engagement",
                "ENG-9999-9999",
                "--file",
                str(csv_path),
            ]
        )
        == 2
    )
    assert "engagement not found" in capsys.readouterr().err


def test_assets_template(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    out_path = tmp_path / "template.csv"
    assert main(["--home", home, "assets", "template", "--out", str(out_path)]) == 0
    assert out_path.read_text(encoding="utf-8").lstrip("\ufeff").startswith(
        "name,asset_type,category"
    )


def test_risks_list_and_export(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    assert (
        main(["--home", home, "risks", "list", "--engagement", "ENG-2026-0001"]) == 0
    )
    listing = capsys.readouterr().out
    assert "RA-0001" in listing
    assert "RA-0002" in listing
    assert "issued" in listing

    out_path = tmp_path / "register.csv"
    assert (
        main(
            [
                "--home",
                home,
                "risks",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--assessment",
                "RA-0001",
                "--out",
                str(out_path),
            ]
        )
        == 0
    )
    exported = out_path.read_text(encoding="utf-8").lstrip("\ufeff")
    assert exported.startswith("asset_code,asset_name,threat_code")
    assert "AST-0001" in exported
    assert "mitigate" in exported


def test_controls_catalog_and_coverage(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    assert main(["--home", home, "controls", "frameworks"]) == 0
    frameworks = capsys.readouterr().out
    assert "ISO27001" in frameworks
    assert "NISTCSF" in frameworks
    assert "93" in frameworks

    assert (
        main(
            [
                "--home",
                home,
                "controls",
                "list",
                "--framework",
                "NISTCSF",
                "--domain",
                "PR",
            ]
        )
        == 0
    )
    listed = capsys.readouterr().out
    assert "PR.AA" in listed
    assert "PR.IR" in listed
    assert "GV.OC" not in listed

    assert (
        main(["--home", home, "controls", "coverage", "--engagement", "ENG-2026-0001"])
        == 0
    )
    coverage = capsys.readouterr().out
    assert "2/5 (40.0%)" in coverage
    assert "uncovered: 3" in coverage


def test_soa_generate_and_export(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    assert (
        main(
            [
                "--home",
                home,
                "soa",
                "generate",
                "--engagement",
                "ENG-2026-0001",
                "--framework",
                "ISO27001",
            ]
        )
        == 0
    )
    assert "generated 0 entries" in capsys.readouterr().out

    out_path = tmp_path / "soa.csv"
    assert (
        main(
            [
                "--home",
                home,
                "soa",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--framework",
                "ISO27001",
                "--out",
                str(out_path),
            ]
        )
        == 0
    )
    exported = out_path.read_text(encoding="utf-8").lstrip("\ufeff")
    assert exported.startswith("control_code,control_title,domain")
    assert "A.8.13" in exported
    assert "已实施" in exported
    assert "租赁机柜" in exported


def test_remediation_and_evidence_cli(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    capsys.readouterr()

    assert (
        main(["--home", home, "remediation", "list", "--engagement", "ENG-2026-0001"])
        == 0
    )
    listing = capsys.readouterr().out
    assert "RT-0001" in listing
    assert "RT-0003" in listing
    assert "已完成" in listing

    assert (
        main(
            ["--home", home, "remediation", "summary", "--engagement", "ENG-2026-0001"]
        )
        == 0
    )
    summary = capsys.readouterr().out
    assert "overdue:" in summary
    assert "completion:" in summary

    assert (
        main(
            [
                "--home",
                home,
                "evidence",
                "list",
                "--engagement",
                "ENG-2026-0001",
                "--task",
                "RT-0001",
            ]
        )
        == 0
    )
    evidence = capsys.readouterr().out
    assert "mes-segmentation-plan.txt" in evidence
    assert "text/plain" in evidence

    out_dir = tmp_path / "evidence"
    assert (
        main(
            [
                "--home",
                home,
                "evidence",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--task",
                "RT-0001",
                "--out",
                str(out_dir),
            ]
        )
        == 0
    )
    exported = out_dir / "mes-segmentation-plan.txt"
    assert "MES 生产网分区方案" in exported.read_text(encoding="utf-8")

    assert main(["--home", home, "status"]) == 0
    status_out = capsys.readouterr().out
    assert "remediation_tasks:" in status_out
    assert "evidence_files:" in status_out


def test_risks_export_unknown_assessment(tmp_path: Path, capsys) -> None:
    home = str(tmp_path)
    main(["--home", home, "init"])
    main(["--home", home, "seed-demo"])
    assert (
        main(
            [
                "--home",
                home,
                "risks",
                "export",
                "--engagement",
                "ENG-2026-0001",
                "--assessment",
                "RA-9999",
            ]
        )
        == 2
    )
    assert "assessment not found" in capsys.readouterr().err
