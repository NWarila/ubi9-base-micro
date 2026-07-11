# Purpose: Validate collapse-proof runtime lock generation and capture-stage policy helpers.
# Role: test
# Micro-container candidate: no - pytest coverage for generation logic used in a discarded build stage.
# Build-process: no - test-only fixtures and mutation coverage.

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
from tools import rpmlock

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools/generate-runtime-lock.py"


def _load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_runtime_lock", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["rpmlock"] = rpmlock
    spec.loader.exec_module(module)
    return module


generator = _load_helper()


def _row(name: str, index: int) -> rpmlock.LockRow:
    arch = "x86_64" if name in {"glibc", "discarded"} else "noarch"
    return rpmlock.LockRow(
        package=f"{name}-1-{index}.el9.{arch}",
        final_rpmdb="no",
        name=name,
        epoch="0",
        version="1",
        release=f"{index}.el9",
        arch=arch,
        sha256_header=f"{index:064x}",
        sigmd5=f"{index:032x}",
    )


def _fixture() -> tuple[tuple[rpmlock.LockRow, ...], tuple[str, ...], tuple[rpmlock.DirectRpm, ...]]:
    rows = tuple(_row(name, index) for index, name in enumerate((*rpmlock.REQUIRED_FINAL_NAMES, "discarded"), start=1))
    final_nevras = tuple(row.package for row in rows if row.name != "discarded")
    direct = tuple(
        rpmlock.DirectRpm(
            package=row.package,
            url=(
                "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/"
                f"baseos/os/Packages/{row.name[0]}/{rpmlock.rpm_filename(row)}"
            ),
            sha256=f"{index + 100:064x}",
        )
        for index, row in enumerate(rows)
    )
    return rows, final_nevras, direct


class _ExactlyOnce:
    def __init__(self, rows: tuple[rpmlock.LockRow, ...]) -> None:
        self.rows = rows
        self.iterations = 0

    def __iter__(self) -> Iterator[rpmlock.LockRow]:
        self.iterations += 1
        if self.iterations != 1:
            raise AssertionError("full_rows was iterated more than once")
        yield from self.rows


def test_render_consumes_full_rows_once_and_preserves_snapshot_order() -> None:
    rows, final_nevras, direct = _fixture()
    one_shot = _ExactlyOnce(rows)

    rendered = cast(bytes, generator.render(one_shot, final_nevras, reversed(direct)))
    lines = rendered.decode().splitlines()
    direct_lines = [line for line in lines if line.startswith(rpmlock.DIRECT_PREFIX)]
    data_lines = [line for line in lines if not line.startswith("#")]

    assert one_shot.iterations == 1
    assert len(data_lines) == len(rows)
    assert [line.removeprefix(rpmlock.DIRECT_PREFIX).split("|", 1)[0] for line in direct_lines] == [
        row.package for row in rows
    ]
    assert [line.split("|", 1)[0] for line in data_lines] == [row.package for row in rows]
    assert {line.split("|", 2)[0] for line in data_lines if line.split("|", 2)[1] == "no"} == {rows[-1].package}
    assert rendered.endswith(b"\n")
    assert b"\r" not in rendered


def test_render_lock_is_byte_exact_lf_text() -> None:
    rows, final_nevras, direct = _fixture()

    rendered = cast(
        bytes,
        generator.render_lock(
            arch="amd64",
            source_date_epoch="1704067200",
            full_rows=rows,
            final_nevras=final_nevras,
            direct_results=direct,
        ),
    )

    expected_header = f"# arch: amd64\n# source_date_epoch: 1704067200\n# columns: {rpmlock.COLUMNS}\n".encode()
    assert rendered.startswith(expected_header)
    assert len([line for line in rendered.splitlines() if line and not line.startswith(b"#")]) == len(rows)
    assert rendered.endswith(b"\n")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("survivor", "survivor absent from full snapshot"),
        ("final_names", "final RPM names differ"),
        ("missing_direct", "missing direct RPM result"),
        ("duplicate_direct", "duplicate direct RPM result"),
        ("orphan_direct", "no matching full row"),
        ("filename", "does not match row filename"),
        ("candidate", "does not match candidate policy"),
        ("sha", "invalid direct RPM sha256"),
        ("duplicate_row", "duplicate full RPM snapshot row"),
    ],
)
def test_render_rejects_every_join_failure_class(mutation: str, message: str) -> None:
    rows, final_nevras, direct = _fixture()
    active_rows = rows
    active_final = final_nevras
    active_direct = direct
    if mutation == "survivor":
        active_final = (*final_nevras, "ghost-1-1.el9.noarch")
    elif mutation == "final_names":
        active_final = final_nevras[:-1]
    elif mutation == "missing_direct":
        active_direct = direct[:-1]
    elif mutation == "duplicate_direct":
        active_direct = (*direct, direct[0])
    elif mutation == "orphan_direct":
        active_direct = (*direct, rpmlock.DirectRpm("ghost", direct[0].url, direct[0].sha256))
    elif mutation == "filename":
        active_direct = (
            rpmlock.DirectRpm(direct[0].package, direct[0].url.replace(".rpm", ".wrong.rpm"), direct[0].sha256),
            *direct[1:],
        )
    elif mutation == "candidate":
        active_direct = (
            rpmlock.DirectRpm(
                direct[0].package, direct[0].url.replace("/Packages/b/", "/Packages/z/"), direct[0].sha256
            ),
            *direct[1:],
        )
    elif mutation == "sha":
        active_direct = (rpmlock.DirectRpm(direct[0].package, direct[0].url, "0" * 63), *direct[1:])
    elif mutation == "duplicate_row":
        active_rows = (*rows, rows[0])

    with pytest.raises(generator.GenerationError, match=message):
        generator.render(active_rows, active_final, active_direct)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("too|few|columns", "exactly 8 columns"),
        ("name-1-1.el9.noarch|name|epoch|1|1.el9|noarch|" + "0" * 64 + "|" + "0" * 32, "non-numeric epoch"),
    ],
)
def test_full_snapshot_parser_rejects_malformed_rows(tmp_path: Path, replacement: str, message: str) -> None:
    path = tmp_path / "runtime.full.tsv"
    path.write_text(f"{replacement}\n", encoding="utf-8", newline="\n")

    with pytest.raises(generator.GenerationError, match=message):
        generator.parse_full_rows(path)


def test_full_snapshot_parser_rejects_duplicate_rows(tmp_path: Path) -> None:
    rows, _, _ = _fixture()
    row = rows[0]
    line = "|".join(
        (row.package, row.name, row.epoch, row.version, row.release, row.arch, row.sha256_header, row.sigmd5)
    )
    path = tmp_path / "runtime.full.tsv"
    path.write_text(f"{line}\n{line}\n", encoding="utf-8", newline="\n")

    with pytest.raises(generator.GenerationError, match="duplicate full RPM snapshot row"):
        generator.parse_full_rows(path)


def test_candidate_derivation_is_baseos_then_appstream() -> None:
    row = _row("sample", 1)

    candidates = cast(
        tuple[str, str],
        generator.candidate_urls(row, "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/", "x86_64"),
    )

    assert "/x86_64/baseos/os/Packages/s/" in candidates[0]
    assert "/x86_64/appstream/os/Packages/s/" in candidates[1]
    assert candidates[0].endswith(rpmlock.rpm_filename(row))


@pytest.mark.parametrize(
    ("output", "accepted"),
    [
        ("package.rpm: digests signatures OK\n", True),
        ("package.rpm: digests OK\n", False),
        ("package.rpm: signatures NOT OK\n", False),
    ],
)
def test_signature_output_acceptance(output: str, accepted: bool) -> None:
    assert generator.signature_output_is_accepted(output) is accepted


def test_runtime_package_and_provider_policies_are_python_owned() -> None:
    expected_package_specs = tuple(name for name in rpmlock.REQUIRED_FINAL_NAMES if "fips" not in name)
    assert tuple(generator.RUNTIME_PACKAGE_SPECS) == expected_package_specs
    assert generator.provider_nvr("openssl-fips-provider-so-3.0.7-8.el9") == "3.0.7-8.el9"
    with pytest.raises(generator.GenerationError, match="invalid FIPS provider NEVRA pin"):
        generator.provider_nvr("openssl-libs-3.0.7-8.el9")
