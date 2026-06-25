#!/usr/bin/env python3
# Purpose: Assert Syft SBOMs enumerate the required runtime RPM floor
# Role: gate
# Micro-container candidate: yes - pure-stdlib, SBOM-in/exit-out, has --self-test

"""Assert Syft SBOMs enumerate the runtime RPM floor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

REQUIRED_RPMS = frozenset(
    {
        "ca-certificates",
        "glibc",
        "openssl-fips-provider-so",
        "openssl-libs",
    }
)
DEFAULT_MIN_RPM_COUNT = 10


class SbomError(Exception):
    pass


def rpm_name_from_purl(purl: str) -> str | None:
    if not purl.startswith("pkg:rpm/"):
        return None
    package = purl.rsplit("/", 1)[-1].split("@", 1)[0]
    package = unquote(package)
    return package or None


def names_from_spdx(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for package in document.get("packages") or []:
        package_name = package.get("name")
        for ref in package.get("externalRefs") or []:
            locator = ref.get("referenceLocator") or ""
            rpm_name = rpm_name_from_purl(locator)
            if rpm_name:
                names.add(package_name or rpm_name)
    return names


def names_from_cyclonedx(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for component in document.get("components") or []:
        rpm_name = rpm_name_from_purl(component.get("purl") or "")
        if rpm_name:
            names.add(component.get("name") or rpm_name)
    return names


def names_from_syft_json(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for artifact in document.get("artifacts") or []:
        if artifact.get("type") == "rpm" and artifact.get("name"):
            names.add(artifact["name"])
    return names


def rpm_names(document: dict[str, Any]) -> tuple[str, set[str]]:
    if document.get("spdxVersion") and "packages" in document:
        return "spdx-json", names_from_spdx(document)
    if document.get("bomFormat") == "CycloneDX" and "components" in document:
        return "cyclonedx-json", names_from_cyclonedx(document)
    if "artifacts" in document:
        return "syft-json", names_from_syft_json(document)
    raise SbomError("unsupported SBOM document shape")


def load_document(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SbomError(f"{path}: expected a JSON object")
    return cast(dict[str, Any], document)


def assert_names(
    label: str,
    names: set[str],
    min_rpm_count: int,
    required: frozenset[str] = REQUIRED_RPMS,
) -> None:
    missing = sorted(required - names)
    if missing:
        raise SbomError(
            f"{label}: missing required RPM package(s): {', '.join(missing)} (rpm package count={len(names)})"
        )
    if len(names) < min_rpm_count:
        raise SbomError(f"{label}: rpm package count {len(names)} is below minimum {min_rpm_count}")


def check_file(path: Path, min_rpm_count: int) -> tuple[str, set[str]]:
    document = load_document(path)
    format_name, names = rpm_names(document)
    assert_names(str(path), names, min_rpm_count)
    return format_name, names


def run_self_test() -> None:
    positive_spdx = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": name,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:rpm/redhat/{name}@1.0",
                    }
                ],
            }
            for name in sorted(REQUIRED_RPMS | {"basesystem", "filesystem", "setup", "tzdata", "zlib", "libgcc"})
        ],
    }
    format_name, names = rpm_names(positive_spdx)
    assert format_name == "spdx-json"
    assert_names("positive-spdx", names, DEFAULT_MIN_RPM_COUNT)

    negative_cdx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "glibc", "purl": "pkg:rpm/redhat/glibc@1.0"},
        ],
    }
    try:
        format_name, names = rpm_names(negative_cdx)
        assert format_name == "cyclonedx-json"
        assert_names("negative-cyclonedx", names, DEFAULT_MIN_RPM_COUNT)
    except SbomError:
        print("sbom rpm assertion self-test: ok")
        return
    raise SbomError("negative self-test unexpectedly passed")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail unless SBOM JSON enumerates required RPM packages.")
    parser.add_argument(
        "--min-rpm-count",
        type=int,
        default=DEFAULT_MIN_RPM_COUNT,
        help="minimum unique RPM package names required in each document",
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="gate-only Syft JSON inventory to corroborate required RPM names",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in positive and negative parser checks",
    )
    parser.add_argument("documents", nargs="*", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()

        if not args.documents and not args.self_test:
            raise SbomError("at least one SBOM document is required")

        source_names: set[str] | None = None
        if args.source:
            source_format, source_names = check_file(args.source, args.min_rpm_count)
            print(
                f"{args.source}: format={source_format} "
                f"rpm_package_count={len(source_names)} "
                f"required={','.join(sorted(REQUIRED_RPMS))}"
            )

        for path in args.documents:
            format_name, names = check_file(path, args.min_rpm_count)
            if source_names is not None:
                missing_from_source = sorted(REQUIRED_RPMS - source_names)
                if missing_from_source:
                    raise SbomError(
                        f"{path}: source inventory missing required RPM package(s): " + ", ".join(missing_from_source)
                    )
            print(
                f"{path}: format={format_name} "
                f"rpm_package_count={len(names)} "
                f"required={','.join(sorted(REQUIRED_RPMS))}"
            )
    except SbomError as exc:
        print(f"sbom rpm assertion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
