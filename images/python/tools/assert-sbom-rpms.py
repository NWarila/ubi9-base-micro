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
        "python3.12",
        "python3.12-libs",
    }
)
FORBIDDEN_RPMS = frozenset({"sqlite-libs"})
# The combined parent-plus-python rpmdb carries 39 packages (15 inherited floor + 24 shipped).
# The floor absorbs ordinary upstream churn without going vacuous.
DEFAULT_MIN_RPM_COUNT = 35


class SbomError(Exception):
    pass


def rpm_name_from_purl(purl: str) -> str | None:
    if not purl.startswith("pkg:rpm/"):
        return None
    package = purl.rsplit("/", 1)[-1].split("@", 1)[0]
    package = unquote(package)
    return package or None


def add_rpm_identity(names: set[str], display_name: Any, purl_name: str, context: str) -> None:
    """Collect both RPM identities and reject a display-name alias."""
    if display_name is not None and (not isinstance(display_name, str) or not display_name):
        raise SbomError(f"{context}: RPM display name must be a non-empty string")
    if isinstance(display_name, str):
        names.add(display_name)
    names.add(purl_name)
    if display_name is not None and display_name != purl_name:
        raise SbomError(f"{context}: RPM display name {display_name!r} disagrees with purl name {purl_name!r}")


def names_from_spdx(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise SbomError("SPDX packages must be a list")
    for package_index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise SbomError(f"SPDX packages[{package_index}] must be an object")
        package_name = package.get("name")
        refs = package.get("externalRefs") or []
        if not isinstance(refs, list):
            raise SbomError(f"SPDX packages[{package_index}].externalRefs must be a list")
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, dict):
                raise SbomError(f"SPDX packages[{package_index}].externalRefs[{ref_index}] must be an object")
            locator = ref.get("referenceLocator") or ""
            if not isinstance(locator, str):
                raise SbomError(
                    f"SPDX packages[{package_index}].externalRefs[{ref_index}].referenceLocator must be a string"
                )
            rpm_name = rpm_name_from_purl(locator)
            if rpm_name:
                add_rpm_identity(names, package_name, rpm_name, f"SPDX packages[{package_index}]")
    return names


def names_from_cyclonedx(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    components = document.get("components")
    if not isinstance(components, list):
        raise SbomError("CycloneDX components must be a list")
    for component_index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SbomError(f"CycloneDX components[{component_index}] must be an object")
        purl = component.get("purl") or ""
        if not isinstance(purl, str):
            raise SbomError(f"CycloneDX components[{component_index}].purl must be a string")
        rpm_name = rpm_name_from_purl(purl)
        if rpm_name:
            add_rpm_identity(names, component.get("name"), rpm_name, f"CycloneDX components[{component_index}]")
    return names


def names_from_syft_json(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise SbomError("Syft artifacts must be a list")
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise SbomError(f"Syft artifacts[{artifact_index}] must be an object")
        if artifact.get("type") != "rpm":
            continue
        display_name = artifact.get("name")
        if not isinstance(display_name, str) or not display_name:
            raise SbomError(f"Syft artifacts[{artifact_index}]: RPM display name must be a non-empty string")
        names.add(display_name)
        purl = artifact.get("purl")
        if purl is None or purl == "":
            continue
        if not isinstance(purl, str):
            raise SbomError(f"Syft artifacts[{artifact_index}].purl must be a string")
        rpm_name = rpm_name_from_purl(purl)
        if rpm_name is None:
            raise SbomError(f"Syft artifacts[{artifact_index}].purl must identify an RPM package")
        add_rpm_identity(names, display_name, rpm_name, f"Syft artifacts[{artifact_index}]")
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
    forbidden: frozenset[str] = FORBIDDEN_RPMS,
) -> None:
    missing = sorted(required - names)
    if missing:
        raise SbomError(
            f"{label}: missing required RPM package(s): {', '.join(missing)} (rpm package count={len(names)})"
        )
    if len(names) < min_rpm_count:
        raise SbomError(f"{label}: rpm package count {len(names)} is below minimum {min_rpm_count}")
    present_forbidden = sorted(forbidden & names)
    if present_forbidden:
        raise SbomError(f"{label}: forbidden RPM package(s) present: {', '.join(present_forbidden)}")


def check_file(path: Path, min_rpm_count: int) -> tuple[str, set[str]]:
    document = load_document(path)
    format_name, names = rpm_names(document)
    assert_names(str(path), names, min_rpm_count)
    return format_name, names


def run_self_test() -> None:
    positive_names = (
        REQUIRED_RPMS
        | {"basesystem", "filesystem", "setup", "tzdata", "zlib", "libgcc"}
        | {f"combined-rpmdb-filler-{index:02d}" for index in range(DEFAULT_MIN_RPM_COUNT)}
    )

    def documents(names: frozenset[str]) -> list[dict[str, Any]]:
        return [
            {
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
                    for name in sorted(names)
                ],
            },
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": name, "purl": f"pkg:rpm/redhat/{name}@1.0"} for name in sorted(names)],
            },
            {
                "artifacts": [
                    {"name": name, "type": "rpm", "purl": f"pkg:rpm/redhat/{name}@1.0"} for name in sorted(names)
                ]
            },
        ]

    expected_formats = ["spdx-json", "cyclonedx-json", "syft-json"]
    for expected_format, document in zip(expected_formats, documents(positive_names), strict=True):
        format_name, names = rpm_names(document)
        assert format_name == expected_format
        assert_names(f"positive-{expected_format}", names, DEFAULT_MIN_RPM_COUNT)

    negative_cdx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "glibc", "purl": "pkg:rpm/redhat/glibc@1.0"},
        ],
    }
    rejected = 0
    try:
        format_name, names = rpm_names(negative_cdx)
        assert format_name == "cyclonedx-json"
        assert_names("negative-cyclonedx", names, DEFAULT_MIN_RPM_COUNT)
    except SbomError:
        rejected += 1
    else:
        raise SbomError("missing-floor negative self-test unexpectedly passed")

    forbidden_names = positive_names | FORBIDDEN_RPMS
    for expected_format, document in zip(expected_formats, documents(forbidden_names), strict=True):
        try:
            format_name, names = rpm_names(document)
            assert format_name == expected_format
            assert_names(f"forbidden-{expected_format}", names, DEFAULT_MIN_RPM_COUNT)
        except SbomError:
            rejected += 1
        else:
            raise SbomError(f"{expected_format} sqlite-libs negative self-test unexpectedly passed")

    alias_documents = documents(positive_names)
    alias_documents[0]["packages"].append(
        {
            "name": "innocent-alias",
            "externalRefs": [{"referenceLocator": "pkg:rpm/redhat/sqlite-libs@3.34.1"}],
        }
    )
    alias_documents[1]["components"].append({"name": "innocent-alias", "purl": "pkg:rpm/redhat/sqlite-libs@3.34.1"})
    alias_documents[2]["artifacts"].append(
        {"name": "innocent-alias", "type": "rpm", "purl": "pkg:rpm/redhat/sqlite-libs@3.34.1"}
    )
    for expected_format, document in zip(expected_formats, alias_documents, strict=True):
        try:
            format_name, names = rpm_names(document)
            assert format_name == expected_format
            assert_names(f"alias-{expected_format}", names, DEFAULT_MIN_RPM_COUNT)
        except SbomError:
            rejected += 1
        else:
            raise SbomError(f"{expected_format} alias-purl self-test unexpectedly passed")
    print(f"sbom rpm assertion self-test: positive formats=3; {rejected}/7 mutations rejected")


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
