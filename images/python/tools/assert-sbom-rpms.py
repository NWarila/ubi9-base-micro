#!/usr/bin/env python3
# Purpose: Assert Syft SBOMs enumerate the required runtime RPM floor
# Role: gate
# Micro-container candidate: yes - pure-stdlib, SBOM-in/exit-out, has --self-test

"""Assert Syft SBOMs enumerate the runtime RPM floor."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
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


@dataclass
class SbomNames:
    rpm: set[str]
    inspected: set[str]


def rpm_name_from_purl(purl: str) -> str | None:
    if not purl.startswith("pkg:rpm/"):
        return None
    package_url = purl.split("#", 1)[0].split("?", 1)[0]
    package = package_url.rsplit("/", 1)[-1].split("@", 1)[0]
    package = unquote(package)
    return package or None


def inspect_display_name(names: SbomNames, display_name: Any, context: str) -> str | None:
    """Inspect every available display name, independently of package type or purl."""
    if display_name is None:
        return None
    if not isinstance(display_name, str) or not display_name:
        raise SbomError(f"{context}: display name must be a non-empty string")
    names.inspected.add(display_name)
    return display_name


def inspect_purl(
    names: SbomNames,
    display_name: str | None,
    purl: Any,
    context: str,
    *,
    require_rpm: bool = False,
) -> None:
    """Inspect an RPM identity from every available purl and reject aliases."""
    if purl is None or purl == "":
        return
    if not isinstance(purl, str):
        raise SbomError(f"{context}.purl must be a string")
    purl_name = rpm_name_from_purl(purl)
    if purl_name is None:
        if require_rpm:
            raise SbomError(f"{context}.purl must identify an RPM package")
        return
    names.rpm.add(purl_name)
    names.inspected.add(purl_name)
    if display_name is not None and display_name != purl_name:
        raise SbomError(f"{context}: RPM display name {display_name!r} disagrees with purl name {purl_name!r}")


def names_from_spdx(document: dict[str, Any]) -> SbomNames:
    names = SbomNames(rpm=set(), inspected=set())
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise SbomError("SPDX packages must be a list")
    for package_index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise SbomError(f"SPDX packages[{package_index}] must be an object")
        context = f"SPDX packages[{package_index}]"
        package_name = inspect_display_name(names, package.get("name"), context)
        refs = package.get("externalRefs") or []
        if not isinstance(refs, list):
            raise SbomError(f"SPDX packages[{package_index}].externalRefs must be a list")
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, dict):
                raise SbomError(f"SPDX packages[{package_index}].externalRefs[{ref_index}] must be an object")
            locator = ref.get("referenceLocator")
            inspect_purl(names, package_name, locator, context)
    return names


def names_from_cyclonedx(document: dict[str, Any]) -> SbomNames:
    names = SbomNames(rpm=set(), inspected=set())
    components = document.get("components")
    if not isinstance(components, list):
        raise SbomError("CycloneDX components must be a list")
    for component_index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SbomError(f"CycloneDX components[{component_index}] must be an object")
        context = f"CycloneDX components[{component_index}]"
        display_name = inspect_display_name(names, component.get("name"), context)
        inspect_purl(names, display_name, component.get("purl"), context)
    return names


def names_from_syft_json(document: dict[str, Any]) -> SbomNames:
    names = SbomNames(rpm=set(), inspected=set())
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        raise SbomError("Syft artifacts must be a list")
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise SbomError(f"Syft artifacts[{artifact_index}] must be an object")
        context = f"Syft artifacts[{artifact_index}]"
        display_name = inspect_display_name(names, artifact.get("name"), context)
        artifact_is_rpm = artifact.get("type") == "rpm"
        if artifact_is_rpm:
            if display_name is None:
                raise SbomError(f"{context}: RPM display name must be a non-empty string")
            names.rpm.add(display_name)
        inspect_purl(
            names,
            display_name,
            artifact.get("purl"),
            context,
            require_rpm=artifact_is_rpm,
        )
    return names


def rpm_names(document: dict[str, Any]) -> tuple[str, SbomNames]:
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
    names: SbomNames,
    min_rpm_count: int,
    required: frozenset[str] = REQUIRED_RPMS,
    forbidden: frozenset[str] = FORBIDDEN_RPMS,
) -> None:
    missing = sorted(required - names.rpm)
    if missing:
        raise SbomError(
            f"{label}: missing required RPM package(s): {', '.join(missing)} (rpm package count={len(names.rpm)})"
        )
    if len(names.rpm) < min_rpm_count:
        raise SbomError(f"{label}: rpm package count {len(names.rpm)} is below minimum {min_rpm_count}")
    present_forbidden = sorted(forbidden & names.inspected)
    if present_forbidden:
        raise SbomError(f"{label}: forbidden RPM package(s) present: {', '.join(present_forbidden)}")


def check_file(path: Path, min_rpm_count: int) -> tuple[str, set[str]]:
    document = load_document(path)
    format_name, names = rpm_names(document)
    assert_names(str(path), names, min_rpm_count)
    return format_name, names.rpm


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

    mutation_documents: list[tuple[str, str, dict[str, Any]]] = []
    negative_cdx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "glibc", "purl": "pkg:rpm/redhat/glibc@1.0"},
        ],
    }
    mutation_documents.append(("missing-floor", "cyclonedx-json", negative_cdx))

    forbidden_names = positive_names | FORBIDDEN_RPMS
    for expected_format, document in zip(expected_formats, documents(forbidden_names), strict=True):
        mutation_documents.append((f"forbidden-{expected_format}", expected_format, document))

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
        mutation_documents.append((f"alias-{expected_format}", expected_format, document))

    display_bypass_locators: list[tuple[str, str | None]] = [
        ("no-purl", None),
        ("generic-purl", "pkg:generic/sqlite-libs@3.34.1"),
        ("malformed-rpm-purl", "pkg:rpm/"),
    ]
    for label, locator in display_bypass_locators:
        spdx_document = documents(positive_names)[0]
        spdx_package: dict[str, Any] = {"name": "sqlite-libs"}
        if locator is not None:
            spdx_package["externalRefs"] = [{"referenceLocator": locator}]
        spdx_document["packages"].append(spdx_package)
        mutation_documents.append((f"spdx-{label}", "spdx-json", spdx_document))

        cyclonedx_document = documents(positive_names)[1]
        cyclonedx_component: dict[str, Any] = {"name": "sqlite-libs"}
        if locator is not None:
            cyclonedx_component["purl"] = locator
        cyclonedx_document["components"].append(cyclonedx_component)
        mutation_documents.append((f"cyclonedx-{label}", "cyclonedx-json", cyclonedx_document))

    subpath_purl = "pkg:rpm/redhat/sqlite-libs@3.34.1#usr/lib/innocent-alias"
    subpath_documents = documents(positive_names)
    subpath_documents[0]["packages"].append(
        {
            "name": "innocent-alias",
            "externalRefs": [{"referenceLocator": subpath_purl}],
        }
    )
    subpath_documents[1]["components"].append({"name": "innocent-alias", "purl": subpath_purl})
    subpath_documents[2]["artifacts"].append({"name": "innocent-alias", "type": "rpm", "purl": subpath_purl})
    for expected_format, document in zip(expected_formats, subpath_documents, strict=True):
        mutation_documents.append((f"subpath-{expected_format}", expected_format, document))

    qualified_subpath_purl = "pkg:rpm/redhat/sqlite-libs@3.34.1?arch=x86_64#usr/lib/innocent-alias"
    qualified_subpath_documents = documents(positive_names)
    qualified_subpath_documents[0]["packages"].append(
        {
            "name": "innocent-alias",
            "externalRefs": [{"referenceLocator": qualified_subpath_purl}],
        }
    )
    qualified_subpath_documents[1]["components"].append({"name": "innocent-alias", "purl": qualified_subpath_purl})
    qualified_subpath_documents[2]["artifacts"].append(
        {"name": "innocent-alias", "type": "rpm", "purl": qualified_subpath_purl}
    )
    for expected_format, document in zip(expected_formats, qualified_subpath_documents, strict=True):
        mutation_documents.append((f"qualified-subpath-{expected_format}", expected_format, document))

    syft_non_rpm_purl = documents(positive_names)[2]
    syft_non_rpm_purl["artifacts"].append(
        {
            "name": "innocent-alias",
            "type": "library",
            "purl": "pkg:rpm/redhat/sqlite-libs@3.34.1",
        }
    )
    mutation_documents.append(("syft-non-rpm-purl", "syft-json", syft_non_rpm_purl))

    rejected = 0
    for label, expected_format, document in mutation_documents:
        try:
            format_name, names = rpm_names(document)
            assert format_name == expected_format
            assert_names(label, names, DEFAULT_MIN_RPM_COUNT)
        except SbomError as exc:
            if label == "missing-floor":
                expected_failure = "missing required RPM package(s)"
            elif label.startswith(("forbidden-", "spdx-", "cyclonedx-")):
                expected_failure = "forbidden RPM package(s) present"
            else:
                expected_failure = "disagrees with purl name"
            if expected_failure not in str(exc):
                raise SbomError(f"{label} self-test rejected for the wrong reason: {exc}") from exc
            rejected += 1
        else:
            raise SbomError(f"{label} self-test unexpectedly passed")
    print(f"sbom rpm assertion self-test: positive formats=3; {rejected}/{len(mutation_documents)} mutations rejected")


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
