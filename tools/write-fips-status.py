#!/usr/bin/env python3
# Purpose: Write the contract-derived FIPS status artifact into the production runtime rootfs.
# Role: build
# Micro-container candidate: no - runs inside the discarded rpm-rootfs builder stage and writes into its installroot.
# Build-process: yes - validates build pins against the image contract and emits byte-stable runtime metadata.

"""Write a byte-stable FIPS status artifact from the image contract."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

TARGET_ARCHES = ("amd64", "arm64")


class StatusWriteError(RuntimeError):
    """Raised when the FIPS status contract or build pins are invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StatusWriteError(message)


def _object(value: Any, name: str) -> Mapping[str, Any]:
    _require(isinstance(value, dict), f"{name} must be a JSON object")
    return cast("Mapping[str, Any]", value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    _require(actual == expected, f"{name} keys must be exactly {sorted(expected)}; got {sorted(actual)}")


def _typed_value[T](value: Mapping[str, Any], key: str, expected_type: type[T], name: str) -> T:
    _require(key in value, f"{name}.{key} is required")
    item = value[key]
    _require(type(item) is expected_type, f"{name}.{key} must be {expected_type.__name__}")
    if expected_type is str:
        _require(bool(item), f"{name}.{key} must not be empty")
    return cast(T, item)


def _load_fips_contract(contract: Path, target_arch: str) -> tuple[str, str, str, str, bool, str]:
    document = _object(json.loads(contract.read_text(encoding="utf-8")), "contract")
    fips = _object(document.get("fips"), "contract.fips")
    _exact_keys(fips, {"module_version", "provider_nevra", "cmvp", "architectures"}, "contract.fips")

    module_version = _typed_value(fips, "module_version", str, "contract.fips")
    provider_nevra = _typed_value(fips, "provider_nevra", str, "contract.fips")
    cmvp = _typed_value(fips, "cmvp", str, "contract.fips")
    architectures = _object(fips.get("architectures"), "contract.fips.architectures")
    _require(target_arch in architectures, f"contract.fips.architectures.{target_arch} is required")
    architecture = _object(architectures[target_arch], f"contract.fips.architectures.{target_arch}")
    _exact_keys(
        architecture,
        {"rpm_arch", "fips_so_sha256", "oe_validated", "disclaimer"},
        f"contract.fips.architectures.{target_arch}",
    )
    rpm_arch = _typed_value(architecture, "rpm_arch", str, f"contract.fips.architectures.{target_arch}")
    _typed_value(architecture, "fips_so_sha256", str, f"contract.fips.architectures.{target_arch}")
    oe_validated = _typed_value(architecture, "oe_validated", bool, f"contract.fips.architectures.{target_arch}")
    disclaimer = _typed_value(architecture, "disclaimer", str, f"contract.fips.architectures.{target_arch}")
    return module_version, provider_nevra, cmvp, rpm_arch, oe_validated, disclaimer


def write_status(
    contract: Path,
    *,
    target_arch: str,
    provider_nevra: str,
    module_version: str,
    output: Path,
) -> None:
    """Validate the build pins and write the contract-derived status bytes."""
    contract_module, contract_provider, cmvp, rpm_arch, oe_validated, disclaimer = _load_fips_contract(
        contract, target_arch
    )
    _require(
        provider_nevra == contract_provider,
        "provider NEVRA build pin does not match contract.fips.provider_nevra",
    )
    _require(module_version == contract_module, "module version build pin does not match contract.fips.module_version")

    payload = {
        "arch": target_arch,
        "module": contract_module,
        "provider_nvr": contract_provider,
        "provider_nevra": f"{contract_provider}.{rpm_arch}",
        "cmvp": f"#{cmvp}",
        "oe_validated": oe_validated,
        "disclaimer": disclaimer,
    }
    encoded = (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    output.write_bytes(encoded)
    _require(bool(output.read_bytes()), f"FIPS status output is empty: {output}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--target-arch", choices=TARGET_ARCHES, required=True)
    parser.add_argument("--provider-nevra", required=True)
    parser.add_argument("--module-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        write_status(
            args.contract,
            target_arch=args.target_arch,
            provider_nevra=args.provider_nevra,
            module_version=args.module_version,
            output=args.output,
        )
    except (StatusWriteError, OSError, json.JSONDecodeError) as exc:
        print(f"FIPS status write failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
