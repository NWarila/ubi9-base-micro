#!/usr/bin/env python3
# Purpose: Build the base-python image twice and diff exported runtime rootfs bytes to prove reproducibility
# Role: gate
# Micro-container candidate: no - orchestrates a full double-build of images/python, not a thin file-in gate

"""Build the base-python image twice and compare exported runtime rootfs bytes."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

DEFAULT_IMAGE_PREFIX = "local/ubi9-base-python-repro"
DEFAULT_REPORT_RELATIVE_TEMPLATE = "dist/reproducibility/base-python.{arch}.reproducibility.json"
DEFAULT_SUMMARY_RELATIVE_TEMPLATE = "dist/reproducibility/base-python.{arch}.reproducibility.txt"
DEFAULT_WORKDIR_RELATIVE = "dist/reproducibility/work"
DEFAULT_BAKE_FILE_RELATIVE = "images/python/docker-bake.json"
DEFAULT_CONTRACT_RELATIVE = "images/python/contracts/image-manifest.json"
BAKE_TARGET = "repro"
CONTRACT_DEFAULT = Path("@base-python-contract-default@")
RPMDB_PATH = "var/lib/rpm/rpmdb.sqlite"
FIPS_SO_PATH = "usr/lib64/ossl-modules/fips.so"
XATTR_PAX_PREFIX = "SCHILY.xattr."
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OCI_XATTR_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
OCI_SPEC_VERSION = "1.1.1"
OCI_LAYOUT_VERSION = "1.0.0"
OCI_PROFILE_VERSION = "oci-content-identity/1"
OCI_CREATED = "2024-01-01T00:00:00Z"
OCI_SOURCE_DATE_EPOCH = 1704067200
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_CONTENT_IDENTITY_SCHEMA = Path(__file__).resolve().parents[1] / "contracts/content-identity.schema.json"
OCI_PRODUCER_OUTPUT = (
    "type=oci,tar=true,oci-mediatypes=true,compression=gzip,force-compression=true,dest=<per-architecture path>"
)
OCI_PRODUCER_CONTRACT = {
    "platform_override": "linux/<architecture>",
    "output": OCI_PRODUCER_OUTPUT,
    "target_tags": "absent",
    "exporter_name": "absent",
    "user_annotations": "absent",
    "provenance": "disabled",
    "sbom": "disabled",
    "source_date_epoch": str(OCI_SOURCE_DATE_EPOCH),
}


@dataclass(frozen=True)
class OciLimits:
    outer_archive_bytes: int = 1_073_741_824
    outer_member_bytes: int = 805_306_368
    outer_individual_bytes: int = 536_870_912
    compressed_layer_bytes: int = 402_653_184
    outer_member_count: int = 256
    json_document_bytes: int = 1_048_576
    json_nesting_depth: int = 32
    json_members: int = 4096
    json_string_bytes: int = 65_536
    decoded_layer_bytes: int = 2_147_483_648
    layer_regular_bytes: int = 1_610_612_736
    layer_member_count: int = 500_000
    path_bytes: int = 4096
    link_bytes: int = 4096
    pax_records: int = 64
    pax_key_bytes: int = 256
    pax_value_bytes: int = 8192
    annotation_count: int = 16
    annotation_key_bytes: int = 256
    annotation_value_bytes: int = 4096
    descriptor_bytes: int = 536_870_912
    xattr_count: int = 64
    xattr_name_bytes: int = 256
    xattr_value_bytes: int = 8192


OCI_LIMITS = OciLimits()


def assert_oci_limit_ordering(limits: OciLimits = OCI_LIMITS) -> None:
    if not (
        limits.outer_archive_bytes
        > limits.outer_member_bytes
        > limits.outer_individual_bytes
        > limits.compressed_layer_bytes
    ):
        raise ReproError("OCI production outer byte limits are not strictly ordered")
    if not limits.decoded_layer_bytes > limits.layer_regular_bytes:
        raise ReproError("OCI production decoded byte limits are not strictly ordered")


OCI_GUARD_REASONS: dict[str, str] = {
    "O01.outer_archive_bytes": "outer OCI archive exceeds 1073741824 bytes",
    "O02.outer_compressed": "outer OCI archive must be an uncompressed tar",
    "O03.outer_tar": "outer OCI archive is not a valid tar",
    "O04.outer_member_count": "outer OCI archive exceeds 256 members",
    "O05.outer_path_bytes": "outer member name exceeds 4096 UTF-8 bytes",
    "O06.outer_absolute": "outer member name is absolute",
    "O07.outer_traversal": "outer member name contains a parent traversal",
    "O08.outer_duplicate": "outer member names collide after normalization",
    "O09.outer_canonical": "outer member name is not canonical",
    "O10.outer_individual_bytes": "outer member exceeds 536870912 bytes",
    "O11.outer_member_bytes": "aggregate consumed outer member bytes exceed 805306368 bytes",
    "O12.outer_consumed_size": "outer member consumed size differs from its tar header",
    "O13.outer_unexpected": "outer OCI archive contains an unexpected member",
    "O14.outer_directory_type": "OCI blob directory entry has the wrong member type",
    "O15.outer_unreferenced_blob": "outer OCI archive contains an unreferenced blob",
    "L01.layout_missing": "OCI layout marker is missing",
    "L02.layout_regular": "OCI layout marker must be a regular file",
    "L03.layout_json": "OCI layout marker is malformed JSON",
    "L04.layout_object": "OCI layout marker must be a JSON object",
    "L05.layout_keys": "OCI layout marker has an invalid key set",
    "L06.layout_version": "OCI layout imageLayoutVersion must equal 1.0.0",
    "J01.json_bytes": "JSON document exceeds 1048576 bytes",
    "J02.json_duplicate": "JSON document contains a duplicate object key",
    "J03.json_nan": "JSON document contains NaN",
    "J04.json_infinity": "JSON document contains Infinity",
    "J05.json_depth": "JSON document exceeds nesting depth 32",
    "J06.json_members": "JSON object or array exceeds 4096 members",
    "J07.json_string_bytes": "JSON string exceeds 65536 UTF-8 bytes",
    "I01.index_missing": "index.json is missing",
    "I02.index_regular": "index.json must be a regular file",
    "I03.index_json": "index.json is malformed JSON",
    "I04.index_object": "index.json must be a JSON object",
    "I05.index_keys": "index.json has an invalid key set",
    "I06.index_schema": "index.json schemaVersion must be integer 2",
    "I07.index_media_type": "index.json mediaType must be application/vnd.oci.image.index.v1+json",
    "I08.index_annotations": "index.json annotations are not permitted",
    "I09.index_artifact_type": "index.json artifactType is not permitted",
    "I10.index_subject": "index.json subject is not permitted",
    "I11.index_manifests_type": "index.json manifests must be an array",
    "I12.index_manifests_zero": "index.json must contain one manifest descriptor, not zero",
    "I13.index_manifests_multiple": "index.json must contain exactly one manifest descriptor",
    "D01.child_object": "index manifest descriptor must be a JSON object",
    "D02.child_keys": "index manifest descriptor has an invalid key set",
    "D03.child_media_type": "index manifest descriptor has the wrong mediaType",
    "D04.child_platform_missing": "index manifest descriptor platform is required",
    "D05.child_platform_type": "index manifest descriptor platform must be a JSON object",
    "D06.child_platform_keys": "index manifest descriptor platform has an invalid key set",
    "D07.child_platform_os": "index manifest descriptor platform os must match linux",
    "D08.child_platform_arch": "index manifest descriptor platform architecture does not match the request",
    "D09.child_urls": "index manifest descriptor urls are not permitted",
    "D10.child_data": "index manifest descriptor data is not permitted",
    "D11.child_artifact_type": "index manifest descriptor artifactType is not permitted",
    "A01.child_annotations_missing": "index manifest descriptor must contain the created annotation",
    "A02.child_annotations_type": "index manifest descriptor annotations must be a JSON object",
    "A03.child_annotations_count": "index manifest descriptor annotations exceed 16 entries",
    "A04.child_annotation_key_bytes": "index manifest descriptor annotation key exceeds 256 UTF-8 bytes",
    "A05.child_annotation_value_bytes": "index manifest descriptor annotation value exceeds 4096 UTF-8 bytes",
    "A06.child_annotation_unknown": "index manifest descriptor contains an unaccepted annotation",
    "A07.child_annotation_type": "index manifest descriptor annotation value must be a string",
    "A08.child_created_rfc3339": "index manifest descriptor created annotation is not RFC 3339",
    "A09.child_created_epoch": "index manifest descriptor created annotation does not match SOURCE_DATE_EPOCH",
    "D12.child_digest_type": "index manifest descriptor digest must be a string",
    "D13.child_digest_algorithm": "index manifest descriptor digest algorithm must be sha256",
    "D14.child_digest_grammar": "index manifest descriptor digest must match lowercase sha256 grammar",
    "D15.child_size_type": "index manifest descriptor size must be an integer, not a boolean",
    "D16.child_size_negative": "index manifest descriptor size must be non-negative",
    "D17.child_size_ceiling": "index manifest descriptor size exceeds 536870912 bytes",
    "M01.child_blob_missing": "child manifest blob is missing",
    "M02.child_blob_regular": "child manifest blob must be a regular file",
    "M03.child_size": "child manifest blob size does not match its descriptor",
    "M04.child_digest": "child manifest blob digest does not match its descriptor",
    "M05.manifest_json": "child manifest blob is malformed JSON",
    "M06.manifest_object": "child manifest must be a JSON object",
    "M07.manifest_keys": "child manifest has an invalid key set",
    "M08.manifest_schema": "child manifest schemaVersion must be integer 2",
    "M09.manifest_media_type": "child manifest mediaType has the wrong value",
    "M10.manifest_annotations": "child manifest annotations are not permitted",
    "M11.manifest_artifact_type": "child manifest artifactType is not permitted",
    "M12.manifest_subject": "child manifest subject is not permitted",
    "M13.config_object": "config descriptor must be a JSON object",
    "M14.layers_type": "child manifest layers must be an array",
    "M15.layers_zero": "child manifest must contain one layer, not zero",
    "M16.layers_multiple": "child manifest must contain exactly one layer",
    "C01.config_keys": "config descriptor has an invalid key set",
    "C02.config_media_type": "config descriptor has the wrong mediaType",
    "C03.config_urls": "config descriptor urls are not permitted",
    "C04.config_data": "config descriptor data is not permitted",
    "C05.config_artifact_type": "config descriptor artifactType is not permitted",
    "C06.config_annotations": "config descriptor annotations are not permitted",
    "C07.config_platform": "config descriptor platform is not permitted",
    "C08.config_digest_type": "config descriptor digest must be a string",
    "C09.config_digest_algorithm": "config descriptor digest algorithm must be sha256",
    "C10.config_digest_grammar": "config descriptor digest must match lowercase sha256 grammar",
    "C11.config_size_type": "config descriptor size must be an integer, not a boolean",
    "C12.config_size_negative": "config descriptor size must be non-negative",
    "C13.config_size_ceiling": "config descriptor size exceeds 536870912 bytes",
    "C14.config_blob_missing": "config blob is missing",
    "C15.config_blob_regular": "config blob must be a regular file",
    "C16.config_size": "config blob size does not match its descriptor",
    "C17.config_digest": "config blob digest does not match its descriptor",
    "C18.config_json": "config blob is malformed JSON",
    "C19.config_object": "config blob must be a JSON object",
    "C20.config_arch_type": "config architecture must be a string",
    "C21.config_arch": "config architecture does not match the requested architecture",
    "C22.config_os_type": "config os must be a string",
    "C23.config_os": "config os must match linux",
    "C24.rootfs_object": "config rootfs must be a JSON object",
    "C25.rootfs_type": "config rootfs type must equal layers",
    "C26.diff_ids_type": "config rootfs diff_ids must be an array",
    "C27.diff_ids_zero": "config rootfs diff_ids must contain one entry, not zero",
    "C28.diff_ids_multiple": "config rootfs diff_ids must contain exactly one entry",
    "C29.diff_id_type": "config rootfs diff_id must be a string",
    "C30.diff_id_algorithm": "config rootfs diff_id algorithm must be sha256",
    "C31.diff_id_grammar": "config rootfs diff_id must match lowercase sha256 grammar",
    "C32.layer_diff_id_count": "layer descriptor count does not match rootfs diff_id count",
    "Y01.layer_object": "layer descriptor must be a JSON object",
    "Y02.layer_keys": "layer descriptor has an invalid key set",
    "Y03.layer_media_uncompressed": "uncompressed OCI layers are not accepted",
    "Y04.layer_media_zstd": "zstd OCI layers are not accepted",
    "Y05.layer_media_nondistributable": "non-distributable OCI layers are not accepted",
    "Y06.layer_media_type": "layer descriptor has an unaccepted mediaType",
    "Y07.layer_urls": "layer descriptor urls are not permitted",
    "Y08.layer_data": "layer descriptor data is not permitted",
    "Y09.layer_artifact_type": "layer descriptor artifactType is not permitted",
    "Y10.layer_annotations": "layer descriptor annotations are not permitted",
    "Y11.layer_platform": "layer descriptor platform is not permitted",
    "Y12.layer_digest_type": "layer descriptor digest must be a string",
    "Y13.layer_digest_algorithm": "layer descriptor digest algorithm must be sha256",
    "Y14.layer_digest_grammar": "layer descriptor digest must match lowercase sha256 grammar",
    "Y15.layer_size_type": "layer descriptor size must be an integer, not a boolean",
    "Y16.layer_size_negative": "layer descriptor size must be non-negative",
    "Y17.layer_size_ceiling": "layer descriptor size exceeds 536870912 bytes",
    "Y18.layer_blob_missing": "layer blob is missing",
    "Y19.layer_blob_regular": "layer blob must be a regular file",
    "Y20.layer_size": "layer blob size does not match its descriptor",
    "Y21.layer_digest": "layer blob digest does not match its descriptor",
    "Y22.compressed_layer_bytes": "compressed layer exceeds 402653184 bytes",
    "Y23.gzip_invalid": "layer blob is not a valid gzip stream",
    "Y24.gzip_truncated": "layer gzip stream did not reach a verified end",
    "Y25.gzip_concatenated": "concatenated gzip members are not accepted",
    "Y26.gzip_trailing": "bytes after the gzip stream are not accepted",
    "Y27.decoded_layer_bytes": "decoded layer exceeds 2147483648 bytes",
    "Y28.diff_id": "decoded layer digest does not match config rootfs diff_id",
    "T01.layer_tar": "decoded layer is not a valid tar archive",
    "T02.layer_member_count": "decoded layer exceeds 500000 members",
    "T03.inner_path_bytes": "layer member name exceeds 4096 UTF-8 bytes",
    "T04.inner_absolute": "layer member name is absolute",
    "T05.inner_traversal": "layer member name contains a parent traversal",
    "T06.inner_duplicate": "layer member names collide after normalization",
    "T07.inner_canonical": "layer member name is not canonical",
    "T08.link_bytes": "layer link target exceeds 4096 UTF-8 bytes",
    "T09.symlink_escape": "layer symlink target escapes the logical root",
    "T10.hardlink_escape": "layer hardlink target escapes the logical root",
    "T11.hardlink_missing": "layer hardlink target is absent from the archive",
    "T12.hardlink_cycle": "layer hardlinks form a cycle",
    "T13.layer_consumed_size": "layer member consumed size differs from its tar header",
    "T14.layer_regular_bytes": "aggregate consumed regular-file bytes exceed 1610612736 bytes",
    "T15.whiteout_entry": "layer contains a .wh. whiteout entry",
    "T16.whiteout_opaque": "layer contains a .wh..wh..opq whiteout entry",
    "T17.fifo": "layer FIFO members are not accepted",
    "T18.character_device": "layer character-device members are not accepted",
    "T19.block_device": "layer block-device members are not accepted",
    "T20.socket": "layer socket members are not accepted",
    "T21.member_type": "layer member type cannot be represented",
    "P01.global_pax": "global PAX headers are not accepted",
    "P02.unknown_pax": "local PAX header contains an unaccepted key",
    "P03.duplicate_pax": "local PAX header contains a duplicate raw key",
    "P04.pax_records": "local PAX header exceeds 64 raw records for one member",
    "P05.pax_key_bytes": "local PAX key exceeds 256 UTF-8 bytes",
    "P06.pax_value_bytes": "local PAX value exceeds 8192 bytes",
    "P07.sparse": "sparse layer members are not accepted",
    "P08.xattr_count": "layer member exceeds 64 extended attributes",
    "P09.xattr_name": "extended attribute name has an unaccepted grammar",
    "P10.xattr_name_bytes": "extended attribute name exceeds 256 UTF-8 bytes",
    "P11.xattr_value_bytes": "extended attribute value exceeds 8192 bytes",
    "R01.schema_missing": "content-identity schema is missing",
    "R02.schema_json": "content-identity schema is malformed JSON",
    "R03.record_missing": "content-identity record is missing",
    "R04.record_empty": "content-identity record is empty",
    "R05.record_json": "content-identity record is malformed JSON",
    "R06.record_schema": "content-identity record does not satisfy its schema",
    "R07.record_platform": "content-identity record platform disagrees with validated config",
    "R08.record_positions": "content-identity layer positions are not contiguous and unique",
    "R09.record_digest": "content-identity record contains a digest with the wrong grammar",
    "R10.record_layer_count": "content-identity layer count disagrees with validated DiffID count",
    "R11.record_checks": "content-identity record check inventory is incomplete",
    "R12.output_exists": "content-identity output already exists",
    "R13.output_parent": "content-identity output parent must be an existing directory",
}


@dataclass(frozen=True)
class OciGuardContext:
    disabled: frozenset[str] = frozenset()


OCI_GUARD_CONTEXT = OciGuardContext()


def oci_guard(guard_id: str, condition: bool, context: OciGuardContext) -> None:
    if guard_id not in OCI_GUARD_REASONS:
        raise ReproError(f"unknown OCI guard ID: {guard_id}")
    if not condition and guard_id not in context.disabled:
        raise ReproError(f"{guard_id}: {OCI_GUARD_REASONS[guard_id]}")


class ReproError(Exception):
    pass


@dataclass(frozen=True)
class BakeInvocation:
    bake_file: Path
    target: str
    variables: tuple[tuple[str, str], ...]
    overrides: tuple[str, ...]
    progress: str

    def command(self, *, print_only: bool = False) -> list[str]:
        command = [
            "docker",
            "buildx",
            "bake",
            "--file",
            str(self.bake_file),
            self.target,
            "--progress",
            self.progress,
        ]
        for override in self.overrides:
            command.extend(["--set", override])
        if print_only:
            command.append("--print")
        return command

    def environment(self) -> dict[str, str]:
        return dict(self.variables)


@dataclass(frozen=True)
class Entry:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    uname: str
    gname: str
    mtime: int
    size: int
    linkname: str
    nlink_group: str
    xattrs: str
    sha256: str | None
    data: bytes | None
    xattr_pairs: tuple[tuple[str, str], ...]


def run(
    command: list[str],
    *,
    cwd: Path,
    capture: bool = False,
    environment: Mapping[str, str] | None = None,
) -> str:
    process_environment = os.environ.copy()
    if environment is not None:
        process_environment.update(environment)
    if capture:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=process_environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ReproError(
                f"command failed ({result.returncode}): {' '.join(command)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result.stdout.strip()

    result = subprocess.run(command, cwd=cwd, env=process_environment, text=True, check=False)
    if result.returncode != 0:
        raise ReproError(f"command failed ({result.returncode}): {' '.join(command)}")
    return ""


def normalize_path(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized or "."


def entry_type(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.ischr():
        return "character-device"
    if member.isblk():
        return "block-device"
    if member.isfifo():
        return "fifo"
    return "other"


def xattr_pairs_from_pax(pax_headers: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    pairs = [
        (key.removeprefix(XATTR_PAX_PREFIX), value)
        for key, value in pax_headers.items()
        if key.startswith(XATTR_PAX_PREFIX)
    ]
    return tuple(sorted(pairs))


def xattrs_field(pairs: tuple[tuple[str, str], ...]) -> str:
    return ";".join(
        f"{name}={hashlib.sha256(value.encode('utf-8', 'surrogateescape')).hexdigest()}" for name, value in pairs
    )


def entry_from_member(member: tarfile.TarInfo, *, data: bytes | None, digest: str | None) -> Entry:
    pairs = xattr_pairs_from_pax(member.pax_headers)
    return Entry(
        path=normalize_path(member.name),
        type=entry_type(member),
        mode=member.mode & 0o7777,
        uid=member.uid,
        gid=member.gid,
        uname=member.uname or "",
        gname=member.gname or "",
        mtime=int(member.mtime),
        size=member.size if member.isfile() else 0,
        linkname=member.linkname or "",
        nlink_group=member.linkname if member.islnk() else "",
        xattrs=xattrs_field(pairs),
        sha256=digest,
        data=data,
        xattr_pairs=pairs,
    )


def load_tar(path: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            data: bytes | None = None
            digest: str | None = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReproError(f"{path}: could not read regular file {member.name}")
                data = extracted.read()
                digest = hashlib.sha256(data).hexdigest()
            elif member.issym() or member.islnk():
                digest = hashlib.sha256((member.linkname or "").encode("utf-8")).hexdigest()

            entry = entry_from_member(member, data=data, digest=digest)
            entries[entry.path] = entry
    return entries


def apply_whiteout(entries: dict[str, Entry], path: str) -> bool:
    parts = path.split("/")
    basename = parts[-1]
    directory = "/".join(parts[:-1])
    if basename == ".wh..wh..opq":
        prefix = f"{directory}/" if directory else ""
        for existing in list(entries):
            if existing.startswith(prefix) and existing != directory:
                del entries[existing]
        return True
    if basename.startswith(".wh."):
        target_name = basename[4:]
        target = f"{directory}/{target_name}" if directory else target_name
        target_prefix = f"{target}/"
        for existing in list(entries):
            if existing == target or existing.startswith(target_prefix):
                del entries[existing]
        return True
    return False


def load_image_rootfs(image_tar: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    with tarfile.open(image_tar, "r:*") as image:
        manifest_member = image.extractfile("manifest.json")
        if manifest_member is None:
            raise ReproError(f"{image_tar}: missing manifest.json")
        manifest = json.loads(manifest_member.read().decode("utf-8"))
        if not isinstance(manifest, list) or not manifest:
            raise ReproError(f"{image_tar}: invalid manifest.json")
        layers = manifest[0].get("Layers")
        if not isinstance(layers, list) or not layers:
            raise ReproError(f"{image_tar}: manifest contains no layers")

        for layer_name in layers:
            layer_file = image.extractfile(layer_name)
            if layer_file is None:
                raise ReproError(f"{image_tar}: missing layer {layer_name}")
            layer_bytes = layer_file.read()
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
                for member in layer:
                    normalized = normalize_path(member.name)
                    if apply_whiteout(entries, normalized):
                        continue
                    data: bytes | None = None
                    digest: str | None = None
                    if member.isfile():
                        extracted = layer.extractfile(member)
                        if extracted is None:
                            raise ReproError(f"{image_tar}: could not read {member.name} from {layer_name}")
                        data = extracted.read()
                        digest = hashlib.sha256(data).hexdigest()
                    elif member.issym() or member.islnk():
                        digest = hashlib.sha256((member.linkname or "").encode("utf-8")).hexdigest()
                    entries[normalized] = entry_from_member(member, data=data, digest=digest)
    return entries


def write_rootfs_tar(entries: dict[str, Entry], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(entries):
            entry = entries[path]
            info = tarfile.TarInfo(path)
            info.mode = entry.mode
            info.uid = entry.uid
            info.gid = entry.gid
            info.uname = entry.uname
            info.gname = entry.gname
            info.mtime = entry.mtime
            if entry.xattr_pairs:
                info.pax_headers = {f"{XATTR_PAX_PREFIX}{name}": value for name, value in entry.xattr_pairs}
            if entry.type == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry.type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.type == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.type == "file":
                payload = entry.data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                archive.addfile(info)


def canonical_rootfs_digest(entries: dict[str, Entry]) -> str:
    """Hash the sorted rootfs entry manifest, not tar bytes.

    Each line is derived only from the Entry dataclass fields:
    path|type|mode-octal|uid|gid|uname|gname|mtime|size|linkname|sha256-or-empty|nlink-group|xattrs.
    The joined UTF-8 text is stable across tarfile format changes because it
    depends on the normalized rootfs entry set rather than archive encoding.
    """

    lines = []
    for path in sorted(entries):
        entry = entries[path]
        lines.append(
            "|".join(
                [
                    entry.path,
                    entry.type,
                    f"{entry.mode:o}",
                    str(entry.uid),
                    str(entry.gid),
                    entry.uname,
                    entry.gname,
                    str(entry.mtime),
                    str(entry.size),
                    entry.linkname,
                    entry.sha256 or "",
                    entry.nlink_group,
                    entry.xattrs,
                ]
            )
        )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


class _DuplicateJsonKeyError(ValueError):
    pass


class _NonFiniteJsonValueError(ValueError):
    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(value)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _json_constant(value: str) -> Any:
    raise _NonFiniteJsonValueError(value)


def _validate_json_resources(value: Any, limits: OciLimits, context: OciGuardContext, depth: int = 1) -> None:
    oci_guard("J05.json_depth", depth <= limits.json_nesting_depth, context)
    if isinstance(value, dict):
        oci_guard("J06.json_members", len(value) <= limits.json_members, context)
        for key, item in value.items():
            oci_guard("J07.json_string_bytes", len(key.encode("utf-8")) <= limits.json_string_bytes, context)
            _validate_json_resources(item, limits, context, depth + 1)
    elif isinstance(value, list):
        oci_guard("J06.json_members", len(value) <= limits.json_members, context)
        for item in value:
            _validate_json_resources(item, limits, context, depth + 1)
    elif isinstance(value, str):
        oci_guard("J07.json_string_bytes", len(value.encode("utf-8")) <= limits.json_string_bytes, context)


def _parse_oci_json(
    payload: bytes,
    malformed_guard: str,
    limits: OciLimits,
    context: OciGuardContext,
) -> Any:
    oci_guard("J01.json_bytes", len(payload) <= limits.json_document_bytes, context)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_constant=_json_constant,
        )
    except _DuplicateJsonKeyError:
        oci_guard("J02.json_duplicate", False, context)
        raise AssertionError("duplicate JSON guard was disabled") from None
    except _NonFiniteJsonValueError as exc:
        guard_id = "J03.json_nan" if exc.value == "NaN" else "J04.json_infinity"
        oci_guard(guard_id, False, context)
        raise AssertionError("non-finite JSON guard was disabled") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        oci_guard(malformed_guard, False, context)
        raise AssertionError("malformed JSON guard was disabled") from None
    _validate_json_resources(value, limits, context)
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], guard_id: str, context: OciGuardContext) -> None:
    oci_guard(guard_id, set(value) == expected, context)


def _validate_descriptor_digest(
    descriptor: dict[str, Any],
    type_guard: str,
    algorithm_guard: str,
    grammar_guard: str,
    context: OciGuardContext,
) -> str:
    digest = descriptor.get("digest")
    oci_guard(type_guard, isinstance(digest, str), context)
    assert isinstance(digest, str)
    oci_guard(algorithm_guard, digest.startswith("sha256:"), context)
    oci_guard(grammar_guard, OCI_DIGEST.fullmatch(digest) is not None, context)
    return digest


def _validate_descriptor_size(
    descriptor: dict[str, Any],
    type_guard: str,
    negative_guard: str,
    ceiling_guard: str,
    limits: OciLimits,
    context: OciGuardContext,
) -> int:
    size = descriptor.get("size")
    oci_guard(type_guard, type(size) is int, context)
    assert type(size) is int
    oci_guard(negative_guard, size >= 0, context)
    oci_guard(ceiling_guard, size <= limits.descriptor_bytes, context)
    return size


def _normalized_tar_name(name: str) -> str:
    return posixpath.normpath(name.replace("\\", "/"))


def _validate_member_name(
    name: str,
    *,
    seen: set[str],
    outer: bool,
    limits: OciLimits,
    context: OciGuardContext,
) -> str:
    length_guard = "O05.outer_path_bytes" if outer else "T03.inner_path_bytes"
    absolute_guard = "O06.outer_absolute" if outer else "T04.inner_absolute"
    traversal_guard = "O07.outer_traversal" if outer else "T05.inner_traversal"
    duplicate_guard = "O08.outer_duplicate" if outer else "T06.inner_duplicate"
    canonical_guard = "O09.outer_canonical" if outer else "T07.inner_canonical"
    encoded = name.encode("utf-8", "surrogateescape")
    oci_guard(length_guard, len(encoded) <= limits.path_bytes, context)
    replaced = name.replace("\\", "/")
    oci_guard(absolute_guard, not replaced.startswith("/"), context)
    oci_guard(traversal_guard, ".." not in replaced.split("/"), context)
    normalized = _normalized_tar_name(name)
    oci_guard(duplicate_guard, normalized not in seen, context)
    seen.add(normalized)
    canonical = name == normalized and name not in {"", "."} and "\\" not in name
    oci_guard(canonical_guard, canonical, context)
    return normalized


class _OuterReader:
    def __init__(
        self,
        archive: tarfile.TarFile,
        members: dict[str, tarfile.TarInfo],
        limits: OciLimits,
        context: OciGuardContext,
    ) -> None:
        self.archive = archive
        self.members = members
        self.limits = limits
        self.context = context
        self.consumed = 0

    def _copy_member(self, member: tarfile.TarInfo, output: Any, digest: Any | None = None) -> int:
        extracted = self.archive.extractfile(member)
        oci_guard("O12.outer_consumed_size", extracted is not None, self.context)
        assert extracted is not None
        consumed = 0
        try:
            while True:
                chunk = extracted.read(1024 * 1024)
                if not chunk:
                    break
                consumed += len(chunk)
                self.consumed += len(chunk)
                oci_guard("O11.outer_member_bytes", self.consumed <= self.limits.outer_member_bytes, self.context)
                output.write(chunk)
                if digest is not None:
                    digest.update(chunk)
        except (OSError, tarfile.TarError):
            oci_guard("O12.outer_consumed_size", False, self.context)
            raise AssertionError("outer consumed-size guard was disabled") from None
        oci_guard("O12.outer_consumed_size", consumed == member.size, self.context)
        return consumed

    def read_bytes(self, name: str, missing_guard: str, regular_guard: str) -> bytes:
        member = self.members.get(name)
        oci_guard(missing_guard, member is not None, self.context)
        assert member is not None
        oci_guard(regular_guard, member.isfile(), self.context)
        oci_guard("O10.outer_individual_bytes", member.size <= self.limits.outer_individual_bytes, self.context)
        output = io.BytesIO()
        self._copy_member(member, output)
        return output.getvalue()

    def read_blob(
        self,
        descriptor: dict[str, Any],
        *,
        missing_guard: str,
        regular_guard: str,
        size_guard: str,
        digest_guard: str,
        compressed: bool = False,
    ) -> tempfile.SpooledTemporaryFile[bytes]:
        digest = cast(str, descriptor["digest"])
        size = cast(int, descriptor["size"])
        name = f"blobs/sha256/{digest.removeprefix('sha256:')}"
        member = self.members.get(name)
        oci_guard(missing_guard, member is not None, self.context)
        assert member is not None
        oci_guard(regular_guard, member.isfile(), self.context)
        oci_guard("O10.outer_individual_bytes", member.size <= self.limits.outer_individual_bytes, self.context)
        if compressed:
            oci_guard("Y22.compressed_layer_bytes", member.size <= self.limits.compressed_layer_bytes, self.context)
        oci_guard(size_guard, member.size == size, self.context)
        spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")  # noqa: SIM115
        hasher = hashlib.sha256()
        consumed = self._copy_member(member, spool, hasher)
        oci_guard(size_guard, consumed == size, self.context)
        oci_guard(digest_guard, f"sha256:{hasher.hexdigest()}" == digest, self.context)
        spool.seek(0)
        return spool


def _open_outer_archive(
    path: Path,
    limits: OciLimits,
    context: OciGuardContext,
) -> tuple[tarfile.TarFile, dict[str, tarfile.TarInfo]]:
    try:
        archive_size = path.stat().st_size
    except OSError:
        oci_guard("O03.outer_tar", False, context)
        raise AssertionError("outer tar guard was disabled") from None
    oci_guard("O01.outer_archive_bytes", archive_size <= limits.outer_archive_bytes, context)
    try:
        archive = tarfile.open(path, "r:")  # noqa: SIM115
    except (OSError, tarfile.TarError):
        try:
            with tarfile.open(path, "r:*"):
                pass
        except (OSError, tarfile.TarError):
            oci_guard("O03.outer_tar", False, context)
        else:
            oci_guard("O02.outer_compressed", False, context)
        raise AssertionError("outer archive guard was disabled") from None
    try:
        members_list = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        archive.close()
        guard_id = "O12.outer_consumed_size" if "unexpected end" in str(exc).lower() else "O03.outer_tar"
        oci_guard(guard_id, False, context)
        raise AssertionError("outer member scan guard was disabled") from None
    oci_guard("O04.outer_member_count", len(members_list) <= limits.outer_member_count, context)
    seen: set[str] = set()
    members: dict[str, tarfile.TarInfo] = {}
    for member in members_list:
        normalized = _validate_member_name(member.name, seen=seen, outer=True, limits=limits, context=context)
        oci_guard("O10.outer_individual_bytes", member.size <= limits.outer_individual_bytes, context)
        if normalized in {"blobs", "blobs/sha256"}:
            oci_guard("O14.outer_directory_type", member.isdir(), context)
        elif normalized in {"oci-layout", "index.json"} or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", normalized):
            pass
        else:
            oci_guard("O13.outer_unexpected", False, context)
        members[normalized] = member
    return archive, members


def _validate_child_descriptor(
    descriptor: Any,
    architecture: str,
    limits: OciLimits,
    context: OciGuardContext,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    oci_guard("D01.child_object", isinstance(descriptor, dict), context)
    assert isinstance(descriptor, dict)
    for field, guard_id in [
        ("urls", "D09.child_urls"),
        ("data", "D10.child_data"),
        ("artifactType", "D11.child_artifact_type"),
    ]:
        oci_guard(guard_id, field not in descriptor, context)
    oci_guard("D04.child_platform_missing", "platform" in descriptor, context)
    oci_guard("A01.child_annotations_missing", "annotations" in descriptor, context)
    _exact_keys(descriptor, {"mediaType", "digest", "size", "platform", "annotations"}, "D02.child_keys", context)
    oci_guard("D03.child_media_type", descriptor.get("mediaType") == OCI_MANIFEST_MEDIA_TYPE, context)
    platform = descriptor.get("platform")
    oci_guard("D05.child_platform_type", isinstance(platform, dict), context)
    assert isinstance(platform, dict)
    _exact_keys(platform, {"os", "architecture"}, "D06.child_platform_keys", context)
    oci_guard("D07.child_platform_os", platform.get("os") == "linux", context)
    oci_guard("D08.child_platform_arch", platform.get("architecture") == architecture, context)
    annotations = descriptor.get("annotations")
    oci_guard("A02.child_annotations_type", isinstance(annotations, dict), context)
    assert isinstance(annotations, dict)
    oci_guard("A03.child_annotations_count", len(annotations) <= limits.annotation_count, context)
    for key, value in annotations.items():
        oci_guard(
            "A04.child_annotation_key_bytes",
            len(key.encode("utf-8")) <= limits.annotation_key_bytes,
            context,
        )
        oci_guard("A07.child_annotation_type", isinstance(value, str), context)
        assert isinstance(value, str)
        oci_guard(
            "A05.child_annotation_value_bytes",
            len(value.encode("utf-8")) <= limits.annotation_value_bytes,
            context,
        )
    oci_guard("A06.child_annotation_unknown", set(annotations) == {"org.opencontainers.image.created"}, context)
    created = annotations.get("org.opencontainers.image.created")
    oci_guard("A07.child_annotation_type", isinstance(created, str), context)
    assert isinstance(created, str)
    try:
        parsed_created = dt.datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        oci_guard("A08.child_created_rfc3339", False, context)
        raise AssertionError("created RFC 3339 guard was disabled") from None
    oci_guard("A08.child_created_rfc3339", True, context)
    oci_guard("A09.child_created_epoch", int(parsed_created.timestamp()) == OCI_SOURCE_DATE_EPOCH, context)
    _validate_descriptor_digest(
        descriptor,
        "D12.child_digest_type",
        "D13.child_digest_algorithm",
        "D14.child_digest_grammar",
        context,
    )
    _validate_descriptor_size(
        descriptor,
        "D15.child_size_type",
        "D16.child_size_negative",
        "D17.child_size_ceiling",
        limits,
        context,
    )
    accepted = [
        {
            "location": "index.manifests[0]",
            "key": "org.opencontainers.image.created",
            "value": created,
        }
    ]
    return cast(dict[str, Any], descriptor), accepted


def _validate_embedded_descriptor(
    descriptor: Any,
    *,
    site: str,
    limits: OciLimits,
    context: OciGuardContext,
) -> dict[str, Any]:
    is_config = site == "config"
    object_guard = "M13.config_object" if is_config else "Y01.layer_object"
    prefix = "C" if is_config else "Y"
    oci_guard(object_guard, isinstance(descriptor, dict), context)
    assert isinstance(descriptor, dict)
    guards = {
        "urls": f"{prefix}03.config_urls" if is_config else "Y07.layer_urls",
        "data": f"{prefix}04.config_data" if is_config else "Y08.layer_data",
        "artifactType": f"{prefix}05.config_artifact_type" if is_config else "Y09.layer_artifact_type",
        "annotations": f"{prefix}06.config_annotations" if is_config else "Y10.layer_annotations",
        "platform": f"{prefix}07.config_platform" if is_config else "Y11.layer_platform",
    }
    for field, guard_id in guards.items():
        oci_guard(guard_id, field not in descriptor, context)
    keys_guard = "C01.config_keys" if is_config else "Y02.layer_keys"
    _exact_keys(descriptor, {"mediaType", "digest", "size"}, keys_guard, context)
    if is_config:
        oci_guard("C02.config_media_type", descriptor.get("mediaType") == OCI_CONFIG_MEDIA_TYPE, context)
        _validate_descriptor_digest(
            descriptor,
            "C08.config_digest_type",
            "C09.config_digest_algorithm",
            "C10.config_digest_grammar",
            context,
        )
        _validate_descriptor_size(
            descriptor,
            "C11.config_size_type",
            "C12.config_size_negative",
            "C13.config_size_ceiling",
            limits,
            context,
        )
    else:
        media_type = descriptor.get("mediaType")
        if media_type == "application/vnd.oci.image.layer.v1.tar":
            oci_guard("Y03.layer_media_uncompressed", False, context)
        elif media_type == "application/vnd.oci.image.layer.v1.tar+zstd":
            oci_guard("Y04.layer_media_zstd", False, context)
        elif media_type in {
            "application/vnd.oci.image.layer.nondistributable.v1.tar",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        }:
            oci_guard("Y05.layer_media_nondistributable", False, context)
        else:
            oci_guard("Y06.layer_media_type", media_type == OCI_LAYER_MEDIA_TYPE, context)
        _validate_descriptor_digest(
            descriptor,
            "Y12.layer_digest_type",
            "Y13.layer_digest_algorithm",
            "Y14.layer_digest_grammar",
            context,
        )
        _validate_descriptor_size(
            descriptor,
            "Y15.layer_size_type",
            "Y16.layer_size_negative",
            "Y17.layer_size_ceiling",
            limits,
            context,
        )
    return cast(dict[str, Any], descriptor)


def _decode_gzip_layer(
    compressed: Any,
    expected_diff_id: str,
    limits: OciLimits,
    context: OciGuardContext,
) -> tempfile.SpooledTemporaryFile[bytes]:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decoded = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b")  # noqa: SIM115
    hasher = hashlib.sha256()
    decoded_size = 0
    ended = False
    try:
        while True:
            chunk = compressed.read(1024 * 1024)
            if not chunk:
                break
            if ended:
                guard_id = "Y25.gzip_concatenated" if chunk.startswith(b"\x1f\x8b") else "Y26.gzip_trailing"
                oci_guard(guard_id, False, context)
                raise AssertionError("gzip trailing-data guard was disabled")
            pending = chunk
            while pending:
                remaining = limits.decoded_layer_bytes - decoded_size + 1
                output = decoder.decompress(pending, min(1024 * 1024, remaining))
                pending = decoder.unconsumed_tail
                if output:
                    decoded_size += len(output)
                    oci_guard("Y27.decoded_layer_bytes", decoded_size <= limits.decoded_layer_bytes, context)
                    hasher.update(output)
                    decoded.write(output)
                if decoder.eof:
                    trailing = decoder.unused_data
                    if trailing:
                        guard_id = "Y25.gzip_concatenated" if trailing.startswith(b"\x1f\x8b") else "Y26.gzip_trailing"
                        oci_guard(guard_id, False, context)
                        raise AssertionError("gzip trailing-data guard was disabled")
                    ended = True
                    pending = b""
    except zlib.error:
        oci_guard("Y23.gzip_invalid", False, context)
        raise AssertionError("invalid gzip guard was disabled") from None
    oci_guard("Y24.gzip_truncated", decoder.eof, context)
    actual_diff_id = f"sha256:{hasher.hexdigest()}"
    oci_guard("Y28.diff_id", actual_diff_id == expected_diff_id, context)
    decoded.seek(0)
    return decoded


def _tar_number(field: bytes) -> int:
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped:
        return 0
    if stripped[0] & 0x80:
        return int.from_bytes(field, "big", signed=True)
    return int(stripped, 8)


def _parse_pax_records(payload: bytes) -> list[tuple[str, str, int, int]]:
    records: list[tuple[str, str, int, int]] = []
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        if space < 0:
            raise ValueError("PAX record has no length separator")
        length = int(payload[offset:space])
        if length <= 0 or offset + length > len(payload):
            raise ValueError("PAX record length is invalid")
        raw = payload[space + 1 : offset + length]
        if not raw.endswith(b"\n") or b"=" not in raw:
            raise ValueError("PAX record is malformed")
        key_bytes, value_bytes = raw[:-1].split(b"=", 1)
        key = key_bytes.decode("utf-8", "surrogateescape")
        value = value_bytes.decode("utf-8", "surrogateescape")
        records.append((key, value, len(key_bytes), len(value_bytes)))
        offset += length
    return records


def _validate_pax_records(
    records: list[tuple[str, str, int, int]],
    limits: OciLimits,
    context: OciGuardContext,
) -> None:
    keys = [key for key, _, _, _ in records]
    oci_guard("P03.duplicate_pax", len(keys) == len(set(keys)), context)
    xattrs = [record for record in records if record[0].startswith(XATTR_PAX_PREFIX)]
    oci_guard("P08.xattr_count", len(xattrs) <= limits.xattr_count, context)
    for key, _, key_size, value_size in records:
        if key.startswith(XATTR_PAX_PREFIX):
            name = key.removeprefix(XATTR_PAX_PREFIX)
            oci_guard("P09.xattr_name", OCI_XATTR_NAME.fullmatch(name) is not None, context)
            oci_guard(
                "P10.xattr_name_bytes",
                len(name.encode("utf-8", "surrogateescape")) <= limits.xattr_name_bytes,
                context,
            )
            oci_guard("P11.xattr_value_bytes", value_size <= limits.xattr_value_bytes, context)
        else:
            oci_guard("P05.pax_key_bytes", key_size <= limits.pax_key_bytes, context)
            oci_guard("P06.pax_value_bytes", value_size <= limits.pax_value_bytes, context)
            oci_guard(
                "P02.unknown_pax",
                key in {"path", "linkpath", "size", "mtime", "uid", "gid", "uname", "gname"},
                context,
            )
        if key.startswith(XATTR_PAX_PREFIX):
            oci_guard("P05.pax_key_bytes", key_size <= limits.pax_key_bytes, context)
            oci_guard("P06.pax_value_bytes", value_size <= limits.pax_value_bytes, context)
    oci_guard("P04.pax_records", len(records) <= limits.pax_records, context)


def _scan_raw_layer_tar(decoded: Any, limits: OciLimits, context: OciGuardContext) -> None:
    decoded.seek(0)
    pending_records: list[tuple[str, str, int, int]] = []
    zero_blocks = 0
    try:
        while True:
            header = decoded.read(512)
            if not header:
                break
            if len(header) != 512:
                oci_guard("T13.layer_consumed_size", False, context)
                raise AssertionError("layer header-size guard was disabled")
            if header == b"\0" * 512:
                zero_blocks += 1
                if zero_blocks == 2:
                    break
                continue
            zero_blocks = 0
            size = _tar_number(header[124:136])
            typeflag = header[156:157] or tarfile.REGTYPE
            payload = decoded.read(size)
            if len(payload) != size:
                oci_guard("T13.layer_consumed_size", False, context)
                raise AssertionError("layer payload-size guard was disabled")
            padding = (-size) % 512
            if len(decoded.read(padding)) != padding:
                oci_guard("T13.layer_consumed_size", False, context)
                raise AssertionError("layer padding-size guard was disabled")
            if typeflag == tarfile.XGLTYPE:
                oci_guard("P01.global_pax", False, context)
            elif typeflag == tarfile.XHDTYPE:
                pending_records.extend(_parse_pax_records(payload))
            else:
                if typeflag == tarfile.GNUTYPE_SPARSE:
                    oci_guard("P07.sparse", False, context)
                _validate_pax_records(pending_records, limits, context)
                pending_records = []
    except (ValueError, OverflowError):
        oci_guard("T01.layer_tar", False, context)
        raise AssertionError("raw layer tar guard was disabled") from None
    decoded.seek(0)


def _resolved_symlink_target(path: str, target: str) -> str:
    return posixpath.normpath(posixpath.join(posixpath.dirname(path), target.replace("\\", "/")))


def _resolved_hardlink_target(target: str) -> str:
    return posixpath.normpath(target.replace("\\", "/"))


def _target_stays_root(target: str) -> bool:
    return target not in {"", ".", ".."} and not target.startswith("/") and not target.startswith("../")


def _validate_hardlink_graph(entries: dict[str, Entry], context: OciGuardContext) -> None:
    hardlinks = {
        path: _resolved_hardlink_target(entry.linkname) for path, entry in entries.items() if entry.type == "hardlink"
    }
    for target in hardlinks.values():
        oci_guard("T11.hardlink_missing", target in entries, context)
    for start in hardlinks:
        seen: set[str] = set()
        current = start
        while current in hardlinks:
            if current in seen:
                oci_guard("T12.hardlink_cycle", False, context)
                break
            seen.add(current)
            current = hardlinks[current]


def _load_validated_layer_tar(
    decoded: Any,
    limits: OciLimits,
    context: OciGuardContext,
) -> dict[str, Entry]:
    _scan_raw_layer_tar(decoded, limits, context)
    try:
        archive = tarfile.open(fileobj=decoded, mode="r:")  # noqa: SIM115
        members = archive.getmembers()
    except (OSError, tarfile.TarError):
        oci_guard("T01.layer_tar", False, context)
        raise AssertionError("decoded tar guard was disabled") from None
    oci_guard("T02.layer_member_count", len(members) <= limits.layer_member_count, context)
    seen: set[str] = set()
    entries: dict[str, Entry] = {}
    regular_bytes = 0
    for member in members:
        normalized = _validate_member_name(member.name, seen=seen, outer=False, limits=limits, context=context)
        basename = posixpath.basename(normalized)
        oci_guard("T16.whiteout_opaque", basename != ".wh..wh..opq", context)
        oci_guard("T15.whiteout_entry", not basename.startswith(".wh."), context)
        if member.issparse():
            oci_guard("P07.sparse", False, context)
        if member.isfifo():
            oci_guard("T17.fifo", False, context)
        elif member.ischr():
            oci_guard("T18.character_device", False, context)
        elif member.isblk():
            oci_guard("T19.block_device", False, context)
        elif member.type == b"s":
            oci_guard("T20.socket", False, context)
        else:
            oci_guard("T21.member_type", member.isfile() or member.isdir() or member.issym() or member.islnk(), context)
        if member.issym() or member.islnk():
            target_bytes = (member.linkname or "").encode("utf-8", "surrogateescape")
            oci_guard("T08.link_bytes", len(target_bytes) <= limits.link_bytes, context)
            if member.issym():
                oci_guard(
                    "T09.symlink_escape",
                    _target_stays_root(_resolved_symlink_target(normalized, member.linkname)),
                    context,
                )
            else:
                oci_guard(
                    "T10.hardlink_escape", _target_stays_root(_resolved_hardlink_target(member.linkname)), context
                )
        digest: str | None = None
        if member.isfile():
            extracted = archive.extractfile(member)
            oci_guard("T13.layer_consumed_size", extracted is not None, context)
            assert extracted is not None
            hasher = hashlib.sha256()
            consumed = 0
            try:
                while True:
                    chunk = extracted.read(1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    regular_bytes += len(chunk)
                    oci_guard("T14.layer_regular_bytes", regular_bytes <= limits.layer_regular_bytes, context)
                    hasher.update(chunk)
            except (OSError, tarfile.TarError):
                oci_guard("T13.layer_consumed_size", False, context)
                raise AssertionError("layer consumed-size guard was disabled") from None
            oci_guard("T13.layer_consumed_size", consumed == member.size, context)
            digest = hasher.hexdigest()
        elif member.issym() or member.islnk():
            digest = hashlib.sha256((member.linkname or "").encode("utf-8")).hexdigest()
        entries[normalized] = entry_from_member(member, data=None, digest=digest)
    archive.close()
    _validate_hardlink_graph(entries, context)
    return entries


def _schema_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return type(value) is int
    return False


def _validate_record_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    expected = schema.get("type")
    if isinstance(expected, str) and not _schema_type_matches(instance, expected):
        raise ReproError(f"{path} must be JSON type {expected}")
    if "const" in schema and instance != schema["const"]:
        raise ReproError(f"{path} must equal schema const")
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        raise ReproError(f"{path} must be one of the schema enum values")
    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, instance) is None:
            raise ReproError(f"{path} does not match schema pattern")
        maximum_length = schema.get("maxLength")
        if type(maximum_length) is int and len(instance) > maximum_length:
            raise ReproError(f"{path} exceeds schema maxLength")
    if type(instance) is int:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if type(minimum) is int and instance < minimum:
            raise ReproError(f"{path} is below schema minimum")
        if type(maximum) is int and instance > maximum:
            raise ReproError(f"{path} exceeds schema maximum")
    if isinstance(instance, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if type(minimum_items) is int and len(instance) < minimum_items:
            raise ReproError(f"{path} has too few items")
        if type(maximum_items) is int and len(instance) > maximum_items:
            raise ReproError(f"{path} has too many items")
        if schema.get("uniqueItems") is True:
            markers = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(markers) != len(set(markers)):
                raise ReproError(f"{path} items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                _validate_record_schema(item, item_schema, f"{path}[{index}]")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    raise ReproError(f"{path} missing required property {key}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ReproError(f"{path} schema properties must be an object")
        for key, value in instance.items():
            child_path = f"{path}.{key}"
            if key in properties and isinstance(properties[key], dict):
                _validate_record_schema(value, properties[key], child_path)
            elif schema.get("additionalProperties", True) is False:
                raise ReproError(f"{child_path} is not allowed by schema")


def _load_content_identity_schema(
    schema_path: Path = OCI_CONTENT_IDENTITY_SCHEMA,
    context: OciGuardContext = OCI_GUARD_CONTEXT,
) -> dict[str, Any]:
    try:
        payload = schema_path.read_bytes()
    except OSError:
        oci_guard("R01.schema_missing", False, context)
        raise AssertionError("schema-missing guard was disabled") from None
    try:
        schema = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_pairs, parse_constant=_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError, _NonFiniteJsonValueError):
        oci_guard("R02.schema_json", False, context)
        raise AssertionError("schema JSON guard was disabled") from None
    oci_guard("R02.schema_json", isinstance(schema, dict), context)
    return cast(dict[str, Any], schema)


def validate_content_identity_record(
    record: dict[str, Any],
    *,
    architecture: str,
    config_platform: tuple[str, str],
    diff_ids: list[str],
    schema_path: Path = OCI_CONTENT_IDENTITY_SCHEMA,
    context: OciGuardContext = OCI_GUARD_CONTEXT,
) -> None:
    schema = _load_content_identity_schema(schema_path, context)
    if "platform" in record:
        expected_platform = {"os": config_platform[0], "architecture": config_platform[1]}
        oci_guard(
            "R07.record_platform",
            record.get("platform") == expected_platform == {"os": "linux", "architecture": architecture},
            context,
        )
    layers_value = record.get("layers")
    if isinstance(layers_value, list) and all(isinstance(layer, dict) for layer in layers_value):
        layers = cast(list[dict[str, Any]], layers_value)
        positions = [layer.get("position") for layer in layers]
        oci_guard(
            "R08.record_positions",
            positions == list(range(len(layers))) and len(positions) == len(set(positions)),
            context,
        )
        digest_values: list[Any] = []
        for name in ("index", "child", "config"):
            descriptor = record.get(name)
            if isinstance(descriptor, dict) and "digest" in descriptor:
                digest_values.append(descriptor["digest"])
        for layer in layers:
            if "digest" in layer:
                digest_values.append(layer["digest"])
            if "diff_id" in layer:
                digest_values.append(layer["diff_id"])
        if digest_values:
            oci_guard(
                "R09.record_digest",
                all(isinstance(value, str) and OCI_DIGEST.fullmatch(value) for value in digest_values),
                context,
            )
        if all("diff_id" in layer for layer in layers):
            record_diff_ids = [cast(str, layer["diff_id"]) for layer in layers]
            oci_guard(
                "R10.record_layer_count",
                len(layers) == len(diff_ids) == 1 and record_diff_ids == diff_ids,
                context,
            )
    checks_value = record.get("checks")
    if isinstance(checks_value, list) and all(isinstance(item, dict) for item in checks_value):
        check_ids = [cast(dict[str, Any], item).get("id") for item in checks_value]
        oci_guard("R11.record_checks", check_ids == sorted(OCI_GUARD_REASONS), context)
    try:
        _validate_record_schema(record, schema)
    except ReproError:
        oci_guard("R06.record_schema", False, context)
        raise AssertionError("record schema guard was disabled") from None


def load_content_identity_record(
    path: Path,
    *,
    architecture: str,
    config_platform: tuple[str, str],
    diff_ids: list[str],
    schema_path: Path = OCI_CONTENT_IDENTITY_SCHEMA,
    context: OciGuardContext = OCI_GUARD_CONTEXT,
) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError:
        oci_guard("R03.record_missing", False, context)
        raise AssertionError("record-missing guard was disabled") from None
    oci_guard("R04.record_empty", bool(payload), context)
    try:
        record = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_pairs, parse_constant=_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKeyError, _NonFiniteJsonValueError):
        oci_guard("R05.record_json", False, context)
        raise AssertionError("record JSON guard was disabled") from None
    oci_guard("R06.record_schema", isinstance(record, dict), context)
    assert isinstance(record, dict)
    validate_content_identity_record(
        record,
        architecture=architecture,
        config_platform=config_platform,
        diff_ids=diff_ids,
        schema_path=schema_path,
        context=context,
    )
    return cast(dict[str, Any], record)


def emit_content_identity_record(
    record: dict[str, Any],
    output: Path,
    *,
    architecture: str,
    config_platform: tuple[str, str],
    diff_ids: list[str],
    schema_path: Path = OCI_CONTENT_IDENTITY_SCHEMA,
    context: OciGuardContext = OCI_GUARD_CONTEXT,
) -> None:
    """Validate and atomically emit one record for a single-writer job.

    The destination precheck catches operator error. Concurrent writers are out
    of scope and are not made safe by the subsequent rename.
    """

    validate_content_identity_record(
        record,
        architecture=architecture,
        config_platform=config_platform,
        diff_ids=diff_ids,
        schema_path=schema_path,
        context=context,
    )
    oci_guard("R12.output_exists", not output.exists(), context)
    oci_guard("R13.output_parent", output.parent.is_dir(), context)
    serialized = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
        temporary.rename(output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class OciContentIdentity:
    record: dict[str, Any]
    entries: dict[str, Entry]
    config_platform: tuple[str, str]
    diff_ids: list[str]


def read_oci_content_identity(
    archive_path: Path,
    architecture: str,
    *,
    limits: OciLimits = OCI_LIMITS,
    schema_path: Path = OCI_CONTENT_IDENTITY_SCHEMA,
    context: OciGuardContext = OCI_GUARD_CONTEXT,
) -> OciContentIdentity:
    assert_oci_limit_ordering()
    archive, members = _open_outer_archive(archive_path, limits, context)
    reader = _OuterReader(archive, members, limits, context)
    try:
        layout_payload = reader.read_bytes("oci-layout", "L01.layout_missing", "L02.layout_regular")
        layout = _parse_oci_json(layout_payload, "L03.layout_json", limits, context)
        oci_guard("L04.layout_object", isinstance(layout, dict), context)
        assert isinstance(layout, dict)
        _exact_keys(layout, {"imageLayoutVersion"}, "L05.layout_keys", context)
        oci_guard("L06.layout_version", layout.get("imageLayoutVersion") == OCI_LAYOUT_VERSION, context)

        index_payload = reader.read_bytes("index.json", "I01.index_missing", "I02.index_regular")
        index = _parse_oci_json(index_payload, "I03.index_json", limits, context)
        oci_guard("I04.index_object", isinstance(index, dict), context)
        assert isinstance(index, dict)
        oci_guard("I08.index_annotations", "annotations" not in index, context)
        oci_guard("I09.index_artifact_type", "artifactType" not in index, context)
        oci_guard("I10.index_subject", "subject" not in index, context)
        _exact_keys(index, {"schemaVersion", "mediaType", "manifests"}, "I05.index_keys", context)
        oci_guard("I06.index_schema", type(index.get("schemaVersion")) is int and index["schemaVersion"] == 2, context)
        oci_guard("I07.index_media_type", index.get("mediaType") == OCI_INDEX_MEDIA_TYPE, context)
        manifests = index.get("manifests")
        oci_guard("I11.index_manifests_type", isinstance(manifests, list), context)
        assert isinstance(manifests, list)
        oci_guard("I12.index_manifests_zero", len(manifests) != 0, context)
        oci_guard("I13.index_manifests_multiple", len(manifests) == 1, context)
        child_descriptor, annotations = _validate_child_descriptor(manifests[0], architecture, limits, context)

        child_spool = reader.read_blob(
            child_descriptor,
            missing_guard="M01.child_blob_missing",
            regular_guard="M02.child_blob_regular",
            size_guard="M03.child_size",
            digest_guard="M04.child_digest",
        )
        child_payload = child_spool.read()
        child_spool.close()
        manifest = _parse_oci_json(child_payload, "M05.manifest_json", limits, context)
        oci_guard("M06.manifest_object", isinstance(manifest, dict), context)
        assert isinstance(manifest, dict)
        oci_guard("M10.manifest_annotations", "annotations" not in manifest, context)
        oci_guard("M11.manifest_artifact_type", "artifactType" not in manifest, context)
        oci_guard("M12.manifest_subject", "subject" not in manifest, context)
        _exact_keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, "M07.manifest_keys", context)
        oci_guard(
            "M08.manifest_schema",
            type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] == 2,
            context,
        )
        oci_guard("M09.manifest_media_type", manifest.get("mediaType") == OCI_MANIFEST_MEDIA_TYPE, context)
        config_descriptor = _validate_embedded_descriptor(
            manifest.get("config"), site="config", limits=limits, context=context
        )
        layers = manifest.get("layers")
        oci_guard("M14.layers_type", isinstance(layers, list), context)
        assert isinstance(layers, list)
        oci_guard("M15.layers_zero", len(layers) != 0, context)
        oci_guard("M16.layers_multiple", len(layers) == 1, context)
        layer_descriptor = _validate_embedded_descriptor(layers[0], site="layer", limits=limits, context=context)

        config_spool = reader.read_blob(
            config_descriptor,
            missing_guard="C14.config_blob_missing",
            regular_guard="C15.config_blob_regular",
            size_guard="C16.config_size",
            digest_guard="C17.config_digest",
        )
        config_payload = config_spool.read()
        config_spool.close()
        config = _parse_oci_json(config_payload, "C18.config_json", limits, context)
        oci_guard("C19.config_object", isinstance(config, dict), context)
        assert isinstance(config, dict)
        config_arch = config.get("architecture")
        oci_guard("C20.config_arch_type", isinstance(config_arch, str), context)
        oci_guard("C21.config_arch", config_arch == architecture, context)
        config_os = config.get("os")
        oci_guard("C22.config_os_type", isinstance(config_os, str), context)
        oci_guard("C23.config_os", config_os == "linux", context)
        rootfs = config.get("rootfs")
        oci_guard("C24.rootfs_object", isinstance(rootfs, dict), context)
        assert isinstance(rootfs, dict)
        oci_guard("C25.rootfs_type", rootfs.get("type") == "layers", context)
        diff_ids = rootfs.get("diff_ids")
        oci_guard("C26.diff_ids_type", isinstance(diff_ids, list), context)
        assert isinstance(diff_ids, list)
        oci_guard("C27.diff_ids_zero", len(diff_ids) != 0, context)
        if len(diff_ids) == 2:
            oci_guard("C28.diff_ids_multiple", False, context)
        elif len(diff_ids) != 1:
            oci_guard("C32.layer_diff_id_count", len(layers) == len(diff_ids), context)
            oci_guard("C28.diff_ids_multiple", False, context)
        oci_guard("C32.layer_diff_id_count", len(layers) == len(diff_ids), context)
        diff_id = diff_ids[0]
        oci_guard("C29.diff_id_type", isinstance(diff_id, str), context)
        assert isinstance(diff_id, str)
        oci_guard("C30.diff_id_algorithm", diff_id.startswith("sha256:"), context)
        oci_guard("C31.diff_id_grammar", OCI_DIGEST.fullmatch(diff_id) is not None, context)

        layer_spool = reader.read_blob(
            layer_descriptor,
            missing_guard="Y18.layer_blob_missing",
            regular_guard="Y19.layer_blob_regular",
            size_guard="Y20.layer_size",
            digest_guard="Y21.layer_digest",
            compressed=True,
        )
        decoded = _decode_gzip_layer(layer_spool, diff_id, limits, context)
        layer_spool.close()
        entries = _load_validated_layer_tar(decoded, limits, context)
        decoded.close()

        referenced = {
            f"blobs/sha256/{cast(str, child_descriptor['digest']).removeprefix('sha256:')}",
            f"blobs/sha256/{cast(str, config_descriptor['digest']).removeprefix('sha256:')}",
            f"blobs/sha256/{cast(str, layer_descriptor['digest']).removeprefix('sha256:')}",
        }
        actual_blobs = {name for name in members if name.startswith("blobs/sha256/")}
        oci_guard("O15.outer_unreferenced_blob", actual_blobs == referenced, context)
        index_digest = f"sha256:{hashlib.sha256(index_payload).hexdigest()}"
        record: dict[str, Any] = {
            "schema_version": 1,
            "profile_version": OCI_PROFILE_VERSION,
            "platform": {"os": "linux", "architecture": architecture},
            "index": {"digest": index_digest, "size": len(index_payload)},
            "child": {
                "digest": child_descriptor["digest"],
                "size": child_descriptor["size"],
                "media_type": child_descriptor["mediaType"],
            },
            "config": {
                "digest": config_descriptor["digest"],
                "size": config_descriptor["size"],
                "media_type": config_descriptor["mediaType"],
            },
            "layers": [
                {
                    "position": 0,
                    "digest": layer_descriptor["digest"],
                    "size": layer_descriptor["size"],
                    "media_type": layer_descriptor["mediaType"],
                    "diff_id": diff_id,
                }
            ],
            "annotations": annotations,
            "canonical_rootfs_digest": canonical_rootfs_digest(entries),
            "checks": [{"id": guard_id, "result": "pass"} for guard_id in sorted(OCI_GUARD_REASONS)],
        }
        validate_content_identity_record(
            record,
            architecture=architecture,
            config_platform=(cast(str, config_os), cast(str, config_arch)),
            diff_ids=cast(list[str], diff_ids),
            schema_path=schema_path,
            context=context,
        )
        return OciContentIdentity(
            record=record,
            entries=entries,
            config_platform=(cast(str, config_os), cast(str, config_arch)),
            diff_ids=cast(list[str], diff_ids),
        )
    finally:
        archive.close()


def entry_digest(entries: dict[str, Entry], path: str) -> str | None:
    entry = entries.get(path)
    if entry is None or entry.sha256 is None:
        return None
    return entry.sha256


def rootfs_facts(entries: dict[str, Entry]) -> dict[str, str | None]:
    return {
        "rootfs_digest": canonical_rootfs_digest(entries),
        "rpmdb_sha256": entry_digest(entries, RPMDB_PATH),
        "fips_so_sha256": entry_digest(entries, FIPS_SO_PATH),
    }


def add_rootfs_facts(builds: list[dict[str, object]], left: dict[str, Entry], right: dict[str, Entry]) -> None:
    for side, build, entries in zip(("left", "right"), builds, (left, right), strict=True):
        build["side"] = side
        build.update(rootfs_facts(entries))


def require_sha256(value: str, source: str) -> str:
    if SHA256_HEX.fullmatch(value) is None:
        raise ReproError(f"{source} must be a 64-character lowercase sha256")
    return value


def platform_arch(platform: str) -> str:
    prefix = "linux/"
    if not platform.startswith(prefix) or platform == prefix:
        raise ReproError(f"platform must have linux/<arch> form for contract lookup: {platform}")
    return platform.removeprefix(prefix)


def read_contract_expectations(path: Path, platform: str) -> list[tuple[str, str, str]]:
    contract_path = path
    try:
        loaded = json.loads(contract_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReproError(f"missing expectation contract: {contract_path}") from exc
    except OSError as exc:
        raise ReproError(f"could not read expectation contract {contract_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReproError(f"expectation contract {contract_path} is malformed JSON: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ReproError(f"expectation contract {contract_path} must contain a JSON object")

    arch = platform_arch(platform)
    repro = loaded.get("reproducibility")
    if not isinstance(repro, dict):
        raise ReproError(f"missing expected digest for {platform}: reproducibility")

    checks: list[tuple[str, str, str]] = []
    for contract_key, fact_key in [
        ("canonical_rootfs_digest", "rootfs_digest"),
        ("rpmdb_sha256", "rpmdb_sha256"),
    ]:
        values = repro.get(contract_key)
        if not isinstance(values, dict):
            raise ReproError(f"missing expected digest for {platform}: reproducibility.{contract_key}")
        value = values.get(arch)
        if not isinstance(value, str):
            raise ReproError(f"missing expected digest for {platform}: reproducibility.{contract_key}.{arch}")
        source = f"{contract_path}:reproducibility.{contract_key}.{arch}"
        checks.append((fact_key, require_sha256(value, source), str(contract_path)))
    return checks


def collect_expectations(args: argparse.Namespace, contract: Path | None) -> list[tuple[str, str, str]]:
    checks: list[tuple[str, str, str]] = []
    if args.expect_rootfs_digest is not None:
        checks.append(("rootfs_digest", require_sha256(args.expect_rootfs_digest, "--expect-rootfs-digest"), "cli"))
    if args.expect_rpmdb_sha256 is not None:
        checks.append(("rpmdb_sha256", require_sha256(args.expect_rpmdb_sha256, "--expect-rpmdb-sha256"), "cli"))
    if contract is not None:
        checks.extend(read_contract_expectations(contract, args.platform))
    return checks


def assert_expectations(builds: list[dict[str, object]], checks: list[tuple[str, str, str]]) -> None:
    for build in builds:
        side = str(build.get("side", "unknown"))
        for fact_key, expected, source in checks:
            actual = build.get(fact_key)
            if not isinstance(actual, str):
                if fact_key == "rpmdb_sha256":
                    raise ReproError(f"{fact_key} is uncomputable for {side}: missing {RPMDB_PATH}")
                raise ReproError(f"{fact_key} is uncomputable for {side}")
            if actual != expected:
                raise ReproError(f"{fact_key} mismatch for {side}: expected {expected} from {source}, actual {actual}")


def assert_single_rootfs(rootfs_tar: Path, arch: str, contract: Path) -> None:
    try:
        entries = load_tar(rootfs_tar)
    except FileNotFoundError as exc:
        raise ReproError(f"missing rootfs tar: {rootfs_tar}") from exc
    except (OSError, tarfile.TarError) as exc:
        raise ReproError(f"could not read rootfs tar {rootfs_tar}: {exc}") from exc

    facts = rootfs_facts(entries)
    build: dict[str, object] = {"side": f"single rootfs linux/{arch}", **facts}
    assert_expectations([build], read_contract_expectations(contract, f"linux/{arch}"))

    rootfs_digest = facts["rootfs_digest"]
    rpmdb_sha256 = facts["rpmdb_sha256"]
    if not isinstance(rootfs_digest, str) or not isinstance(rpmdb_sha256, str):
        raise ReproError(f"rootfs facts are uncomputable for linux/{arch}")
    print(f"single-rootfs contract assertion passed for linux/{arch}")
    print(f"canonical_rootfs_digest: {rootfs_digest} (matched)")
    print(f"rpmdb_sha256: {rpmdb_sha256} (matched)")


def first_diff(left: bytes, right: bytes) -> dict[str, object]:
    limit = min(len(left), len(right))
    offset = limit
    for index in range(limit):
        if left[index] != right[index]:
            offset = index
            break
    sample_left = left[offset : offset + 16]
    sample_right = right[offset : offset + 16]
    return {
        "offset": offset,
        "left_hex": sample_left.hex(),
        "right_hex": sample_right.hex(),
    }


def content_bytes(entry: Entry) -> bytes:
    if entry.data is not None:
        return entry.data
    if entry.type in {"symlink", "hardlink"}:
        return entry.linkname.encode("utf-8")
    return b""


def compare_entries(left: dict[str, Entry], right: dict[str, Entry]) -> dict[str, Any]:
    differences: list[dict[str, Any]] = []
    identical = 0

    for path in sorted(set(left) | set(right)):
        left_entry = left.get(path)
        right_entry = right.get(path)
        if left_entry is None or right_entry is None:
            present_entry = left_entry or right_entry
            assert present_entry is not None
            differences.append(
                {
                    "path": path,
                    "classification": "present-in-one-only",
                    "reasons": ["present-in-one-only"],
                    "left_present": left_entry is not None,
                    "right_present": right_entry is not None,
                    "differing_bytes": present_entry.size,
                }
            )
            continue

        reasons: list[str] = []
        detail: dict[str, Any] = {}
        differing_bytes = 0

        if left_entry.type != right_entry.type:
            reasons.append("type-differs")
            detail["left_type"] = left_entry.type
            detail["right_type"] = right_entry.type

        if (
            left_entry.mode != right_entry.mode
            or left_entry.uid != right_entry.uid
            or left_entry.gid != right_entry.gid
            or left_entry.uname != right_entry.uname
            or left_entry.gname != right_entry.gname
        ):
            reasons.append("mode-or-owner-differs")
            detail["left_mode"] = oct(left_entry.mode)
            detail["right_mode"] = oct(right_entry.mode)
            detail["left_uid"] = left_entry.uid
            detail["right_uid"] = right_entry.uid
            detail["left_gid"] = left_entry.gid
            detail["right_gid"] = right_entry.gid
            detail["left_uname"] = left_entry.uname
            detail["right_uname"] = right_entry.uname
            detail["left_gname"] = left_entry.gname
            detail["right_gname"] = right_entry.gname

        if left_entry.sha256 != right_entry.sha256 or left_entry.size != right_entry.size:
            reasons.append("content-differs")
            left_bytes = content_bytes(left_entry)
            right_bytes = content_bytes(right_entry)
            detail["left_size"] = len(left_bytes)
            detail["right_size"] = len(right_bytes)
            detail["left_sha256"] = hashlib.sha256(left_bytes).hexdigest()
            detail["right_sha256"] = hashlib.sha256(right_bytes).hexdigest()
            detail["first_diff"] = first_diff(left_bytes, right_bytes)
            differing_bytes = max(len(left_bytes), len(right_bytes))

        if left_entry.nlink_group != right_entry.nlink_group:
            reasons.append("hardlink-group-differs")
            detail["left_nlink_group"] = left_entry.nlink_group
            detail["right_nlink_group"] = right_entry.nlink_group

        if left_entry.xattrs != right_entry.xattrs:
            reasons.append("xattrs-differ")
            detail["left_xattrs"] = left_entry.xattrs
            detail["right_xattrs"] = right_entry.xattrs

        if left_entry.mtime != right_entry.mtime:
            reasons.append("mtime-differs")
            detail["left_mtime"] = left_entry.mtime
            detail["right_mtime"] = right_entry.mtime

        if reasons:
            if "present-in-one-only" in reasons:
                classification = "present-in-one-only"
            elif "type-differs" in reasons:
                classification = "type-differs"
            elif "content-differs" in reasons:
                classification = "content-differs"
            elif "hardlink-group-differs" in reasons:
                classification = "hardlink-group-differs"
            elif "xattrs-differ" in reasons:
                classification = "xattrs-differ"
            elif "mode-or-owner-differs" in reasons:
                classification = "mode-or-owner-differs"
            else:
                classification = "mtime-differs"
            differences.append(
                {
                    "path": path,
                    "classification": classification,
                    "reasons": reasons,
                    "differing_bytes": differing_bytes,
                    **detail,
                }
            )
        else:
            identical += 1

    class_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    for item in differences:
        classification = str(item["classification"])
        class_counts[classification] = class_counts.get(classification, 0) + 1
        for reason in item["reasons"]:
            reason_counts[str(reason)] = reason_counts.get(str(reason), 0) + 1

    differing_bytes_total = sum(int(item["differing_bytes"]) for item in differences)
    return {
        "byte_identical": not differences,
        "summary": {
            "total_paths": len(set(left) | set(right)),
            "identical_paths": identical,
            "differing_paths": len(differences),
            "total_differing_bytes": differing_bytes_total,
            "classification_counts": class_counts,
            "reason_counts": reason_counts,
        },
        "differences": differences,
    }


def resolve_default(explicit: Path | None, repo_root: Path | None, relative: str, option: str) -> Path:
    if explicit is not None:
        return explicit
    if repo_root is None:
        raise ReproError(f"--repo-root is required when {option} falls back to its default ({relative})")
    return repo_root / relative


def resolve_contract(args: argparse.Namespace) -> Path | None:
    contract = cast("Path | None", args.expect_from_contract)
    if contract is None:
        return None
    if contract is CONTRACT_DEFAULT:
        return resolve_default(None, args.repo_root, DEFAULT_CONTRACT_RELATIVE, "--expect-from-contract")
    return contract


def resolve_report_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    arch = platform_arch(args.platform)
    report = resolve_default(
        args.report,
        args.repo_root,
        DEFAULT_REPORT_RELATIVE_TEMPLATE.format(arch=arch),
        "--report",
    )
    summary = resolve_default(
        args.summary,
        args.repo_root,
        DEFAULT_SUMMARY_RELATIVE_TEMPLATE.format(arch=arch),
        "--summary",
    )
    return report, summary


def resolve_bake_target(invocation: BakeInvocation, *, repo_root: Path) -> dict[str, Any]:
    raw = run(
        invocation.command(print_only=True),
        cwd=repo_root,
        capture=True,
        environment=invocation.environment(),
    )
    try:
        resolved = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReproError(f"bake --print returned invalid JSON: {exc}") from exc
    targets = resolved.get("target")
    if not isinstance(targets, dict):
        raise ReproError("bake --print output has no target object")
    target = targets.get(invocation.target)
    if not isinstance(target, dict):
        raise ReproError(f"bake --print output has no resolved {invocation.target!r} target")
    return cast("dict[str, Any]", target)


def bake_report(invocation: BakeInvocation, resolved_target: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": str(invocation.bake_file),
        "target": invocation.target,
        "variables": invocation.environment(),
        "overrides": list(invocation.overrides),
        "progress": invocation.progress,
        "resolved_target": resolved_target,
    }


def build_image(tag: str, args: argparse.Namespace, image_tar: Path) -> dict[str, Any]:
    image_tar.parent.mkdir(parents=True, exist_ok=True)
    if image_tar.exists():
        image_tar.unlink()
    repo_root = args.repo_root if args.repo_root is not None else Path.cwd()
    bake_file = resolve_default(None, args.repo_root, DEFAULT_BAKE_FILE_RELATIVE, "Bake file")
    variables = [("REPRO_DEST", str(image_tar))]
    if args.ubi_minimal_image is not None:
        variables.append(("UBI_MINIMAL_IMAGE", args.ubi_minimal_image))
    if args.base_micro_image is not None:
        variables.append(("BASE_MICRO_IMAGE", args.base_micro_image))
    invocation = BakeInvocation(
        bake_file=bake_file,
        target=BAKE_TARGET,
        variables=tuple(variables),
        overrides=(
            f"repro.platform={args.platform}",
            f"repro.tags={tag}",
        ),
        progress=args.progress,
    )
    resolved_target = resolve_bake_target(invocation, repo_root=repo_root)
    run(invocation.command(), cwd=repo_root, environment=invocation.environment())
    return {
        "image": tag,
        "image_tar": str(image_tar),
        "bake": bake_report(invocation, resolved_target),
    }


def build_and_export(args: argparse.Namespace) -> tuple[Path, Path, list[dict[str, object]]]:
    workdir = resolve_default(args.workdir, args.repo_root, DEFAULT_WORKDIR_RELATIVE, "--workdir")
    workdir.mkdir(parents=True, exist_ok=True)
    left_tag = f"{args.image_prefix}:a"
    right_tag = f"{args.image_prefix}:b"
    left_tar = workdir / "rootfs.a.tar"
    right_tar = workdir / "rootfs.b.tar"
    left_image_tar = workdir / "image.a.tar"
    right_image_tar = workdir / "image.b.tar"

    for tar_path in (left_tar, right_tar):
        if tar_path.exists():
            tar_path.unlink()

    left_build = build_image(left_tag, args, left_image_tar)
    write_rootfs_tar(load_image_rootfs(left_image_tar), left_tar)
    right_build = build_image(right_tag, args, right_image_tar)
    write_rootfs_tar(load_image_rootfs(right_image_tar), right_tar)
    left_build["rootfs_tar"] = str(left_tar)
    right_build["rootfs_tar"] = str(right_tar)
    return (
        left_tar,
        right_tar,
        [
            left_build,
            right_build,
        ],
    )


def write_reports(report: dict[str, Any], output: Path, summary_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = cast("dict[str, Any]", report["summary"])
    differences = cast("list[dict[str, Any]]", report["differences"])
    builds = cast("list[dict[str, Any]]", report["builds"])
    lines = [
        f"byte-identical: {str(report['byte_identical']).lower()}",
        f"total_paths: {summary['total_paths']}",
        f"identical_paths: {summary['identical_paths']}",
        f"differing_paths: {summary['differing_paths']}",
        f"total_differing_bytes: {summary['total_differing_bytes']}",
        f"classification_counts: {json.dumps(summary['classification_counts'], sort_keys=True)}",
        "rootfs facts:",
    ]
    for build in builds:
        side = str(build["side"])
        lines.extend(
            [
                f"- {side}.rootfs_digest: {build['rootfs_digest']}",
                f"- {side}.rpmdb_sha256: {build['rpmdb_sha256']}",
                f"- {side}.fips_so_sha256: {build['fips_so_sha256']}",
            ]
        )
    lines.append("differences:")
    for item in differences:
        assert isinstance(item, dict)
        reasons = ",".join(str(reason) for reason in item["reasons"])
        line = f"- {item['path']}: {item['classification']} reasons={reasons} differing_bytes={item['differing_bytes']}"
        first = item.get("first_diff")
        if isinstance(first, dict):
            line += f" first_diff_offset={first['offset']} left_hex={first['left_hex']} right_hex={first['right_hex']}"
        if "left_mtime" in item or "right_mtime" in item:
            line += f" left_mtime={item.get('left_mtime')} right_mtime={item.get('right_mtime')}"
        lines.append(line)

    text = "\n".join(lines) + "\n"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(text, encoding="utf-8")
    print(text, end="")
    print(f"wrote JSON report: {output}")
    print(f"wrote text summary: {summary_path}")


def resolved_report_fields(builds: list[dict[str, object]], fallback_platform: str) -> dict[str, object]:
    if not builds or "bake" not in builds[0]:
        return {
            "platform": fallback_platform,
            "source_date_epoch": None,
            "oci_created": None,
        }
    bake = builds[0]["bake"]
    if not isinstance(bake, dict):
        raise ReproError("first build has malformed Bake report data")
    resolved = bake.get("resolved_target")
    if not isinstance(resolved, dict):
        raise ReproError("first build has no resolved Bake target")
    platforms = resolved.get("platforms")
    args = resolved.get("args")
    if not isinstance(platforms, list) or len(platforms) != 1 or not isinstance(platforms[0], str):
        raise ReproError("resolved repro target must contain exactly one platform")
    if not isinstance(args, dict):
        raise ReproError("resolved repro target has no args object")
    source_date_epoch = args.get("SOURCE_DATE_EPOCH")
    oci_created = args.get("OCI_CREATED")
    if not isinstance(source_date_epoch, str) or not source_date_epoch.isdigit():
        raise ReproError("resolved repro target has an invalid SOURCE_DATE_EPOCH")
    if not isinstance(oci_created, str):
        raise ReproError("resolved repro target has an invalid OCI_CREATED")
    return {
        "platform": platforms[0],
        "source_date_epoch": int(source_date_epoch),
        "oci_created": oci_created,
    }


FixtureEntry = tuple[str, bytes | None, str, int, int, int, int, str, dict[str, str]]


@dataclass(frozen=True)
class OciFixtureEntry:
    name: str
    data: bytes | None = None
    kind: str = "file"
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    uname: str = "root"
    gname: str = "root"
    mtime: int = OCI_SOURCE_DATE_EPOCH
    linkname: str = ""
    pax_headers: Mapping[str, str] | None = None


def _oci_fixture_layer_entries() -> list[OciFixtureEntry]:
    return [
        OciFixtureEntry("etc", kind="directory", mode=0o755),
        OciFixtureEntry(
            "etc/message",
            b"content identity\n",
            mode=0o640,
            uid=12,
            gid=34,
            uname="fixture",
            gname="fixture",
            pax_headers={"SCHILY.xattr.user.fixture": "one"},
        ),
        OciFixtureEntry("etc/empty", b"", mode=0o600, uid=12, gid=34, uname="fixture", gname="fixture"),
        OciFixtureEntry("usr", kind="directory", mode=0o755),
        OciFixtureEntry("usr/bin", kind="directory", mode=0o755),
        OciFixtureEntry("usr/bin/tool", b"tool\n", mode=0o755),
        OciFixtureEntry("bin", kind="directory", mode=0o755),
        OciFixtureEntry("bin/tool", kind="symlink", mode=0o777, linkname="../usr/bin/tool"),
        OciFixtureEntry("usr/bin/tool-hard", kind="hardlink", mode=0o755, linkname="usr/bin/tool"),
    ]


def _tar_bytes(entries: list[OciFixtureEntry], *, pax_global: Mapping[str, str] | None = None) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT, pax_headers=pax_global) as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.mode = entry.mode
            info.uid = entry.uid
            info.gid = entry.gid
            info.uname = entry.uname
            info.gname = entry.gname
            info.mtime = entry.mtime
            if entry.pax_headers:
                info.pax_headers = dict(entry.pax_headers)
            if entry.kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry.kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            elif entry.kind == "character":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            elif entry.kind == "block":
                info.type = tarfile.BLKTYPE
                archive.addfile(info)
            elif entry.kind == "socket":
                info.type = b"s"
                archive.addfile(info)
            else:
                payload = entry.data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _json_fixture_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


def _oci_descriptor(payload: bytes, media_type: str) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
    }


def _same_length_json_whitespace(payload: bytes) -> bytes:
    marker = b'": '
    position = payload.find(marker)
    if position < 0:
        raise ReproError("fixture JSON has no replaceable separator")
    whitespace = position + len(marker) - 1
    return payload[:whitespace] + b"\t" + payload[whitespace + 1 :]


def _gzip_header_mutation(payload: bytes) -> bytes:
    if len(payload) < 10 or payload[:2] != b"\x1f\x8b":
        raise ReproError("fixture layer is not gzip")
    mutated = bytearray(payload)
    mutated[4] ^= 1
    return bytes(mutated)


def _apply_fixture_mutation(value: Any, mutation: Any) -> Any:
    if mutation is None:
        return value
    if callable(mutation):
        return mutation(value)
    return mutation


def _write_outer_fixture(path: Path, members: list[tuple[str, bytes | None, str]]) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.mtime = OCI_SOURCE_DATE_EPOCH
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "index.json"
                archive.addfile(info)
            else:
                data = payload or b""
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def make_oci_fixture(path: Path, mutations: Mapping[str, Any] | None = None) -> dict[str, Any]:
    changes = dict(mutations or {})
    layer_entries = cast(
        list[OciFixtureEntry],
        _apply_fixture_mutation(_oci_fixture_layer_entries(), changes.get("layer_entries")),
    )
    layer_tar = cast(bytes, changes.get("layer_tar", _tar_bytes(layer_entries)))
    layer_tar = cast(bytes, _apply_fixture_mutation(layer_tar, changes.get("layer_tar_mutation")))
    layer_blob = gzip.compress(layer_tar, compresslevel=9, mtime=0)
    layer_blob = cast(bytes, _apply_fixture_mutation(layer_blob, changes.get("layer_blob")))
    layer_descriptor = _oci_descriptor(layer_blob, OCI_LAYER_MEDIA_TYPE)
    layer_descriptor = cast(dict[str, Any], _apply_fixture_mutation(layer_descriptor, changes.get("layer_descriptor")))
    layer_blob = cast(bytes, _apply_fixture_mutation(layer_blob, changes.get("layer_blob_after_descriptor")))

    config: Any = {
        "architecture": "amd64",
        "os": "linux",
        "created": OCI_CREATED,
        "config": {"Env": ["PATH=/usr/bin"], "WorkingDir": "/"},
        "history": [{"created": OCI_CREATED}],
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{hashlib.sha256(layer_tar).hexdigest()}"],
        },
    }
    config = _apply_fixture_mutation(config, changes.get("config"))
    config_blob = cast(bytes, _apply_fixture_mutation(_json_fixture_bytes(config), changes.get("config_blob")))
    config_descriptor = _oci_descriptor(config_blob, OCI_CONFIG_MEDIA_TYPE)
    config_descriptor = cast(
        dict[str, Any], _apply_fixture_mutation(config_descriptor, changes.get("config_descriptor"))
    )
    config_blob = cast(bytes, _apply_fixture_mutation(config_blob, changes.get("config_blob_after_descriptor")))

    manifest: Any = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": config_descriptor,
        "layers": [layer_descriptor],
    }
    manifest = _apply_fixture_mutation(manifest, changes.get("manifest"))
    manifest_blob = cast(bytes, _apply_fixture_mutation(_json_fixture_bytes(manifest), changes.get("manifest_blob")))
    child_descriptor = _oci_descriptor(manifest_blob, OCI_MANIFEST_MEDIA_TYPE)
    child_descriptor.update(
        {
            "platform": {"os": "linux", "architecture": "amd64"},
            "annotations": {"org.opencontainers.image.created": OCI_CREATED},
        }
    )
    child_descriptor = cast(dict[str, Any], _apply_fixture_mutation(child_descriptor, changes.get("child_descriptor")))
    manifest_blob = cast(bytes, _apply_fixture_mutation(manifest_blob, changes.get("manifest_blob_after_descriptor")))

    index: Any = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "manifests": [child_descriptor],
    }
    index = _apply_fixture_mutation(index, changes.get("index"))
    index_blob = cast(bytes, changes.get("index_blob", _json_fixture_bytes(index)))
    layout_blob = cast(
        bytes,
        changes.get("layout_blob", _json_fixture_bytes({"imageLayoutVersion": OCI_LAYOUT_VERSION})),
    )

    def addressed_name(descriptor: dict[str, Any], payload: bytes) -> str:
        digest = descriptor.get("digest")
        if isinstance(digest, str) and OCI_DIGEST.fullmatch(digest):
            return f"blobs/sha256/{digest.removeprefix('sha256:')}"
        return f"blobs/sha256/{hashlib.sha256(payload).hexdigest()}"

    blobs = {
        addressed_name(child_descriptor, manifest_blob): manifest_blob,
        addressed_name(config_descriptor, config_blob): config_blob,
        addressed_name(layer_descriptor, layer_blob): layer_blob,
    }
    stale_blobs = changes.get("stale_blob_names")
    if isinstance(stale_blobs, dict):
        blobs.update(cast(dict[str, bytes], stale_blobs))
    members: list[tuple[str, bytes | None, str]] = [
        ("oci-layout", layout_blob, "file"),
        ("index.json", index_blob, "file"),
    ]
    if changes.get("include_directories", True):
        members.extend([("blobs", None, "directory"), ("blobs/sha256", None, "directory")])
    omitted = set(cast(list[str], changes.get("omit_blob_kinds", [])))
    descriptor_blobs = {
        "child": addressed_name(child_descriptor, manifest_blob),
        "config": addressed_name(config_descriptor, config_blob),
        "layer": addressed_name(layer_descriptor, layer_blob),
    }
    for name, payload in blobs.items():
        kind = next((label for label, descriptor_name in descriptor_blobs.items() if descriptor_name == name), "extra")
        if kind not in omitted:
            members.append((name, payload, "file"))
    members = cast(list[tuple[str, bytes | None, str]], _apply_fixture_mutation(members, changes.get("outer_members")))
    _write_outer_fixture(path, members)
    if "outer_archive" in changes:
        changes["outer_archive"](path)
    return {
        "layer_tar": layer_tar,
        "layer_blob": layer_blob,
        "config": config,
        "config_blob": config_blob,
        "config_descriptor": config_descriptor,
        "manifest": manifest,
        "manifest_blob": manifest_blob,
        "child_descriptor": child_descriptor,
        "index": index,
        "index_blob": index_blob,
    }


OCI_ORACLE_DIGEST = "d994ea47d217a9b7b2f9e63cc6b6c2c00f52752971ceca720e8e646a5020e744"


def _independent_oci_expected_entries() -> dict[str, Entry]:
    empty_digest = hashlib.sha256(b"").hexdigest()
    return {
        "bin": Entry(
            "bin", "directory", 0o755, 0, 0, "root", "root", OCI_SOURCE_DATE_EPOCH, 0, "", "", "", None, None, ()
        ),
        "bin/tool": Entry(
            "bin/tool",
            "symlink",
            0o777,
            0,
            0,
            "root",
            "root",
            OCI_SOURCE_DATE_EPOCH,
            0,
            "../usr/bin/tool",
            "",
            "",
            hashlib.sha256(b"../usr/bin/tool").hexdigest(),
            None,
            (),
        ),
        "etc": Entry(
            "etc", "directory", 0o755, 0, 0, "root", "root", OCI_SOURCE_DATE_EPOCH, 0, "", "", "", None, None, ()
        ),
        "etc/empty": Entry(
            "etc/empty",
            "file",
            0o600,
            12,
            34,
            "fixture",
            "fixture",
            OCI_SOURCE_DATE_EPOCH,
            0,
            "",
            "",
            "",
            empty_digest,
            b"",
            (),
        ),
        "etc/message": Entry(
            "etc/message",
            "file",
            0o640,
            12,
            34,
            "fixture",
            "fixture",
            OCI_SOURCE_DATE_EPOCH,
            17,
            "",
            "",
            "user.fixture=" + hashlib.sha256(b"one").hexdigest(),
            hashlib.sha256(b"content identity\n").hexdigest(),
            b"content identity\n",
            (("user.fixture", "one"),),
        ),
        "usr": Entry(
            "usr", "directory", 0o755, 0, 0, "root", "root", OCI_SOURCE_DATE_EPOCH, 0, "", "", "", None, None, ()
        ),
        "usr/bin": Entry(
            "usr/bin", "directory", 0o755, 0, 0, "root", "root", OCI_SOURCE_DATE_EPOCH, 0, "", "", "", None, None, ()
        ),
        "usr/bin/tool": Entry(
            "usr/bin/tool",
            "file",
            0o755,
            0,
            0,
            "root",
            "root",
            OCI_SOURCE_DATE_EPOCH,
            5,
            "",
            "",
            "",
            hashlib.sha256(b"tool\n").hexdigest(),
            b"tool\n",
            (),
        ),
        "usr/bin/tool-hard": Entry(
            "usr/bin/tool-hard",
            "hardlink",
            0o755,
            0,
            0,
            "root",
            "root",
            OCI_SOURCE_DATE_EPOCH,
            0,
            "usr/bin/tool",
            "usr/bin/tool",
            "",
            hashlib.sha256(b"usr/bin/tool").hexdigest(),
            None,
            (),
        ),
    }


def _make_docker_save_fixture(path: Path, layer_tar: bytes) -> None:
    manifest = _json_fixture_bytes([{"Config": "config.json", "RepoTags": [], "Layers": ["layer.tar"]}])
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in [("manifest.json", manifest), ("config.json", b"{}"), ("layer.tar", layer_tar)]:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _pax_record(key: str, value: str) -> bytes:
    body = key.encode("utf-8", "surrogateescape") + b"=" + value.encode("utf-8", "surrogateescape") + b"\n"
    length = len(body) + 2
    while True:
        encoded = str(length).encode("ascii") + b" " + body
        if len(encoded) == length:
            return encoded
        length = len(encoded)


def _raw_pax_layer(records: list[tuple[str, str]], *, global_header: bool = False) -> bytes:
    payload = b"".join(_pax_record(key, value) for key, value in records)
    pax_info = tarfile.TarInfo("PaxHeaders/entry")
    pax_info.type = tarfile.XGLTYPE if global_header else tarfile.XHDTYPE
    pax_info.size = len(payload)
    file_info = tarfile.TarInfo("entry")
    file_info.size = 1
    return (
        pax_info.tobuf(format=tarfile.USTAR_FORMAT)
        + payload
        + b"\0" * ((-len(payload)) % 512)
        + file_info.tobuf(format=tarfile.USTAR_FORMAT)
        + b"x"
        + b"\0" * 511
        + b"\0" * 1024
    )


def _patch_tar_type(payload: bytes, member_name: str, typeflag: bytes) -> bytes:
    mutated = bytearray(payload)
    offset = 0
    while offset + 512 <= len(mutated):
        header = mutated[offset : offset + 512]
        if header == b"\0" * 512:
            break
        name = bytes(header[:100]).split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
        size = _tar_number(bytes(header[124:136]))
        if name == member_name:
            mutated[offset + 156 : offset + 157] = typeflag
            mutated[offset + 148 : offset + 156] = b"        "
            checksum = sum(mutated[offset : offset + 512])
            mutated[offset + 148 : offset + 156] = f"{checksum:06o}\0 ".encode("ascii")
            return bytes(mutated)
        offset += 512 + ((size + 511) // 512) * 512
    raise ReproError(f"fixture tar member not found: {member_name}")


@dataclass(frozen=True)
class OciGuardEvidence:
    positive_fixture: str
    negative_fixture: str
    coverage_kind: str


def _expect_oci_guard(
    coverage: dict[str, OciGuardEvidence],
    guard_id: str,
    negative_fixture: str,
    runner: Any,
    *,
    coverage_kind: str = "checker-mutation",
) -> None:
    expected = f"{guard_id}: {OCI_GUARD_REASONS[guard_id]}"
    try:
        runner(OciGuardContext())
    except ReproError as exc:
        if str(exc) != expected:
            raise ReproError(
                f"OCI fixture {negative_fixture} reached {exc!s}; expected exact reason {expected}"
            ) from exc
    else:
        raise ReproError(f"OCI fixture {negative_fixture} unexpectedly passed; expected {expected}")
    if coverage_kind == "checker-mutation":
        try:
            runner(OciGuardContext(frozenset({guard_id})))
        except ReproError as exc:
            if str(exc) == expected:
                raise ReproError(f"OCI guard neutralization still emitted its own reason: {guard_id}") from exc
        except Exception:
            pass
    coverage[guard_id] = OciGuardEvidence(
        positive_fixture="production-shaped valid OCI layout",
        negative_fixture=negative_fixture,
        coverage_kind=coverage_kind,
    )


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _run_oci_self_test(tmp_path: Path) -> dict[str, OciGuardEvidence]:
    assert_oci_limit_ordering()
    schema = _load_content_identity_schema()
    check_id_schema = schema["properties"]["checks"]["items"]["properties"]["id"]
    if sorted(check_id_schema["enum"]) != sorted(OCI_GUARD_REASONS):
        raise ReproError("content-identity schema check IDs differ from the OCI guard inventory")

    valid_archive = tmp_path / "oci-valid.tar"
    valid_parts = make_oci_fixture(valid_archive)
    valid = read_oci_content_identity(valid_archive, "amd64")
    expected_entries = _independent_oci_expected_entries()
    if canonical_rootfs_digest(expected_entries) != OCI_ORACLE_DIGEST:
        raise ReproError("independently declared OCI fixture entries moved from the hard-coded digest")
    if valid.record["canonical_rootfs_digest"] != OCI_ORACLE_DIGEST:
        raise ReproError("OCI layout path disagrees with the independent rootfs oracle")
    docker_save = tmp_path / "oci-oracle-docker-save.tar"
    _make_docker_save_fixture(docker_save, cast(bytes, valid_parts["layer_tar"]))
    if canonical_rootfs_digest(load_image_rootfs(docker_save)) != OCI_ORACLE_DIGEST:
        raise ReproError("Docker-save path disagrees with the independent rootfs oracle")
    without_directories = tmp_path / "oci-no-directories.tar"
    make_oci_fixture(without_directories, {"include_directories": False})
    if read_oci_content_identity(without_directories, "amd64").record["canonical_rootfs_digest"] != OCI_ORACLE_DIGEST:
        raise ReproError("optional outer directory entries changed the OCI rootfs result")
    trailing_tar = tmp_path / "oci-tar-trailing.tar"
    make_oci_fixture(trailing_tar, {"layer_tar_mutation": lambda payload: payload + b"after logical tar EOF"})
    if read_oci_content_identity(trailing_tar, "amd64").record["canonical_rootfs_digest"] != OCI_ORACLE_DIGEST:
        raise ReproError("decoded bytes after the logical tar EOF changed parsed entries")
    changed_xattr = tmp_path / "oci-xattr-mutated.tar"

    def change_xattr(entries: list[OciFixtureEntry]) -> list[OciFixtureEntry]:
        clone = list(entries)
        clone[1] = replace(clone[1], pax_headers={"SCHILY.xattr.user.fixture": "two"})
        return clone

    make_oci_fixture(changed_xattr, {"layer_entries": change_xattr})
    if read_oci_content_identity(changed_xattr, "amd64").record["canonical_rootfs_digest"] == OCI_ORACLE_DIGEST:
        raise ReproError("OCI xattr mutation did not change the canonical rootfs digest")

    valid_output = tmp_path / "content-identity.json"
    emit_content_identity_record(
        valid.record,
        valid_output,
        architecture="amd64",
        config_platform=valid.config_platform,
        diff_ids=valid.diff_ids,
    )
    loaded_record = load_content_identity_record(
        valid_output,
        architecture="amd64",
        config_platform=valid.config_platform,
        diff_ids=valid.diff_ids,
    )
    if loaded_record != valid.record:
        raise ReproError("content-identity record changed across atomic serialization")

    coverage: dict[str, OciGuardEvidence] = {}
    counter = 0

    def field(name: str, value: Any) -> Any:
        def mutate(source: Any) -> Any:
            clone = _json_clone(source)
            clone[name] = value
            return clone

        return mutate

    def drop(name: str) -> Any:
        def mutate(source: Any) -> Any:
            clone = _json_clone(source)
            del clone[name]
            return clone

        return mutate

    def archive_guard(
        guard_id: str,
        name: str,
        mutations: Mapping[str, Any],
        *,
        limits: OciLimits = OCI_LIMITS,
        architecture: str = "amd64",
        coverage_kind: str = "checker-mutation",
    ) -> None:
        nonlocal counter
        counter += 1
        fixture_path = tmp_path / f"oci-negative-{counter:03d}.tar"

        def runner(context: OciGuardContext) -> None:
            make_oci_fixture(fixture_path, mutations)
            read_oci_content_identity(
                fixture_path,
                architecture,
                limits=limits,
                context=context,
            )

        _expect_oci_guard(coverage, guard_id, name, runner, coverage_kind=coverage_kind)

    def direct_guard(guard_id: str, name: str, runner: Any, *, coverage_kind: str = "checker-mutation") -> None:
        _expect_oci_guard(coverage, guard_id, name, runner, coverage_kind=coverage_kind)

    def additional_archive_reason(
        guard_id: str,
        name: str,
        mutations: Mapping[str, Any],
        *,
        limits: OciLimits = OCI_LIMITS,
    ) -> None:
        nonlocal counter
        counter += 1
        fixture_path = tmp_path / f"oci-additional-{counter:03d}.tar"
        make_oci_fixture(fixture_path, mutations)
        expected = f"{guard_id}: {OCI_GUARD_REASONS[guard_id]}"
        try:
            read_oci_content_identity(fixture_path, "amd64", limits=limits)
        except ReproError as exc:
            if str(exc) != expected:
                raise ReproError(f"OCI fixture {name} reached {exc!s}; expected {expected}") from exc
        else:
            raise ReproError(f"OCI fixture {name} unexpectedly passed; expected {expected}")

    archive_guard(
        "O01.outer_archive_bytes",
        "outer archive byte ceiling",
        {},
        limits=replace(OCI_LIMITS, outer_archive_bytes=1),
    )

    def compress_outer(path: Path) -> None:
        path.write_bytes(gzip.compress(path.read_bytes(), mtime=0))

    archive_guard(
        "O02.outer_compressed",
        "compressed outer archive",
        {"outer_archive": compress_outer},
        coverage_kind="input-path",
    )

    def invalidate_outer(path: Path) -> None:
        path.write_bytes(b"not a tar")

    archive_guard(
        "O03.outer_tar", "malformed outer tar", {"outer_archive": invalidate_outer}, coverage_kind="input-path"
    )
    archive_guard(
        "O04.outer_member_count", "outer member-count ceiling", {}, limits=replace(OCI_LIMITS, outer_member_count=1)
    )
    archive_guard("O05.outer_path_bytes", "outer path byte ceiling", {}, limits=replace(OCI_LIMITS, path_bytes=5))

    def append_outer(name: str, payload: bytes = b"x", kind: str = "file") -> Any:
        return lambda members: [*members, (name, payload, kind)]

    archive_guard("O06.outer_absolute", "absolute outer path", {"outer_members": append_outer("/escape")})
    archive_guard("O07.outer_traversal", "outer parent traversal", {"outer_members": append_outer("../escape")})
    archive_guard(
        "O08.outer_duplicate", "outer normalized-name collision", {"outer_members": append_outer("./index.json")}
    )

    def rename_index(new_name: str) -> Any:
        return lambda members: [
            (new_name if name == "index.json" else name, payload, kind) for name, payload, kind in members
        ]

    archive_guard(
        "O09.outer_canonical", "safe non-canonical ./index.json", {"outer_members": rename_index("./index.json")}
    )
    additional_archive_reason(
        "O09.outer_canonical",
        "safe non-canonical doubled-slash outer name",
        {"outer_members": rename_index("index//json")},
    )
    additional_archive_reason(
        "O09.outer_canonical",
        "safe non-canonical trailing-slash outer file",
        {"outer_members": rename_index("index.json/")},
    )
    archive_guard(
        "O10.outer_individual_bytes",
        "individual outer member byte ceiling",
        {},
        limits=replace(OCI_LIMITS, outer_individual_bytes=1),
    )
    archive_guard(
        "O11.outer_member_bytes",
        "aggregate consumed outer member byte ceiling",
        {},
        limits=replace(OCI_LIMITS, outer_member_bytes=1),
    )

    def truncate_outer_member(path: Path) -> None:
        info = tarfile.TarInfo("oci-layout")
        info.size = 128
        path.write_bytes(info.tobuf(format=tarfile.USTAR_FORMAT) + b"{}")

    archive_guard(
        "O12.outer_consumed_size",
        "outer header-declared size differs from consumed size",
        {"outer_archive": truncate_outer_member},
        coverage_kind="input-path",
    )
    archive_guard("O13.outer_unexpected", "unexpected outer member", {"outer_members": append_outer("unexpected")})

    def wrong_blob_directory(members: list[tuple[str, bytes | None, str]]) -> list[tuple[str, bytes | None, str]]:
        return [(name, b"", "file") if name == "blobs" else (name, payload, kind) for name, payload, kind in members]

    archive_guard(
        "O14.outer_directory_type", "blobs directory entry with wrong type", {"outer_members": wrong_blob_directory}
    )
    archive_guard(
        "O15.outer_unreferenced_blob",
        "unreferenced OCI blob",
        {"outer_members": append_outer("blobs/sha256/" + "f" * 64)},
    )

    def remove_outer(name_to_remove: str) -> Any:
        return lambda members: [item for item in members if item[0] != name_to_remove]

    archive_guard("L01.layout_missing", "missing oci-layout", {"outer_members": remove_outer("oci-layout")})

    def make_outer_symlink(name_to_change: str) -> Any:
        return lambda members: [
            (name, payload, "symlink" if name == name_to_change else kind) for name, payload, kind in members
        ]

    archive_guard("L02.layout_regular", "non-regular oci-layout", {"outer_members": make_outer_symlink("oci-layout")})
    archive_guard("L03.layout_json", "malformed oci-layout JSON", {"layout_blob": b"{"}, coverage_kind="input-path")
    archive_guard("L04.layout_object", "wrong-typed oci-layout JSON", {"layout_blob": b"[]"})
    archive_guard(
        "L05.layout_keys", "extra oci-layout property", {"layout_blob": b'{"extra":1,"imageLayoutVersion":"1.0.0"}'}
    )
    archive_guard("L06.layout_version", "wrong imageLayoutVersion", {"layout_blob": b'{"imageLayoutVersion":"1.0.1"}'})
    archive_guard("I01.index_missing", "missing index.json", {"outer_members": remove_outer("index.json")})
    archive_guard("I02.index_regular", "non-regular index.json", {"outer_members": make_outer_symlink("index.json")})
    archive_guard("I03.index_json", "malformed index.json", {"index_blob": b"{"}, coverage_kind="input-path")
    archive_guard("I04.index_object", "wrong-typed index.json", {"index_blob": b"[]"})
    archive_guard("I05.index_keys", "extra index.json property", {"index": field("extra", 1)})
    archive_guard("I06.index_schema", "bad index schemaVersion", {"index": field("schemaVersion", 3)})
    archive_guard("I07.index_media_type", "bad index mediaType", {"index": field("mediaType", "bad")})
    archive_guard("I08.index_annotations", "index annotations present", {"index": field("annotations", {})})
    archive_guard("I09.index_artifact_type", "index artifactType present", {"index": field("artifactType", "x")})
    archive_guard("I10.index_subject", "index subject present", {"index": field("subject", {})})
    archive_guard("I11.index_manifests_type", "wrong-typed index manifests", {"index": field("manifests", {})})
    archive_guard("I12.index_manifests_zero", "zero index manifests", {"index": field("manifests", [])})
    archive_guard(
        "I13.index_manifests_multiple",
        "multiple index manifests",
        {"index": lambda value: {**value, "manifests": [value["manifests"][0], value["manifests"][0]]}},
    )

    def nested_json(depth: int) -> Any:
        value: Any = "leaf"
        for _ in range(depth):
            value = [value]
        return value

    archive_guard("J01.json_bytes", "JSON document byte ceiling", {}, limits=replace(OCI_LIMITS, json_document_bytes=1))
    archive_guard(
        "J02.json_duplicate",
        "duplicate JSON object key",
        {"index_blob": b'{"schemaVersion":2,"schemaVersion":2,"mediaType":"x","manifests":[]}'},
        coverage_kind="input-path",
    )
    archive_guard(
        "J03.json_nan",
        "NaN JSON value",
        {"index_blob": b'{"schemaVersion":NaN,"mediaType":"x","manifests":[]}'},
        coverage_kind="input-path",
    )
    archive_guard(
        "J04.json_infinity",
        "Infinity JSON value",
        {"index_blob": b'{"schemaVersion":Infinity,"mediaType":"x","manifests":[]}'},
        coverage_kind="input-path",
    )
    archive_guard(
        "J05.json_depth",
        "JSON nesting-depth ceiling",
        {"index": field("deep", nested_json(4))},
        limits=replace(OCI_LIMITS, json_nesting_depth=3),
    )
    archive_guard("J06.json_members", "JSON member-count ceiling", {}, limits=replace(OCI_LIMITS, json_members=2))
    archive_guard(
        "J07.json_string_bytes", "JSON string byte ceiling", {}, limits=replace(OCI_LIMITS, json_string_bytes=5)
    )

    archive_guard("D01.child_object", "wrong-typed index manifest descriptor", {"index": field("manifests", [1])})
    archive_guard("D02.child_keys", "extra index manifest descriptor key", {"child_descriptor": field("extra", 1)})
    archive_guard(
        "D03.child_media_type", "wrong index-child mediaType", {"child_descriptor": field("mediaType", "bad")}
    )
    archive_guard("D04.child_platform_missing", "missing index-child platform", {"child_descriptor": drop("platform")})
    archive_guard(
        "D05.child_platform_type",
        "wrong-typed index-child platform",
        {"child_descriptor": field("platform", "linux/amd64")},
    )

    def child_platform(mutation: Any) -> Any:
        def apply(descriptor: dict[str, Any]) -> dict[str, Any]:
            clone = cast(dict[str, Any], _json_clone(descriptor))
            clone["platform"] = mutation(clone["platform"])
            return clone

        return apply

    archive_guard(
        "D06.child_platform_keys",
        "extra index-child platform key",
        {"child_descriptor": child_platform(field("variant", "v1"))},
    )
    archive_guard(
        "D07.child_platform_os",
        "wrong index-child platform os",
        {"child_descriptor": child_platform(field("os", "windows"))},
    )
    archive_guard(
        "D08.child_platform_arch",
        "wrong-platform child",
        {"child_descriptor": child_platform(field("architecture", "arm64"))},
    )
    archive_guard("D09.child_urls", "index-child urls present", {"child_descriptor": field("urls", [])})
    archive_guard("D10.child_data", "index-child data present", {"child_descriptor": field("data", "")})
    archive_guard(
        "D11.child_artifact_type", "index-child artifactType present", {"child_descriptor": field("artifactType", "x")}
    )
    archive_guard(
        "A01.child_annotations_missing", "missing created annotation", {"child_descriptor": drop("annotations")}
    )
    archive_guard(
        "A02.child_annotations_type", "wrong-typed child annotations", {"child_descriptor": field("annotations", [])}
    )

    def child_annotations(value: Any) -> Any:
        return field("annotations", value)

    archive_guard(
        "A03.child_annotations_count",
        "child annotation-count ceiling",
        {"child_descriptor": child_annotations({f"key{index}": "x" for index in range(17)})},
    )
    archive_guard(
        "A04.child_annotation_key_bytes",
        "child annotation key byte ceiling",
        {"child_descriptor": child_annotations({"org.opencontainers.image.created": OCI_CREATED})},
        limits=replace(OCI_LIMITS, annotation_key_bytes=5),
    )
    archive_guard(
        "A05.child_annotation_value_bytes",
        "child annotation value byte ceiling",
        {"child_descriptor": child_annotations({"org.opencontainers.image.created": OCI_CREATED})},
        limits=replace(OCI_LIMITS, annotation_value_bytes=5),
    )
    archive_guard(
        "A06.child_annotation_unknown",
        "unknown child annotation",
        {"child_descriptor": child_annotations({"unknown": "x"})},
    )
    archive_guard(
        "A07.child_annotation_type",
        "wrong-typed created annotation",
        {"child_descriptor": child_annotations({"org.opencontainers.image.created": 1})},
    )
    archive_guard(
        "A08.child_created_rfc3339",
        "non-RFC-3339 created annotation",
        {"child_descriptor": child_annotations({"org.opencontainers.image.created": "not-a-time"})},
        coverage_kind="input-path",
    )
    archive_guard(
        "A09.child_created_epoch",
        "created annotation disagrees with SOURCE_DATE_EPOCH",
        {"child_descriptor": child_annotations({"org.opencontainers.image.created": "2024-01-01T00:00:01Z"})},
    )
    archive_guard("D12.child_digest_type", "wrong-typed child digest", {"child_descriptor": field("digest", 1)})
    archive_guard(
        "D13.child_digest_algorithm",
        "non-sha256 child digest",
        {"child_descriptor": field("digest", "sha512:" + "0" * 64)},
    )
    archive_guard(
        "D14.child_digest_grammar",
        "malformed child digest grammar",
        {"child_descriptor": field("digest", "sha256:../escape")},
    )
    archive_guard("D15.child_size_type", "boolean child size", {"child_descriptor": field("size", True)})
    archive_guard("D16.child_size_negative", "negative child size", {"child_descriptor": field("size", -1)})
    archive_guard(
        "D17.child_size_ceiling",
        "child descriptor size ceiling",
        {},
        limits=replace(OCI_LIMITS, descriptor_bytes=1),
    )

    archive_guard("M01.child_blob_missing", "absent child manifest blob", {"omit_blob_kinds": ["child"]})

    def blob_to_symlink(kind_to_change: str) -> Any:
        def mutate(members: list[tuple[str, bytes | None, str]]) -> list[tuple[str, bytes | None, str]]:
            blobs = [item for item in members if item[0].startswith("blobs/sha256/")]
            target = {"child": blobs[0], "config": blobs[1], "layer": blobs[2]}[kind_to_change]
            return [(name, payload, "symlink" if name == target[0] else kind) for name, payload, kind in members]

        return mutate

    archive_guard(
        "M02.child_blob_regular", "non-regular child manifest blob", {"outer_members": blob_to_symlink("child")}
    )
    archive_guard(
        "M03.child_size",
        "child manifest descriptor size mismatch",
        {"child_descriptor": lambda value: {**value, "size": value["size"] + 1}},
    )
    archive_guard(
        "M04.child_digest",
        "same-length manifest JSON whitespace digest mismatch",
        {"manifest_blob_after_descriptor": _same_length_json_whitespace},
    )
    archive_guard(
        "M05.manifest_json", "malformed child manifest blob", {"manifest_blob": b"{"}, coverage_kind="input-path"
    )
    archive_guard("M06.manifest_object", "wrong-typed child manifest", {"manifest_blob": b"[]"})
    archive_guard("M07.manifest_keys", "extra child manifest key", {"manifest": field("extra", 1)})
    archive_guard("M08.manifest_schema", "bad manifest schemaVersion", {"manifest": field("schemaVersion", 3)})
    archive_guard("M09.manifest_media_type", "bad manifest mediaType", {"manifest": field("mediaType", "bad")})
    archive_guard("M10.manifest_annotations", "manifest annotations present", {"manifest": field("annotations", {})})
    archive_guard(
        "M11.manifest_artifact_type", "manifest artifactType present", {"manifest": field("artifactType", "x")}
    )
    archive_guard("M12.manifest_subject", "manifest subject present", {"manifest": field("subject", {})})
    archive_guard("M13.config_object", "wrong-typed config descriptor", {"manifest": field("config", [])})
    archive_guard("M14.layers_type", "wrong-typed manifest layers", {"manifest": field("layers", {})})
    archive_guard("M15.layers_zero", "zero manifest layers", {"manifest": field("layers", [])})
    archive_guard(
        "M16.layers_multiple",
        "multiple manifest layers",
        {"manifest": lambda value: {**value, "layers": [value["layers"][0], value["layers"][0]]}},
    )

    archive_guard("C01.config_keys", "extra config descriptor key", {"config_descriptor": field("extra", 1)})
    archive_guard(
        "C02.config_media_type", "bad config descriptor mediaType", {"config_descriptor": field("mediaType", "bad")}
    )
    archive_guard("C03.config_urls", "config descriptor urls present", {"config_descriptor": field("urls", [])})
    archive_guard("C04.config_data", "config descriptor data present", {"config_descriptor": field("data", "")})
    archive_guard(
        "C05.config_artifact_type",
        "config descriptor artifactType present",
        {"config_descriptor": field("artifactType", "x")},
    )
    archive_guard(
        "C06.config_annotations",
        "config descriptor annotations present",
        {"config_descriptor": field("annotations", {})},
    )
    archive_guard(
        "C07.config_platform", "config descriptor platform present", {"config_descriptor": field("platform", {})}
    )
    archive_guard("C08.config_digest_type", "wrong-typed config digest", {"config_descriptor": field("digest", 1)})
    archive_guard(
        "C09.config_digest_algorithm",
        "non-sha256 config digest",
        {"config_descriptor": field("digest", "sha512:" + "0" * 64)},
    )
    archive_guard(
        "C10.config_digest_grammar",
        "malformed config digest grammar",
        {"config_descriptor": field("digest", "sha256:BAD")},
    )
    archive_guard("C11.config_size_type", "boolean config size", {"config_descriptor": field("size", True)})
    archive_guard("C12.config_size_negative", "negative config size", {"config_descriptor": field("size", -1)})
    archive_guard(
        "C13.config_size_ceiling",
        "config descriptor size ceiling",
        {"config_descriptor": field("size", OCI_LIMITS.descriptor_bytes + 1)},
    )
    archive_guard("C14.config_blob_missing", "absent config blob", {"omit_blob_kinds": ["config"]})
    archive_guard("C15.config_blob_regular", "non-regular config blob", {"outer_members": blob_to_symlink("config")})
    archive_guard(
        "C16.config_size",
        "config descriptor size mismatch",
        {"config_descriptor": lambda value: {**value, "size": value["size"] + 1}},
    )
    archive_guard(
        "C17.config_digest",
        "same-length config JSON whitespace digest mismatch",
        {"config_blob_after_descriptor": _same_length_json_whitespace},
    )
    archive_guard("C18.config_json", "malformed config JSON", {"config_blob": b"{"}, coverage_kind="input-path")
    archive_guard("C19.config_object", "wrong-typed config JSON", {"config_blob": b"[]"})
    archive_guard("C20.config_arch_type", "wrong-typed config architecture", {"config": field("architecture", 1)})
    archive_guard("C21.config_arch", "config architecture mismatch", {"config": field("architecture", "arm64")})
    archive_guard("C22.config_os_type", "wrong-typed config os", {"config": field("os", 1)})
    archive_guard("C23.config_os", "config os mismatch", {"config": field("os", "windows")})
    archive_guard("C24.rootfs_object", "wrong-typed config rootfs", {"config": field("rootfs", [])})

    def rootfs_field(name: str, value: Any) -> Any:
        def mutate(config: dict[str, Any]) -> dict[str, Any]:
            clone = cast(dict[str, Any], _json_clone(config))
            clone["rootfs"][name] = value
            return clone

        return mutate

    archive_guard("C25.rootfs_type", "bad rootfs type", {"config": rootfs_field("type", "other")})
    archive_guard("C26.diff_ids_type", "wrong-typed rootfs diff_ids", {"config": rootfs_field("diff_ids", {})})
    archive_guard("C27.diff_ids_zero", "zero rootfs DiffIDs", {"config": rootfs_field("diff_ids", [])})
    archive_guard(
        "C28.diff_ids_multiple",
        "multiple rootfs DiffIDs",
        {"config": rootfs_field("diff_ids", ["sha256:" + "0" * 64] * 2)},
    )
    archive_guard("C29.diff_id_type", "wrong-typed rootfs DiffID", {"config": rootfs_field("diff_ids", [1])})
    archive_guard(
        "C30.diff_id_algorithm",
        "non-sha256 rootfs DiffID",
        {"config": rootfs_field("diff_ids", ["sha512:" + "0" * 64])},
    )
    archive_guard(
        "C31.diff_id_grammar", "malformed rootfs DiffID grammar", {"config": rootfs_field("diff_ids", ["sha256:BAD"])}
    )
    archive_guard(
        "C32.layer_diff_id_count",
        "layer descriptor and DiffID count disagreement",
        {"config": rootfs_field("diff_ids", ["sha256:" + "0" * 64] * 3)},
    )

    archive_guard("Y01.layer_object", "wrong-typed layer descriptor", {"manifest": field("layers", [1])})
    archive_guard("Y02.layer_keys", "extra layer descriptor key", {"layer_descriptor": field("extra", 1)})
    archive_guard(
        "Y03.layer_media_uncompressed",
        "uncompressed layer mediaType",
        {"layer_descriptor": field("mediaType", "application/vnd.oci.image.layer.v1.tar")},
    )
    archive_guard(
        "Y04.layer_media_zstd",
        "zstd layer mediaType",
        {"layer_descriptor": field("mediaType", "application/vnd.oci.image.layer.v1.tar+zstd")},
    )
    archive_guard(
        "Y05.layer_media_nondistributable",
        "non-distributable layer mediaType",
        {"layer_descriptor": field("mediaType", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip")},
    )
    archive_guard("Y06.layer_media_type", "unknown layer mediaType", {"layer_descriptor": field("mediaType", "bad")})
    archive_guard("Y07.layer_urls", "layer descriptor urls present", {"layer_descriptor": field("urls", [])})
    archive_guard("Y08.layer_data", "layer descriptor data present", {"layer_descriptor": field("data", "")})
    archive_guard(
        "Y09.layer_artifact_type",
        "layer descriptor artifactType present",
        {"layer_descriptor": field("artifactType", "x")},
    )
    archive_guard(
        "Y10.layer_annotations", "layer descriptor annotations present", {"layer_descriptor": field("annotations", {})}
    )
    archive_guard(
        "Y11.layer_platform", "layer descriptor platform present", {"layer_descriptor": field("platform", {})}
    )
    archive_guard("Y12.layer_digest_type", "wrong-typed layer digest", {"layer_descriptor": field("digest", 1)})
    archive_guard(
        "Y13.layer_digest_algorithm",
        "non-sha256 layer digest",
        {"layer_descriptor": field("digest", "sha512:" + "0" * 64)},
    )
    archive_guard(
        "Y14.layer_digest_grammar",
        "malformed layer digest grammar",
        {"layer_descriptor": field("digest", "sha256:BAD")},
    )
    archive_guard("Y15.layer_size_type", "boolean layer size", {"layer_descriptor": field("size", True)})
    archive_guard("Y16.layer_size_negative", "negative layer size", {"layer_descriptor": field("size", -1)})
    archive_guard(
        "Y17.layer_size_ceiling",
        "layer descriptor size ceiling",
        {"layer_descriptor": field("size", OCI_LIMITS.descriptor_bytes + 1)},
    )
    archive_guard("Y18.layer_blob_missing", "absent layer blob", {"omit_blob_kinds": ["layer"]})
    archive_guard("Y19.layer_blob_regular", "non-regular layer blob", {"outer_members": blob_to_symlink("layer")})
    archive_guard(
        "Y20.layer_size",
        "layer descriptor size mismatch",
        {"layer_descriptor": lambda value: {**value, "size": value["size"] + 1}},
    )
    archive_guard(
        "Y21.layer_digest",
        "gzip-header-only layer descriptor digest mismatch",
        {"layer_blob_after_descriptor": _gzip_header_mutation},
    )
    archive_guard(
        "Y22.compressed_layer_bytes",
        "compressed layer byte ceiling",
        {},
        limits=replace(OCI_LIMITS, compressed_layer_bytes=1),
    )
    archive_guard("Y23.gzip_invalid", "invalid gzip stream", {"layer_blob": b"not gzip"}, coverage_kind="input-path")
    archive_guard(
        "Y24.gzip_truncated",
        "truncated gzip stream",
        {"layer_blob": lambda value: value[:-4]},
        coverage_kind="input-path",
    )
    archive_guard(
        "Y25.gzip_concatenated",
        "concatenated gzip members",
        {"layer_blob": lambda value: value + gzip.compress(b"second", mtime=0)},
    )
    archive_guard(
        "Y26.gzip_trailing", "trailing bytes after gzip stream", {"layer_blob": lambda value: value + b"trailing"}
    )
    archive_guard(
        "Y27.decoded_layer_bytes",
        "streaming decoded-layer byte ceiling",
        {},
        limits=replace(OCI_LIMITS, decoded_layer_bytes=1),
    )
    archive_guard(
        "Y28.diff_id", "decoded layer DiffID mismatch", {"config": rootfs_field("diff_ids", ["sha256:" + "0" * 64])}
    )
    archive_guard(
        "T01.layer_tar", "decoded content is not a tar", {"layer_tar": b"x" * 1024}, coverage_kind="input-path"
    )
    archive_guard(
        "T02.layer_member_count", "layer member-count ceiling", {}, limits=replace(OCI_LIMITS, layer_member_count=1)
    )
    archive_guard(
        "T03.inner_path_bytes",
        "inner path byte ceiling",
        {"layer_entries": lambda entries: [*entries, OciFixtureEntry("a" * 4097)]},
    )

    def append_layer(entry: OciFixtureEntry) -> Any:
        return lambda entries: [*entries, entry]

    archive_guard(
        "T04.inner_absolute", "absolute inner path", {"layer_entries": append_layer(OciFixtureEntry("/escape"))}
    )
    archive_guard(
        "T05.inner_traversal", "inner parent traversal", {"layer_entries": append_layer(OciFixtureEntry("../escape"))}
    )
    archive_guard(
        "T06.inner_duplicate",
        "inner normalized-name collision",
        {"layer_entries": append_layer(OciFixtureEntry("./etc/message"))},
    )
    archive_guard(
        "T07.inner_canonical",
        "safe non-canonical inner name",
        {"layer_entries": append_layer(OciFixtureEntry("safe//name"))},
    )
    additional_archive_reason(
        "T07.inner_canonical",
        "safe non-canonical ./ inner name",
        {"layer_entries": append_layer(OciFixtureEntry("./safe-name"))},
    )
    additional_archive_reason(
        "T07.inner_canonical",
        "safe non-canonical trailing-slash inner file",
        {"layer_entries": append_layer(OciFixtureEntry("safe-name/"))},
    )
    archive_guard(
        "T08.link_bytes",
        "link-target byte ceiling",
        {},
        limits=replace(OCI_LIMITS, link_bytes=2),
    )
    archive_guard(
        "T09.symlink_escape",
        "escaping symlink target",
        {"layer_entries": append_layer(OciFixtureEntry("link", kind="symlink", linkname="../../escape"))},
    )
    archive_guard(
        "T10.hardlink_escape",
        "escaping hardlink target",
        {"layer_entries": append_layer(OciFixtureEntry("hard", kind="hardlink", linkname="../escape"))},
    )
    archive_guard(
        "T11.hardlink_missing",
        "out-of-archive hardlink target",
        {"layer_entries": append_layer(OciFixtureEntry("hard", kind="hardlink", linkname="absent"))},
    )
    archive_guard(
        "T12.hardlink_cycle",
        "hardlink cycle",
        {
            "layer_entries": lambda entries: [
                *entries,
                OciFixtureEntry("cycle-a", kind="hardlink", linkname="cycle-b"),
                OciFixtureEntry("cycle-b", kind="hardlink", linkname="cycle-a"),
            ]
        },
    )

    def truncated_inner(_: bytes) -> bytes:
        info = tarfile.TarInfo("file")
        info.size = 100
        return info.tobuf(format=tarfile.USTAR_FORMAT) + b"x"

    archive_guard(
        "T13.layer_consumed_size",
        "inner header-declared size differs from consumed size",
        {"layer_tar_mutation": truncated_inner},
        coverage_kind="input-path",
    )
    archive_guard(
        "T14.layer_regular_bytes",
        "aggregate layer regular-file byte ceiling",
        {},
        limits=replace(OCI_LIMITS, layer_regular_bytes=1),
    )
    archive_guard(
        "T15.whiteout_entry", ".wh.name whiteout", {"layer_entries": append_layer(OciFixtureEntry("etc/.wh.name"))}
    )
    archive_guard(
        "T16.whiteout_opaque",
        ".wh..wh..opq whiteout",
        {"layer_entries": append_layer(OciFixtureEntry("etc/.wh..wh..opq"))},
    )
    archive_guard(
        "T17.fifo", "FIFO layer member", {"layer_entries": append_layer(OciFixtureEntry("fifo", kind="fifo"))}
    )
    archive_guard(
        "T18.character_device",
        "character-device layer member",
        {"layer_entries": append_layer(OciFixtureEntry("char", kind="character"))},
    )
    archive_guard(
        "T19.block_device",
        "block-device layer member",
        {"layer_entries": append_layer(OciFixtureEntry("block", kind="block"))},
    )
    archive_guard(
        "T20.socket", "socket layer member", {"layer_entries": append_layer(OciFixtureEntry("socket", kind="socket"))}
    )

    def unknown_member_type(payload: bytes) -> bytes:
        return _patch_tar_type(payload, "etc/message", b"V")

    archive_guard("T21.member_type", "unrepresentable layer member type", {"layer_tar_mutation": unknown_member_type})
    archive_guard(
        "P01.global_pax",
        "global PAX header",
        {"layer_tar": _raw_pax_layer([("comment", "x")], global_header=True)},
    )
    archive_guard("P02.unknown_pax", "unknown local PAX key", {"layer_tar": _raw_pax_layer([("comment", "x")])})
    archive_guard(
        "P03.duplicate_pax",
        "duplicate raw local PAX key",
        {"layer_tar": _raw_pax_layer([("path", "entry"), ("path", "entry")])},
    )
    pax_limit_records = [(f"SCHILY.xattr.user.key{index}", "x") for index in range(64)] + [("path", "entry")]
    archive_guard(
        "P04.pax_records", "raw local PAX record ceiling per member", {"layer_tar": _raw_pax_layer(pax_limit_records)}
    )
    archive_guard(
        "P05.pax_key_bytes",
        "PAX key byte ceiling",
        {"layer_tar": _raw_pax_layer([("comment", "x")])},
        limits=replace(OCI_LIMITS, pax_key_bytes=3),
    )
    archive_guard(
        "P06.pax_value_bytes",
        "PAX value byte ceiling",
        {"layer_tar": _raw_pax_layer([("path", "entry")])},
        limits=replace(OCI_LIMITS, pax_value_bytes=2),
    )

    def sparse_member(payload: bytes) -> bytes:
        return _patch_tar_type(payload, "etc/message", tarfile.GNUTYPE_SPARSE)

    archive_guard("P07.sparse", "sparse layer member", {"layer_tar_mutation": sparse_member})
    xattr_over_count = [(f"SCHILY.xattr.user.key{index}", "x") for index in range(65)]
    archive_guard("P08.xattr_count", "xattr count ceiling per member", {"layer_tar": _raw_pax_layer(xattr_over_count)})
    archive_guard(
        "P09.xattr_name",
        "unaccepted xattr name grammar",
        {"layer_tar": _raw_pax_layer([("SCHILY.xattr.bad/name", "x")])},
    )
    archive_guard(
        "P10.xattr_name_bytes",
        "xattr name byte ceiling",
        {"layer_tar": _raw_pax_layer([("SCHILY.xattr.user.long", "x")])},
        limits=replace(OCI_LIMITS, xattr_name_bytes=2),
    )
    archive_guard(
        "P11.xattr_value_bytes",
        "xattr value byte ceiling",
        {"layer_tar": _raw_pax_layer([("SCHILY.xattr.user.key", "long")])},
        limits=replace(OCI_LIMITS, xattr_value_bytes=2),
    )

    missing_schema = tmp_path / "missing-content-identity.schema.json"
    direct_guard(
        "R01.schema_missing",
        "missing content-identity schema",
        lambda context: _load_content_identity_schema(missing_schema, context),
        coverage_kind="input-path",
    )
    malformed_schema = tmp_path / "malformed-content-identity.schema.json"
    malformed_schema.write_text("{", encoding="utf-8")
    direct_guard(
        "R02.schema_json",
        "malformed content-identity schema",
        lambda context: _load_content_identity_schema(malformed_schema, context),
        coverage_kind="input-path",
    )
    missing_record = tmp_path / "missing-content-identity.json"
    direct_guard(
        "R03.record_missing",
        "missing content-identity record",
        lambda context: load_content_identity_record(
            missing_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
        coverage_kind="input-path",
    )
    empty_record = tmp_path / "empty-content-identity.json"
    empty_record.write_bytes(b"")
    direct_guard(
        "R04.record_empty",
        "empty content-identity record",
        lambda context: load_content_identity_record(
            empty_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    malformed_record = tmp_path / "malformed-content-identity.json"
    malformed_record.write_text("{", encoding="utf-8")
    direct_guard(
        "R05.record_json",
        "malformed content-identity record",
        lambda context: load_content_identity_record(
            malformed_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
        coverage_kind="input-path",
    )

    schema_mutants: list[tuple[str, Any]] = []
    unknown_property = _json_clone(valid.record)
    unknown_property["unknown"] = True
    schema_mutants.append(("unknown property schema mutant", unknown_property))
    boolean_integer = _json_clone(valid.record)
    boolean_integer["schema_version"] = True
    schema_mutants.append(("boolean-as-integer schema mutant", boolean_integer))
    wrong_type = _json_clone(valid.record)
    wrong_type["canonical_rootfs_digest"] = 1
    schema_mutants.append(("wrong-type schema mutant", wrong_type))
    missing_property = _json_clone(valid.record)
    del missing_property["profile_version"]
    schema_mutants.append(("missing required property schema mutant", missing_property))

    def schema_mutant_runner(context: OciGuardContext) -> None:
        for _, mutant in schema_mutants:
            try:
                validate_content_identity_record(
                    mutant,
                    architecture="amd64",
                    config_platform=valid.config_platform,
                    diff_ids=valid.diff_ids,
                    context=context,
                )
            except ReproError as exc:
                if str(exc) != f"R06.record_schema: {OCI_GUARD_REASONS['R06.record_schema']}":
                    raise
            else:
                raise ReproError("content-identity schema mutant unexpectedly passed")
        raise ReproError(f"R06.record_schema: {OCI_GUARD_REASONS['R06.record_schema']}")

    direct_guard(
        "R06.record_schema",
        "unknown, boolean-integer, wrong-type, and missing-property schema mutants",
        schema_mutant_runner,
    )
    platform_record = _json_clone(valid.record)
    platform_record["platform"]["architecture"] = "arm64"
    direct_guard(
        "R07.record_platform",
        "record platform/config disagreement",
        lambda context: validate_content_identity_record(
            platform_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    positions_record = _json_clone(valid.record)
    positions_record["layers"][0]["position"] = 1
    direct_guard(
        "R08.record_positions",
        "non-contiguous layer position",
        lambda context: validate_content_identity_record(
            positions_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    duplicate_positions = _json_clone(valid.record)
    duplicate_positions["layers"].append({**duplicate_positions["layers"][0]})
    expected_positions_reason = f"R08.record_positions: {OCI_GUARD_REASONS['R08.record_positions']}"
    try:
        validate_content_identity_record(
            duplicate_positions,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
        )
    except ReproError as exc:
        if str(exc) != expected_positions_reason:
            raise ReproError(
                f"duplicate record positions reached {exc!s}; expected {expected_positions_reason}"
            ) from exc
    else:
        raise ReproError("duplicate record positions unexpectedly passed")
    digest_record = _json_clone(valid.record)
    digest_record["config"]["digest"] = "sha256:BAD"
    direct_guard(
        "R09.record_digest",
        "record digest grammar violation",
        lambda context: validate_content_identity_record(
            digest_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    layer_count_record = _json_clone(valid.record)
    layer_count_record["layers"].append({**layer_count_record["layers"][0], "position": 1})
    direct_guard(
        "R10.record_layer_count",
        "record layer-count/DiffID-count disagreement",
        lambda context: validate_content_identity_record(
            layer_count_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    checks_record = _json_clone(valid.record)
    checks_record["checks"] = checks_record["checks"][:-1]
    direct_guard(
        "R11.record_checks",
        "incomplete record check inventory",
        lambda context: validate_content_identity_record(
            checks_record,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    existing_output = tmp_path / "content-identity-existing.json"
    existing_output.write_text("existing\n", encoding="utf-8")
    direct_guard(
        "R12.output_exists",
        "pre-existing output target",
        lambda context: emit_content_identity_record(
            valid.record,
            existing_output,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )
    absent_parent_output = tmp_path / "absent-parent" / "record.json"
    direct_guard(
        "R13.output_parent",
        "output parent is absent",
        lambda context: emit_content_identity_record(
            valid.record,
            absent_parent_output,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
            context=context,
        ),
    )

    failed_output = tmp_path / "failed-content-identity.json"
    invalid_for_emission = _json_clone(valid.record)
    invalid_for_emission["unknown"] = True
    try:
        emit_content_identity_record(
            invalid_for_emission,
            failed_output,
            architecture="amd64",
            config_platform=valid.config_platform,
            diff_ids=valid.diff_ids,
        )
    except ReproError:
        pass
    else:
        raise ReproError("schema-invalid content-identity emission unexpectedly passed")
    temporary_pattern = f".{failed_output.name}.*.tmp"
    if failed_output.exists() or list(tmp_path.glob(temporary_pattern)):
        raise ReproError("failed content-identity emission left a target or temporary file")

    missing_coverage = sorted(set(OCI_GUARD_REASONS) - set(coverage))
    unexpected_coverage = sorted(set(coverage) - set(OCI_GUARD_REASONS))
    if missing_coverage or unexpected_coverage:
        raise ReproError(
            "OCI guard coverage mismatch: "
            f"missing={','.join(missing_coverage) or 'none'}; "
            f"unexpected={','.join(unexpected_coverage) or 'none'}"
        )
    mutation_count = sum(item.coverage_kind == "checker-mutation" for item in coverage.values())
    input_count = sum(item.coverage_kind == "input-path" for item in coverage.values())
    print(f"OCI guard inventory coverage: {len(coverage)}/{len(OCI_GUARD_REASONS)} exact IDs")
    print(f"OCI checker-mutation coverage: {mutation_count}/{mutation_count} neutralizations detected")
    print(f"OCI exception input-path coverage: {input_count}/{input_count} exact reasons")
    print(f"OCI independent oracle: OCI={OCI_ORACLE_DIGEST} Docker-save={OCI_ORACLE_DIGEST}")
    print("OCI failed-emission lifecycle: no target and no temporary")
    return coverage


def make_tar(path: Path, entries: list[FixtureEntry]) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, kind, mode, uid, gid, mtime, linkname, xattrs in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = uid
            info.gid = gid
            info.mtime = mtime
            if xattrs:
                info.pax_headers = {f"{XATTR_PAX_PREFIX}{key}": value for key, value in xattrs.items()}
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                archive.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))


def flipped_sha256(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def run_main_silently(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        left_tar = tmp_path / "left.tar"
        right_tar = tmp_path / "right.tar"
        make_tar(
            left_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/content", b"abcdef", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mode", b"same-mode-body", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/left-only", b"left", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/xattr", b"cap-body", "file", 0o644, 0, 0, 10, "", {"security.capability": "\x01\x00\x02"}),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/libx.so", {}),
                ("usr", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3.12", b"elf-bytes", "file", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3", None, "hardlink", 0o755, 0, 0, 10, "usr/bin/python3.12", {}),
                (RPMDB_PATH, b"rpmdb", "file", 0o644, 0, 0, 10, "", {}),
                (FIPS_SO_PATH, b"fips", "file", 0o755, 0, 0, 10, "", {}),
            ],
        )
        make_tar(
            right_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/content", b"abcxef", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 11, "", {}),
                ("etc/mode", b"same-mode-body", "file", 0o600, 0, 0, 10, "", {}),
                ("etc/right-only", b"right", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/xattr", b"cap-body", "file", 0o644, 0, 0, 10, "", {"security.capability": "\x01\x00\x03"}),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/liby.so", {}),
                ("usr", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3.12", b"elf-bytes", "file", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3", None, "hardlink", 0o755, 0, 0, 10, "usr/bin/python3.12", {}),
                (RPMDB_PATH, b"rpmdb", "file", 0o644, 0, 0, 10, "", {}),
                (FIPS_SO_PATH, b"fips", "file", 0o755, 0, 0, 10, "", {}),
            ],
        )
        result = compare_entries(load_tar(left_tar), load_tar(right_tar))
        summary = result["summary"]
        assert isinstance(summary, dict)
        if summary["differing_paths"] != 7:
            raise ReproError(f"self-test differing path count mismatch: {summary}")
        classes = summary["classification_counts"]
        assert isinstance(classes, dict)
        expected = {
            "content-differs": 2,
            "mtime-differs": 1,
            "mode-or-owner-differs": 1,
            "present-in-one-only": 2,
            "xattrs-differ": 1,
        }
        if classes != expected:
            raise ReproError(f"self-test classification mismatch: {classes}")

        identical_tar = tmp_path / "identical.tar"
        shutil.copyfile(left_tar, identical_tar)
        identical = compare_entries(load_tar(left_tar), load_tar(identical_tar))
        if not identical["byte_identical"]:
            raise ReproError("self-test identical tar comparison failed")

        left_entries = load_tar(left_tar)
        hardlink_entry = left_entries["usr/bin/python3"]
        if hardlink_entry.nlink_group != "usr/bin/python3.12":
            raise ReproError("self-test hardlink member did not carry its hardlink-group identity")
        xattr_entry = left_entries["etc/xattr"]
        if not xattr_entry.xattrs.startswith("security.capability="):
            raise ReproError("self-test xattr member did not carry a hashed xattr map")
        if left_entries["etc/identical"].xattrs != "":
            raise ReproError("self-test xattr-free member must carry an empty xattr map")

        base_digest = canonical_rootfs_digest(left_entries)
        content_entry = left_entries["etc/identical"]
        content_mutated = dict(left_entries)
        content_bytes_mutated = b"tame"
        content_mutated["etc/identical"] = replace(
            content_entry,
            sha256=hashlib.sha256(content_bytes_mutated).hexdigest(),
            data=content_bytes_mutated,
        )
        if canonical_rootfs_digest(content_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored file content changes")

        mode_mutated = dict(left_entries)
        mode_mutated["etc/identical"] = replace(content_entry, mode=content_entry.mode ^ 0o100)
        if canonical_rootfs_digest(mode_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored mode changes")

        mtime_mutated = dict(left_entries)
        mtime_mutated["etc/identical"] = replace(content_entry, mtime=content_entry.mtime + 1)
        if canonical_rootfs_digest(mtime_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored mtime changes")

        nlink_mutated = dict(left_entries)
        nlink_mutated["usr/bin/python3"] = replace(hardlink_entry, nlink_group="usr/bin/python3-other")
        if canonical_rootfs_digest(nlink_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored hardlink-group changes")
        nlink_compare = compare_entries(left_entries, nlink_mutated)
        nlink_diffs = cast("list[dict[str, Any]]", nlink_compare["differences"])
        if len(nlink_diffs) != 1 or nlink_diffs[0]["classification"] != "hardlink-group-differs":
            raise ReproError(f"self-test hardlink-group classification mismatch: {nlink_diffs}")

        xattr_mutated = dict(left_entries)
        xattr_mutated["etc/xattr"] = replace(xattr_entry, xattrs="security.capability=" + "0" * 64)
        if canonical_rootfs_digest(xattr_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored xattr changes")
        xattr_compare = compare_entries(left_entries, xattr_mutated)
        xattr_diffs = cast("list[dict[str, Any]]", xattr_compare["differences"])
        if len(xattr_diffs) != 1 or xattr_diffs[0]["classification"] != "xattrs-differ":
            raise ReproError(f"self-test xattrs classification mismatch: {xattr_diffs}")

        roundtrip_tar = tmp_path / "roundtrip.tar"
        write_rootfs_tar(left_entries, roundtrip_tar)
        if canonical_rootfs_digest(load_tar(roundtrip_tar)) != base_digest:
            raise ReproError("self-test write_rootfs_tar did not preserve hardlink/xattr fidelity")

        facts = rootfs_facts(left_entries)
        rootfs_digest = facts["rootfs_digest"]
        rpmdb_sha256 = facts["rpmdb_sha256"]
        if not isinstance(rootfs_digest, str) or not isinstance(rpmdb_sha256, str):
            raise ReproError("self-test could not compute rootfs facts")

        valid_contract = tmp_path / "contract.valid.json"
        valid_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest, "arm64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": rpmdb_sha256, "arm64": rpmdb_sha256},
                    }
                }
            ),
            encoding="utf-8",
        )
        common_args = [
            "--left-tar",
            str(left_tar),
            "--right-tar",
            str(identical_tar),
            "--assert-byte-identical",
            "--report",
            str(tmp_path / "report.json"),
            "--summary",
            str(tmp_path / "summary.txt"),
        ]
        if (
            run_main_silently(
                [
                    *common_args,
                    "--expect-from-contract",
                    str(valid_contract),
                    "--platform",
                    "linux/amd64",
                ]
            )
            != 0
        ):
            raise ReproError("self-test expected contract assertion to pass")

        single_args = [
            "--rootfs-tar",
            str(left_tar),
            "--arch",
            "amd64",
            "--expect-from-contract",
            str(valid_contract),
        ]
        if run_main_silently(single_args) != 0:
            raise ReproError("self-test expected single-rootfs contract assertion to pass")
        print("single-rootfs contract self-test (positive): ok")

        mutated_contract = tmp_path / "contract.mutated.json"
        mutated_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": flipped_sha256(rpmdb_sha256)},
                    }
                }
            ),
            encoding="utf-8",
        )
        mutated_args = [
            "--rootfs-tar",
            str(left_tar),
            "--arch",
            "amd64",
            "--expect-from-contract",
            str(mutated_contract),
        ]
        if run_main_silently(mutated_args) == 0:
            raise ReproError("self-test expected mutated single-rootfs contract assertion to fail")
        print("single-rootfs contract self-test (mutated negative): ok")

        if run_main_silently([*common_args, "--expect-rootfs-digest", flipped_sha256(rootfs_digest)]) == 0:
            raise ReproError("self-test expected rootfs digest mismatch to fail")

        if run_main_silently([*common_args, "--expect-from-contract", str(tmp_path / "missing.json")]) == 0:
            raise ReproError("self-test expected missing contract to fail")

        missing_key_contract = tmp_path / "contract.missing-key.json"
        missing_key_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": rpmdb_sha256},
                    }
                }
            ),
            encoding="utf-8",
        )
        if (
            run_main_silently(
                [
                    *common_args,
                    "--expect-from-contract",
                    str(missing_key_contract),
                    "--platform",
                    "linux/arm64",
                ]
            )
            == 0
        ):
            raise ReproError("self-test expected missing platform contract key to fail")

        if run_main_silently(["--left-tar", str(left_tar), "--right-tar", str(identical_tar)]) == 0:
            raise ReproError("self-test expected default path resolution without --repo-root to fail")
        _run_oci_self_test(tmp_path)
    print("reproducibility assertion self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert one exported rootfs against the contract, or build/export two rootfs trees and compare."
    )
    parser.add_argument("--self-test", action="store_true", help="run Docker-free comparison checks")
    parser.add_argument("--oci-layout", type=Path, help="validate one OCI layout tar and derive content identity")
    parser.add_argument(
        "--content-identity-output",
        type=Path,
        help="atomically write the validated OCI content-identity record",
    )
    parser.add_argument(
        "--print-oci-guard-inventory",
        action="store_true",
        help="print the stable OCI guard IDs and exact rejection reasons",
    )
    parser.add_argument("--assert-byte-identical", action="store_true", help="exit non-zero if any rootfs path differs")
    parser.add_argument("--expect-rootfs-digest", help="exit non-zero unless both rootfs digests match this sha256")
    parser.add_argument(
        "--expect-rpmdb-sha256",
        help="exit non-zero unless both rpmdb.sqlite digests match this sha256",
    )
    parser.add_argument(
        "--expect-from-contract",
        nargs="?",
        const=CONTRACT_DEFAULT,
        type=Path,
        help=f"load expected reproducibility digests from a contract file (default {DEFAULT_CONTRACT_RELATIVE})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="repository root used to resolve default report/workdir/context/dockerfile/contract paths",
    )
    parser.add_argument("--left-tar", type=Path, help="compare an existing left exported rootfs tar")
    parser.add_argument("--right-tar", type=Path, help="compare an existing right exported rootfs tar")
    parser.add_argument("--rootfs-tar", type=Path, help="assert one exported rootfs tar against the contract")
    parser.add_argument("--arch", choices=("amd64", "arm64"), help="contract architecture for --rootfs-tar")
    parser.add_argument(
        "--report",
        type=Path,
        help=f"write JSON diff report (default {DEFAULT_REPORT_RELATIVE_TEMPLATE} under --repo-root)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help=f"write human-readable report (default {DEFAULT_SUMMARY_RELATIVE_TEMPLATE} under --repo-root)",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        help=f"working directory for rootfs exports (default {DEFAULT_WORKDIR_RELATIVE} under --repo-root)",
    )
    parser.add_argument(
        "--platform", default=os.environ.get("PLATFORM", "linux/amd64"), help="single platform to build and export"
    )
    parser.add_argument("--image-prefix", default=DEFAULT_IMAGE_PREFIX, help="temporary local image name prefix")
    parser.add_argument("--ubi-minimal-image", help="forwarded to the build as --build-arg UBI_MINIMAL_IMAGE")
    parser.add_argument("--base-micro-image", help="forwarded to the build as --build-arg BASE_MICRO_IMAGE")
    parser.add_argument("--progress", default=os.environ.get("BUILDKIT_PROGRESS", "plain"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0

        if args.print_oci_guard_inventory:
            with tempfile.TemporaryDirectory() as temporary:
                coverage = _run_oci_self_test(Path(temporary))
            for guard_id in sorted(OCI_GUARD_REASONS):
                evidence = coverage[guard_id]
                print(
                    "\t".join(
                        [
                            guard_id,
                            OCI_GUARD_REASONS[guard_id],
                            evidence.positive_fixture,
                            evidence.negative_fixture,
                            evidence.coverage_kind,
                        ]
                    )
                )
            return 0

        if args.oci_layout is not None:
            if args.arch is None:
                raise ReproError("--arch is required with --oci-layout")
            if args.content_identity_output is None:
                raise ReproError("--content-identity-output is required with --oci-layout")
            if args.rootfs_tar is not None or args.left_tar is not None or args.right_tar is not None:
                raise ReproError("--oci-layout cannot be combined with rootfs or comparison inputs")
            identity = read_oci_content_identity(args.oci_layout, args.arch)
            emit_content_identity_record(
                identity.record,
                args.content_identity_output,
                architecture=args.arch,
                config_platform=identity.config_platform,
                diff_ids=identity.diff_ids,
            )
            print(f"validated OCI content identity for linux/{args.arch}")
            print(f"canonical_rootfs_digest: {identity.record['canonical_rootfs_digest']}")
            print(f"wrote content-identity record: {args.content_identity_output}")
            return 0

        if args.content_identity_output is not None:
            raise ReproError("--content-identity-output requires --oci-layout")

        contract = resolve_contract(args)

        if args.rootfs_tar is not None:
            if args.left_tar is not None or args.right_tar is not None:
                raise ReproError("--rootfs-tar cannot be combined with --left-tar or --right-tar")
            if args.arch is None:
                raise ReproError("--arch is required with --rootfs-tar")
            if contract is None:
                raise ReproError("--expect-from-contract is required with --rootfs-tar")
            if args.assert_byte_identical:
                raise ReproError("--assert-byte-identical cannot be combined with --rootfs-tar")
            if args.expect_rootfs_digest is not None or args.expect_rpmdb_sha256 is not None:
                raise ReproError("single-rootfs mode accepts expectations only from --expect-from-contract")
            assert_single_rootfs(args.rootfs_tar, args.arch, contract)
            return 0

        if args.arch is not None:
            raise ReproError("--arch requires --rootfs-tar")

        if bool(args.left_tar) != bool(args.right_tar):
            raise ReproError("--left-tar and --right-tar must be provided together")

        report_path, summary_path = resolve_report_paths(args)
        if args.left_tar and args.right_tar:
            left_tar = args.left_tar
            right_tar = args.right_tar
            builds: list[dict[str, object]] = [
                {"rootfs_tar": str(left_tar)},
                {"rootfs_tar": str(right_tar)},
            ]
        else:
            left_tar, right_tar, builds = build_and_export(args)

        left_entries = load_tar(left_tar)
        right_entries = load_tar(right_tar)
        comparison = compare_entries(left_entries, right_entries)
        add_rootfs_facts(builds, left_entries, right_entries)
        report: dict[str, Any] = {
            "schema_version": 1,
            "mode": "assert" if args.assert_byte_identical else "report",
            "builds": builds,
            **resolved_report_fields(builds, args.platform),
            **comparison,
        }
        write_reports(report, report_path, summary_path)

        assert_expectations(builds, collect_expectations(args, contract))
        if args.assert_byte_identical and not report["byte_identical"]:
            return 1
        return 0
    except ReproError as exc:
        print(f"reproducibility assertion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
