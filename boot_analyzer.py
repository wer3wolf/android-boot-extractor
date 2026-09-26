#!/usr/bin/env python3
"""
Android Boot Image Analyzer
----------------------------
Comprehensive tool to:
1. Scan and analyze a boot.img file
2. Extract all sections (kernel, ramdisk, DTB, second stage)
3. Unpack ramdisk CPIO
4. Scan for critical recovery/system files
5. Present a detailed report with extraction options

Usage:
    python boot_analyzer.py /path/to/boot.img
    python boot_analyzer.py
"""

from __future__ import annotations

import argparse
import gzip
import json
import lzma
import os
import posixpath
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BOOT_MAGIC = b"ANDROID!"
BOOT_HEADER_SIZE = 4096


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def decode_c_string(data: bytes) -> str:
    if not data:
        return ""
    end = data.find(b"\x00")
    if end == -1:
        end = len(data)
    return data[:end].decode("utf-8", errors="replace")


def find_boot_magic(data: bytes) -> int:
    offset = data.find(BOOT_MAGIC)
    if offset == -1:
        raise ValueError("Could not find Android boot image magic: ANDROID!")
    return offset


def parse_boot_header(data: bytes, boot_offset: int) -> Dict[str, Any]:
    """Parse boot header from data at given offset."""
    if len(data) - boot_offset < BOOT_HEADER_SIZE:
        raise ValueError(f"Boot image is too small after magic")

    header = data[boot_offset:boot_offset + BOOT_HEADER_SIZE]

    (
        kernel_size,
        kernel_addr,
        ramdisk_size,
        ramdisk_addr,
        second_size,
        second_addr,
        tags_addr,
        page_size,
        dt_size,
        unused,
    ) = struct.unpack_from("<10I", header, 8)

    name = decode_c_string(header[48:64])
    cmdline = decode_c_string(header[64:576])
    extra_cmdline = decode_c_string(header[576:1600])

    kernel_offset = boot_offset + BOOT_HEADER_SIZE
    ramdisk_offset = boot_offset + align_up(BOOT_HEADER_SIZE + kernel_size, page_size)
    second_offset = boot_offset + align_up(
        BOOT_HEADER_SIZE + kernel_size + ramdisk_size, page_size
    )
    dt_offset = boot_offset + align_up(
        BOOT_HEADER_SIZE + kernel_size + ramdisk_size + second_size, page_size
    )

    return {
        "magic": "ANDROID!",
        "boot_offset": boot_offset,
        "kernel_size": kernel_size,
        "kernel_addr": kernel_addr,
        "ramdisk_size": ramdisk_size,
        "ramdisk_addr": ramdisk_addr,
        "second_size": second_size,
        "second_addr": second_addr,
        "tags_addr": tags_addr,
        "page_size": page_size,
        "dt_size": dt_size,
        "unused": unused,
        "name": name,
        "cmdline": cmdline,
        "extra_cmdline": extra_cmdline,
        "kernel_offset": kernel_offset,
        "ramdisk_offset": ramdisk_offset,
        "second_offset": second_offset,
        "dt_offset": dt_offset,
    }


def validate_boot_header(header: Dict[str, Any], file_size: int) -> Tuple[bool, List[str]]:
    """Validate boot header fields."""
    issues = []

    if header["page_size"] == 0 or header["page_size"] > 65536:
        issues.append(f"Invalid page_size: {header['page_size']}")

    if header["kernel_size"] == 0:
        issues.append("kernel_size is zero")

    if header["ramdisk_size"] == 0:
        issues.append("ramdisk_size is zero")

    total_needed = (
        header["boot_offset"]
        + BOOT_HEADER_SIZE
        + header["kernel_size"]
        + header["ramdisk_size"]
        + header["second_size"]
        + header["dt_size"]
    )

    if total_needed > file_size:
        issues.append(
            f"File too small for boot image (needs {total_needed}, have {file_size})"
        )

    return len(issues) == 0, issues


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def detect_ramdisk_compression(raw: bytes) -> Tuple[bytes, str]:
    """Detect and decompress ramdisk payload."""
    if raw.startswith(b"\x1f\x8b"):
        return gzip.decompress(raw), "gzip"
    if raw.startswith(b"\xfd7zXZ\x00"):
        return lzma.decompress(raw), "xz"
    return raw, "none"


def safe_cpio_target(root_dir: Path, name: str) -> Path:
    """Convert CPIO name into safe output path."""
    normalized = posixpath.normpath(name)

    if normalized == ".":
        return root_dir

    if normalized.startswith("../") or normalized == "..":
        raise ValueError(f"Unsafe CPIO path: {name}")

    sanitized = normalized.lstrip("/")
    if sanitized in ("", "."):
        return root_dir

    return root_dir / sanitized.replace("/", "\\")


def cpio_extract_newc(archive_data: bytes, out_dir: Path) -> int:
    """Extract newc-format CPIO archive."""
    out_dir.mkdir(parents=True, exist_ok=True)

    pos = 0
    count = 0

    while pos + 110 <= len(archive_data):
        magic = archive_data[pos:pos + 6]

        if magic not in (b"070701", b"070702"):
            raise ValueError(f"Invalid CPIO header near offset {pos}: {magic!r}")

        header = archive_data[pos:pos + 110]
        fields = []
        for i in range(13):
            start = 6 + i * 8
            end = start + 8
            fields.append(int(header[start:end], 16))

        (
            _magic,
            _ino,
            mode,
            _uid,
            _gid,
            _nlink,
            _mtime,
            file_size,
            _dev_major,
            _dev_minor,
            _rdev_major,
            _rdev_minor,
            name_size,
        ) = fields

        name_start = pos + 110
        name_end = name_start + name_size
        if name_end > len(archive_data):
            raise ValueError(f"Truncated CPIO filename near offset {pos}")

        raw_name = archive_data[name_start:name_end]
        name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")

        data_start = (name_end + 3) & ~3
        data_end = data_start + file_size
        if data_end > len(archive_data):
            raise ValueError(f"Truncated CPIO data for '{name}'")

        if name == "TRAILER!!!":
            break

        file_type = mode & 0o170000

        try:
            target = safe_cpio_target(out_dir, name)
        except ValueError:
            pos = (data_end + 3) & ~3
            continue

        if file_type == 0o040000:  # directory
            target.mkdir(parents=True, exist_ok=True)

        elif file_type == 0o100000:  # regular file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive_data[data_start:data_end])

        elif file_type == 0o120000:  # symlink
            target.parent.mkdir(parents=True, exist_ok=True)
            link_target = archive_data[data_start:data_end].decode(
                "utf-8", errors="replace"
            )
            try:
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.symlink_to(link_target)
            except (OSError, NotImplementedError):
                fallback = target.parent / (target.name + ".link.txt")
                fallback.write_text(link_target, encoding="utf-8")

        count += 1
        pos = (data_end + 3) & ~3

    return count


def scan_for_critical_files(root: Path) -> Dict[str, List[str]]:
    """Scan ramdisk for critical Android/recovery files."""
    categories = {
        "init_scripts": [],
        "fstab_files": [],
        "recovery_files": [],
        "system_files": [],
        "device_files": [],
    }

    patterns = {
        "init_scripts": ["init.rc", "init", "ueventd.rc"],
        "fstab_files": ["fstab", "recovery.fstab"],
        "recovery_files": ["recovery.rc", "recovery-resource.rc"],
        "system_files": ["default.prop", "build.prop"],
        "device_files": ["*.dtb", "*.ko"],
    }

    if not root.exists():
        return categories

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        name = path.name
        rel = str(path.relative_to(root))

        for category, keywords in patterns.items():
            for keyword in keywords:
                if keyword.endswith("*"):
                    prefix = keyword[:-1]
                    if name.startswith(prefix):
                        categories[category].append(rel)
                elif keyword in name or name == keyword:
                    categories[category].append(rel)

    return {k: sorted(set(v)) for k, v in categories.items()}


def print_header_info(header: Dict[str, Any]) -> None:
    """Print human-readable boot header info."""
    print("\n" + "=" * 70)
    print("BOOT IMAGE HEADER")
    print("=" * 70)
    print(f"  Boot Offset:      0x{header['boot_offset']:08x}")
    print(f"  Kernel Size:      {header['kernel_size']:10} bytes (0x{header['kernel_size']:08x})")
    print(f"  Kernel Addr:      0x{header['kernel_addr']:08x}")
    print(f"  Ramdisk Size:     {header['ramdisk_size']:10} bytes (0x{header['ramdisk_size']:08x})")
    print(f"  Ramdisk Addr:     0x{header['ramdisk_addr']:08x}")
    print(f"  Second Size:      {header['second_size']:10} bytes (0x{header['second_size']:08x})")
    print(f"  Second Addr:      0x{header['second_addr']:08x}")
    print(f"  Page Size:        {header['page_size']:10} bytes")
    print(f"  DTB Size:         {header['dt_size']:10} bytes (0x{header['dt_size']:08x})")
    print(f"  Tags Addr:        0x{header['tags_addr']:08x}")
    print(f"  Board Name:       {header['name']}")
    print(f"  Cmdline:          {header['cmdline'][:60]}")
    if header['extra_cmdline']:
        print(f"  Extra Cmdline:    {header['extra_cmdline'][:60]}")
    print("=" * 70)


def print_ramdisk_scan(scan_results: Dict[str, List[str]]) -> None:
    """Print ramdisk file scan results."""
    print("\n" + "=" * 70)
    print("RAMDISK CONTENTS SCAN")
    print("=" * 70)

    for category, files in scan_results.items():
        if files:
            print(f"\n  {category.replace('_', ' ').upper()}:")
            for f in files[:10]:
                print(f"    - {f}")
            if len(files) > 10:
                print(f"    ... and {len(files) - 10} more")
        else:
            print(f"\n  {category.replace('_', ' ').upper()}: (none found)")

    print("=" * 70)


def prompt_yes_no(question: str) -> bool:
    """Prompt user for yes/no answer."""
    while True:
        answer = input(f"\n{question} [y/n]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def extract_boot_image(image_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Extract all boot image sections."""
    data = image_path.read_bytes()
    boot_offset = find_boot_magic(data)
    header = parse_boot_header(data, boot_offset)

    boot_dir = out_dir / "bootimg"
    boot_dir.mkdir(parents=True, exist_ok=True)

    kernel_data = data[
        header["kernel_offset"] : header["kernel_offset"] + header["kernel_size"]
    ]
    ramdisk_data = data[
        header["ramdisk_offset"] : header["ramdisk_offset"] + header["ramdisk_size"]
    ]
    second_data = data[
        header["second_offset"] : header["second_offset"] + header["second_size"]
    ]
    dt_data = data[header["dt_offset"] : header["dt_offset"] + header["dt_size"]]

    if kernel_data:
        write_bytes(boot_dir / "kernel", kernel_data)
    if ramdisk_data:
        write_bytes(boot_dir / "ramdisk.raw", ramdisk_data)
    if second_data:
        write_bytes(boot_dir / "second.bin", second_data)
    if dt_data:
        write_bytes(boot_dir / "dtb.bin", dt_data)

    return {
        "boot_dir": str(boot_dir),
        "kernel": str(boot_dir / "kernel") if kernel_data else None,
        "ramdisk_raw": str(boot_dir / "ramdisk.raw") if ramdisk_data else None,
        "second": str(boot_dir / "second.bin") if second_data else None,
        "dtb": str(boot_dir / "dtb.bin") if dt_data else None,
    }


def unpack_ramdisk(ramdisk_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Unpack ramdisk CPIO archive."""
    ramdisk_raw = ramdisk_path.read_bytes()
    ramdisk_dir = out_dir / "ramdisk"
    extracted_dir = ramdisk_dir / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    write_bytes(ramdisk_dir / "ramdisk.raw", ramdisk_raw)

    payload, compression = detect_ramdisk_compression(ramdisk_raw)
    write_bytes(ramdisk_dir / "ramdisk.decompressed", payload)

    result = {
        "compression": compression,
        "raw_path": str(ramdisk_dir / "ramdisk.raw"),
        "decompressed_path": str(ramdisk_dir / "ramdisk.decompressed"),
        "extracted_path": str(extracted_dir),
        "cpio_unpacked": False,
        "cpio_count": 0,
    }

    prefix = payload[:6]
    if prefix in (b"070701", b"070702"):
        count = cpio_extract_newc(payload, extracted_dir)
        result["cpio_unpacked"] = True
        result["cpio_count"] = count
    else:
        result["note"] = "Payload is not a standard CPIO archive"

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Comprehensive Android boot.img analyzer and extractor."
    )
    parser.add_argument("boot_img", nargs="?", help="Path to boot.img")
    parser.add_argument(
        "-o", "--output", default="extracted_boot_analysis", help="Output directory"
    )
    parser.add_argument(
        "-y", "--yes", action="store_true", help="Auto-extract without prompting"
    )
    args = parser.parse_args()

    try:
        if args.boot_img:
            boot_img = Path(args.boot_img).expanduser().resolve()
        else:
            value = input("Enter path to boot.img: ").strip()
            if not value:
                raise SystemExit("No file provided.")
            boot_img = Path(value).expanduser().resolve()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        return 130

    if not boot_img.exists():
        print(f"ERROR: File not found: {boot_img}")
        return 1

    print(f"\n[+] Analyzing: {boot_img}")
    print(f"    Size: {boot_img.stat().st_size} bytes")

    try:
        data = boot_img.read_bytes()
        boot_offset = find_boot_magic(data)
        header = parse_boot_header(data, boot_offset)

        is_valid, issues = validate_boot_header(header, len(data))
        print_header_info(header)

        if not is_valid:
            print("\n[!] WARNING: Boot header validation issues:")
            for issue in issues:
                print(f"    - {issue}")
            if not args.yes:
                if not prompt_yes_no("Continue anyway?"):
                    return 1

        # Extract sections
        out_dir = Path(args.output).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        if not args.yes:
            if not prompt_yes_no("Extract boot image sections?"):
                return 0

        print("\n[+] Extracting boot sections...")
        sections = extract_boot_image(boot_img, out_dir)
        for key, path in sections.items():
            if path and key != "boot_dir":
                size = Path(path).stat().st_size if Path(path).exists() else 0
                print(f"    ✓ {key}: {Path(path).name} ({size} bytes)")

        # Unpack ramdisk
        ramdisk_path = Path(sections["ramdisk_raw"])
        if ramdisk_path.exists():
            print("\n[+] Unpacking ramdisk...")
            ramdisk_info = unpack_ramdisk(ramdisk_path, out_dir)
            print(
                f"    Compression: {ramdisk_info['compression']}"
            )
            if ramdisk_info["cpio_unpacked"]:
                print(
                    f"    ✓ CPIO unpacked: {ramdisk_info['cpio_count']} entries"
                )
            else:
                print(
                    f"    [!] CPIO not a standard format: {ramdisk_info.get('note', 'unknown')}"
                )

            # Scan for critical files
            extracted_root = Path(ramdisk_info["extracted_path"])
            if extracted_root.exists():
                print("\n[+] Scanning ramdisk for critical files...")
                scan_results = scan_for_critical_files(extracted_root)
                print_ramdisk_scan(scan_results)

                # Save report
                report = {
                    "boot_image": str(boot_img),
                    "output_dir": str(out_dir),
                    "header": header,
                    "extracted_sections": sections,
                    "ramdisk": ramdisk_info,
                    "critical_files": scan_results,
                }
                report_path = out_dir / "analysis_report.json"
                report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(f"\n[+] Analysis report saved to: {report_path}")

        print(f"\n[✓] All files extracted to: {out_dir}")
        return 0

    except Exception as exc:
        print(f"\nERROR: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
