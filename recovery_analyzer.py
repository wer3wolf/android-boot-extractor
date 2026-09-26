#!/usr/bin/env python3
"""
Android Recovery Image Analyzer & TWRP Porting Tool
-----------------------------------------------------
Professional tool for:
1. Finding and analyzing recovery.img from firmware
2. Extracting recovery ramdisk
3. Scanning recovery partition structure
4. Identifying fstab and init.rc configurations
5. Generating TWRP device tree skeleton for MT8163

Usage:
    python recovery_analyzer.py /path/to/recovery.img
    python recovery_analyzer.py /path/to/firmware/folder
    python recovery_analyzer.py
"""

from __future__ import annotations

import argparse
import gzip
import json
import lzma
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
    """Parse boot/recovery image header."""
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


def find_recovery_images(search_path: Path) -> List[Path]:
    """Find recovery.img files in a directory tree."""
    images = []
    
    if search_path.is_file():
        if search_path.name.lower() in ("recovery.img", "recovery-sign.img"):
            return [search_path]
    
    if search_path.is_dir():
        for path in search_path.rglob("*"):
            if path.is_file() and path.name.lower() in ("recovery.img", "recovery-sign.img"):
                images.append(path)
    
    return sorted(images)


def validate_boot_header(header: Dict[str, Any], file_size: int) -> Tuple[bool, List[str]]:
    """Validate boot/recovery header fields."""
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
            f"File too small for recovery image (needs {total_needed}, have {file_size})"
        )

    return len(issues) == 0, issues


def write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def detect_compression(raw: bytes) -> Tuple[bytes, str]:
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

        if file_type == 0o040000:
            target.mkdir(parents=True, exist_ok=True)
        elif file_type == 0o100000:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive_data[data_start:data_end])
        elif file_type == 0o120000:
            target.parent.mkdir(parents=True, exist_ok=True)
            link_target = archive_data[data_start:data_end].decode("utf-8", errors="replace")
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


def scan_recovery_critical_files(root: Path) -> Dict[str, List[str]]:
    """Scan recovery ramdisk for critical files."""
    categories = {
        "init_scripts": [],
        "fstab_files": [],
        "recovery_files": [],
        "system_files": [],
        "sbin_files": [],
    }

    if not root.exists():
        return categories

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        name = path.name
        rel = str(path.relative_to(root)).replace("\\", "/")

        # Categorize files
        if name in ("init.rc", "init") or "init" in name:
            categories["init_scripts"].append(rel)
        elif "fstab" in name:
            categories["fstab_files"].append(rel)
        elif name in ("recovery.rc", "recovery"):
            categories["recovery_files"].append(rel)
        elif name in ("default.prop", "build.prop"):
            categories["system_files"].append(rel)
        elif rel.startswith("sbin/"):
            categories["sbin_files"].append(rel)

    return {k: sorted(set(v)) for k, v in categories.items()}


def extract_fstab_content(root: Path) -> Optional[str]:
    """Extract fstab.* file content for TWRP porting."""
    for fstab_file in root.rglob("fstab*"):
        if fstab_file.is_file():
            try:
                content = fstab_file.read_text(encoding="utf-8", errors="replace")
                return content
            except Exception:
                continue
    return None


def extract_init_rc(root: Path) -> Optional[str]:
    """Extract init.rc file content."""
    init_rc = root / "init.rc"
    if init_rc.exists():
        try:
            return init_rc.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    return None


def print_header_info(header: Dict[str, Any], image_type: str = "RECOVERY") -> None:
    """Print human-readable header info."""
    print("\n" + "=" * 70)
    print(f"{image_type} IMAGE HEADER")
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
    print("RECOVERY RAMDISK CONTENTS")
    print("=" * 70)

    for category, files in scan_results.items():
        if files:
            print(f"\n  {category.replace('_', ' ').upper()}:")
            for f in files[:15]:
                print(f"    - {f}")
            if len(files) > 15:
                print(f"    ... and {len(files) - 15} more")
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


def extract_recovery_image(image_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Extract all recovery image sections."""
    data = image_path.read_bytes()
    boot_offset = find_boot_magic(data)
    header = parse_boot_header(data, boot_offset)

    recovery_dir = out_dir / "recovery_img"
    recovery_dir.mkdir(parents=True, exist_ok=True)

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
        write_bytes(recovery_dir / "kernel", kernel_data)
    if ramdisk_data:
        write_bytes(recovery_dir / "ramdisk.raw", ramdisk_data)
    if second_data:
        write_bytes(recovery_dir / "second.bin", second_data)
    if dt_data:
        write_bytes(recovery_dir / "dtb.bin", dt_data)

    return {
        "recovery_dir": str(recovery_dir),
        "kernel": str(recovery_dir / "kernel") if kernel_data else None,
        "ramdisk_raw": str(recovery_dir / "ramdisk.raw") if ramdisk_data else None,
        "second": str(recovery_dir / "second.bin") if second_data else None,
        "dtb": str(recovery_dir / "dtb.bin") if dt_data else None,
    }


def unpack_recovery_ramdisk(ramdisk_path: Path, out_dir: Path) -> Dict[str, Any]:
    """Unpack recovery ramdisk CPIO archive."""
    ramdisk_raw = ramdisk_path.read_bytes()
    ramdisk_dir = out_dir / "recovery_ramdisk"
    extracted_dir = ramdisk_dir / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    write_bytes(ramdisk_dir / "ramdisk.raw", ramdisk_raw)

    payload, compression = detect_compression(ramdisk_raw)
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


def generate_twrp_device_tree(
    header: Dict[str, Any],
    fstab_content: Optional[str],
    out_dir: Path,
) -> None:
    """Generate TWRP device tree skeleton for MT8163."""
    device_tree_dir = out_dir / "twrp_device_tree"
    device_tree_dir.mkdir(parents=True, exist_ok=True)

    board_name = header.get("name", "mt8163").strip() or "mt8163"
    device_codename = "ac80ox"  # From your device

    # Create device/vendor/device directory
    device_dir = device_tree_dir / "device" / "archos" / device_codename
    device_dir.mkdir(parents=True, exist_ok=True)

    # BoardConfig.mk
    boardconfig = f"""# TWRP Device Configuration for Archos AC80OX (MT8163)
# Generated by recovery_analyzer.py

# Platform
TARGET_ARCH := arm
TARGET_ARCH_VARIANT := armv7-a-neon
TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_CPU_VARIANT := cortex-a53
BOARD_USES_QCOM_HARDWARE := false

# Kernel
TARGET_KERNEL_CONFIG := ac80ox_defconfig
BOARD_KERNEL_PAGESIZE := {header.get('page_size', 2048)}
BOARD_KERNEL_CMDLINE := {header.get('cmdline', 'bootopt=64S3,32N2,64N2')}
BOARD_MKBOOTIMG_ARGS := --kernel_offset 0x00000000 --ramdisk_offset 0x04000000 --tags_offset 0x0e000000 --base 0x40000000
BOARD_CUSTOM_BOOTIMG_MK := device/{device_codename}/bootimg.mk

# Partitions (from MTK scatter file)
BOARD_BOOTIMAGE_PARTITION_SIZE := 0x1000000
BOARD_RECOVERYIMAGE_PARTITION_SIZE := 0x1000000
BOARD_SYSTEMIMAGE_PARTITION_SIZE := 0xaf000000
BOARD_USERDATAIMAGE_PARTITION_SIZE := 0x42000000
BOARD_CACHEIMAGE_PARTITION_SIZE := 0x1a800000

# File systems
TARGET_USERIMAGES_USE_EXT4 := true
TARGET_USERIMAGES_USE_F2FS := false

# Storage
TARGET_NO_KERNEL := false
BOARD_HAS_LARGE_FILESYSTEM := true
TARGET_RECOVERY_PIXEL_FORMAT := RGBA_8888

# TWRP
BOARD_HAS_NO_REAL_SDCARD := true
RECOVERY_SDCARD_ON_DATA := true
TW_EXTERNAL_STORAGE_PATH := "/sdcard"
TW_EXTERNAL_STORAGE_MOUNT_POINT := "sdcard"
TW_DEFAULT_EXTERNAL_STORAGE := true
TW_MAX_BRIGHTNESS := 255
TW_BRIGHTNESS_PATH := "/sys/class/leds/lcd-backlight/brightness"
TW_CUSTOM_CPU_TEMP_PATH := "/sys/class/thermal/thermal_zone0/temp"
TW_THEME := portrait_mdpi
RECOVERY_TOUCHSCREEN_SWAP_XY := false
RECOVERY_TOUCHSCREEN_FLIP_X := false
RECOVERY_TOUCHSCREEN_FLIP_Y := false
TARGET_RECOVERY_LCD_BACKLIGHT_PATH := "/sys/class/leds/lcd-backlight"

# SELinux
BOARD_SEPOLICY_DIRS := device/{device_codename}/sepolicy
"""
    write_bytes(device_dir / "BoardConfig.mk", boardconfig.encode("utf-8"))

    # device.mk
    device_mk = f"""# Device configuration for Archos AC80OX

LOCAL_PATH := device_path

# Prebuilt kernel and ramdisk
ifeq (${{TARGET_DEVICE}}, {device_codename})
-include vendor/archos/proprietary/{device_codename}/BoardConfigVendor.mk
endif

# Recovery
PRODUCT_PACKAGES += \\
    recovery

# Permissions
PRODUCT_COPY_FILES += \\
    frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:system/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml
"""
    write_bytes(device_dir / "device.mk", device_mk.encode("utf-8"))

    # fstab (if available)
    if fstab_content:
        write_bytes(device_dir / "recovery.fstab", fstab_content.encode("utf-8"))
    else:
        # Generate default fstab for MT8163
        default_fstab = """# Mount points for Archos AC80OX (MT8163)
# <mount_point> <fstype> <device> <device2> <flags>

/boot          EMMC    /dev/block/mmcblk0p8     flags=display="boot"
/recovery      EMMC    /dev/block/mmcblk0p9     flags=display="recovery"
/system        EXT4    /dev/block/mmcblk0p20    flags=display="System";backup=1;wipeingui
/system_image  EMMC    /dev/block/mmcblk0p20    flags=backup=1;flashimg=1
/cache         EXT4    /dev/block/mmcblk0p21    flags=display="Cache";backup=1;wipeingui
/data          EXT4    /dev/block/mmcblk0p22    flags=display="Data";backup=1;wipeingui;formattable
/metadata      EMMC    /dev/block/mmcblk0p19    flags=display="Metadata"
/tee1          EMMC    /dev/block/mmcblk0p15    flags=display="TEE1"
/tee2          EMMC    /dev/block/mmcblk0p16    flags=display="TEE2"

# External storage
/sdcard        VFAT    /dev/block/mmcblk1p1     /dev/block/mmcblk1   flags=display="MicroSD";storage;wipeingui;removable;formattable
/usb_otg       VFAT    /dev/block/sda1          /dev/block/sda       flags=display="USB OTG";storage;removable;formattable
"""
        write_bytes(device_dir / "recovery.fstab", default_fstab.encode("utf-8"))

    # Android.mk
    android_mk = f"""LOCAL_PATH := $$(call my-dir)

include $$(CLEAR_VARS)
LOCAL_PATH := device/archos/{device_codename}
LOCAL_MODULE_TAGS := optional

# Nothing to build, this is just a configuration
include $$(call all-makefiles-under, $$(LOCAL_PATH))
"""
    write_bytes(device_dir / "Android.mk", android_mk.encode("utf-8"))

    # Create sepolicy directory
    sepolicy_dir = device_dir / "sepolicy"
    sepolicy_dir.mkdir(exist_ok=True)

    print(f"\n[+] Generated TWRP device tree at: {device_tree_dir}")
    print(f"    - BoardConfig.mk")
    print(f"    - device.mk")
    print(f"    - recovery.fstab")
    print(f"    - Android.mk")
    print(f"\n[*] Next steps to build TWRP:")
    print(f"    1. Copy device tree to TWRP source")
    print(f"    2. Modify paths and board name as needed")
    print(f"    3. Build: cd twrp && . build/envsetup.sh && lunch omni_{device_codename}-eng && make -j4 recoveryimage")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze Android recovery.img and generate TWRP device tree."
    )
    parser.add_argument("recovery_img", nargs="?", help="Path to recovery.img or firmware folder")
    parser.add_argument("-o", "--output", default="recovery_analysis", help="Output directory")
    parser.add_argument("-y", "--yes", action="store_true", help="Auto-extract without prompting")
    args = parser.parse_args()

    # Find recovery image
    recovery_img = None

    if args.recovery_img:
        search_path = Path(args.recovery_img).expanduser().resolve()
        
        if search_path.is_file():
            recovery_img = search_path
        elif search_path.is_dir():
            print(f"[+] Searching for recovery.img in: {search_path}")
            found = find_recovery_images(search_path)
            if found:
                print(f"    Found {len(found)} recovery image(s)")
                for i, img in enumerate(found, 1):
                    print(f"    {i}. {img.relative_to(search_path)}")
                if len(found) == 1:
                    recovery_img = found[0]
                else:
                    choice = input("\nSelect image (number): ").strip()
                    try:
                        recovery_img = found[int(choice) - 1]
                    except (ValueError, IndexError):
                        print("Invalid selection")
                        return 1
            else:
                print("[-] No recovery.img found")
                return 1
    else:
        value = input("Enter path to recovery.img or firmware folder: ").strip()
        if not value:
            print("No path provided")
            return 1
        
        search_path = Path(value).expanduser().resolve()
        if search_path.is_file():
            recovery_img = search_path
        elif search_path.is_dir():
            found = find_recovery_images(search_path)
            if found:
                recovery_img = found[0]
            else:
                print("[-] No recovery.img found in folder")
                return 1
        else:
            print("[-] Path not found")
            return 1

    if not recovery_img or not recovery_img.exists():
        print(f"ERROR: File not found: {recovery_img}")
        return 1

    print(f"\n[+] Analyzing: {recovery_img}")
    print(f"    Size: {recovery_img.stat().st_size} bytes ({recovery_img.stat().st_size / (1024*1024):.2f} MB)")

    try:
        data = recovery_img.read_bytes()
        boot_offset = find_boot_magic(data)
        header = parse_boot_header(data, boot_offset)

        is_valid, issues = validate_boot_header(header, len(data))
        print_header_info(header, "RECOVERY")

        if not is_valid:
            print("\n[!] WARNING: Recovery header validation issues:")
            for issue in issues:
                print(f"    - {issue}")
            if not args.yes:
                if not prompt_yes_no("Continue anyway?"):
                    return 1

        out_dir = Path(args.output).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        if not args.yes:
            if not prompt_yes_no("Extract recovery image sections?"):
                return 0

        print("\n[+] Extracting recovery sections...")
        sections = extract_recovery_image(recovery_img, out_dir)
        for key, path in sections.items():
            if path and key != "recovery_dir":
                size = Path(path).stat().st_size if Path(path).exists() else 0
                print(f"    ✓ {key}: {Path(path).name} ({size} bytes)")

        ramdisk_path = Path(sections["ramdisk_raw"]) if sections.get("ramdisk_raw") else None
        if ramdisk_path and ramdisk_path.exists():
            print("\n[+] Unpacking recovery ramdisk...")
            ramdisk_info = unpack_recovery_ramdisk(ramdisk_path, out_dir)
            print(f"    Compression: {ramdisk_info['compression']}")
            if ramdisk_info["cpio_unpacked"]:
                print(f"    ✓ CPIO unpacked: {ramdisk_info['cpio_count']} entries")
            else:
                print(f"    [!] Not a standard CPIO: {ramdisk_info.get('note', 'unknown')}")

            extracted_root = Path(ramdisk_info["extracted_path"])
            if extracted_root.exists() and ramdisk_info["cpio_unpacked"]:
                print("\n[+] Scanning recovery ramdisk for critical files...")
                scan_results = scan_recovery_critical_files(extracted_root)
                print_ramdisk_scan(scan_results)

                # Extract fstab and init.rc
                fstab_content = extract_fstab_content(extracted_root)
                init_rc_content = extract_init_rc(extracted_root)

                if fstab_content:
                    write_bytes(out_dir / "recovery.fstab", fstab_content.encode("utf-8"))
                    print(f"\n[+] Extracted recovery.fstab")

                if init_rc_content:
                    write_bytes(out_dir / "init.rc", init_rc_content.encode("utf-8"))
                    print(f"[+] Extracted init.rc")

                # Generate TWRP device tree
                print("\n[+] Generating TWRP device tree skeleton...")
                generate_twrp_device_tree(header, fstab_content, out_dir)

                # Save complete report
                report = {
                    "recovery_image": str(recovery_img),
                    "output_dir": str(out_dir),
                    "header": header,
                    "extracted_sections": sections,
                    "ramdisk": ramdisk_info,
                    "critical_files": scan_results,
                    "has_fstab": fstab_content is not None,
                    "has_init_rc": init_rc_content is not None,
                }
                report_path = out_dir / "recovery_analysis_report.json"
                report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(f"\n[+] Analysis report saved to: {report_path}")

        print(f"\n[✓] Recovery analysis complete!")
        print(f"    Output directory: {out_dir}")
        return 0

    except Exception as exc:
        print(f"\nERROR: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
