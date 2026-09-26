#!/usr/bin/env python3
"""
Android Boot Image Scanner
----------------------------
Scans a file for all occurrences of ANDROID! magic and extracts candidate boot images.
Useful for finding boot images nested inside signed blobs.

Usage:
    python debug_bootimg_scanner.py /path/to/boot-sign.img
"""

import struct
import sys
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
BOOT_HEADER_SIZE = 4096


def decode_c_string(data: bytes) -> str:
    if not data:
        return ""
    end = data.find(b"\x00")
    if end == -1:
        end = len(data)
    return data[:end].decode("utf-8", errors="replace")


def scan_file_for_boot_images(file_path: Path) -> None:
    """Scan the entire file for ANDROID! magic and print candidates."""
    data = file_path.read_bytes()
    print(f"[+] Scanning: {file_path}")
    print(f"[+] File size: {len(data)} bytes ({len(data) / (1024*1024):.2f} MB)")
    
    offsets = []
    pos = 0
    while True:
        offset = data.find(BOOT_MAGIC, pos)
        if offset == -1:
            break
        offsets.append(offset)
        pos = offset + 1
    
    print(f"\n[+] Found {len(offsets)} occurrence(s) of ANDROID! magic:\n")
    
    if not offsets:
        print("[-] No ANDROID! magic found. This is likely not an Android boot image.")
        return
    
    for i, offset in enumerate(offsets, 1):
        print(f"=== Candidate #{i} at offset 0x{offset:08x} ({offset} bytes) ===")
        
        # Check if we have enough data for a full header
        if offset + BOOT_HEADER_SIZE > len(data):
            print("  [!] Not enough data for full header (truncated)")
            continue
        
        try:
            header = data[offset:offset + BOOT_HEADER_SIZE]
            
            # Parse boot header
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
            
            cmdline = decode_c_string(header[64:576])
            
            print(f"  kernel_size:    {kernel_size:10} (0x{kernel_size:08x})")
            print(f"  ramdisk_size:   {ramdisk_size:10} (0x{ramdisk_size:08x})")
            print(f"  second_size:    {second_size:10} (0x{second_size:08x})")
            print(f"  page_size:      {page_size:10} (0x{page_size:08x})")
            print(f"  dt_size:        {dt_size:10} (0x{dt_size:08x})")
            print(f"  tags_addr:      0x{tags_addr:08x}")
            print(f"  cmdline:        {cmdline[:60]}")
            
            # Validate the header
            is_valid = True
            issues = []
            
            if page_size == 0 or page_size > 65536:
                issues.append(f"page_size is unrealistic: {page_size}")
                is_valid = False
            
            if kernel_size == 0:
                issues.append("kernel_size is zero")
                is_valid = False
            
            if ramdisk_size == 0:
                issues.append("ramdisk_size is zero")
                is_valid = False
            
            # Check if the data is large enough to contain all sections
            total_needed = (
                BOOT_HEADER_SIZE +
                kernel_size +
                ramdisk_size +
                second_size +
                dt_size +
                (4 * page_size)  # rough padding estimate
            )
            
            if offset + total_needed > len(data):
                issues.append(f"Not enough file data (need ~{total_needed}, have {len(data) - offset})")
                is_valid = False
            
            if is_valid:
                print(f"  [✓] Header looks VALID")
            else:
                print(f"  [!] Header looks SUSPECT:")
                for issue in issues:
                    print(f"      - {issue}")
            
            # Save this candidate to a file
            candidate_name = f"candidate_{i}_offset_0x{offset:08x}.img"
            candidate_path = file_path.parent / candidate_name
            
            # Save just the boot image header + sections
            end_offset = min(
                offset + BOOT_HEADER_SIZE + kernel_size + ramdisk_size + second_size + dt_size + (4 * page_size),
                len(data)
            )
            candidate_data = data[offset:end_offset]
            candidate_path.write_bytes(candidate_data)
            print(f"  [*] Saved candidate to: {candidate_name}")
            
        except Exception as e:
            print(f"  [!] Error parsing header: {e}")
        
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_bootimg_scanner.py /path/to/boot-sign.img")
        sys.exit(1)
    
    file_path = Path(sys.argv[1]).expanduser().resolve()
    
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)
    
    scan_file_for_boot_images(file_path)
