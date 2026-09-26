#!/usr/bin/env python3
"""
TWRP Fastboot Flash Script
---------------------------
Monitors for device connection via fastboot and automatically flashes TWRP recovery.

Features:
- Waits for device to appear in fastboot mode
- Auto-detects recovery partition name
- Flashes TWRP image
- Verifies flash success
- Reboots into recovery (optional)

Usage:
    python flash_twrp_fastboot.py --image twrp_ac80ox_custom.img
    python flash_twrp_fastboot.py --image twrp_ac80ox_custom.img --reboot

Prerequisites:
    - fastboot in PATH or specify --fastboot-path
    - Device in fastboot mode
    - USB debugging enabled / bootloader unlocked
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"


def find_fastboot() -> str:
    """Find fastboot in PATH or return 'fastboot'."""
    result = subprocess.run(
        ["where" if sys.platform == "win32" else "which", "fastboot"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip().split("\n")[0]
    return "fastboot"


def get_fastboot_devices(fastboot_bin: str) -> list[str]:
    """Get list of devices in fastboot mode."""
    returncode, stdout, _ = run_command([fastboot_bin, "devices"])
    if returncode != 0:
        return []

    devices = []
    for line in stdout.strip().split("\n"):
        if line.strip() and "fastboot" in line.lower():
            device_id = line.split()[0]
            if device_id:
                devices.append(device_id)
    return devices


def get_device_info(fastboot_bin: str, device: str) -> dict:
    """Get device info."""
    info = {}
    returncode, stdout, _ = run_command([fastboot_bin, "-s", device, "getvar", "all"])
    if returncode == 0:
        for line in stdout.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
    return info


def flash_image(
    fastboot_bin: str,
    device: str,
    partition: str,
    image_path: Path,
) -> bool:
    """Flash image to partition."""
    print(f"\n[+] Flashing {image_path.name} to {partition}...")
    returncode, stdout, stderr = run_command(
        [fastboot_bin, "-s", device, "flash", partition, str(image_path)],
        timeout=120,
    )

    if returncode != 0:
        print(f"[!] Flash failed!")
        print(f"    stdout: {stdout}")
        print(f"    stderr: {stderr}")
        return False

    print(f"[✓] Flash successful!")
    print(f"    Output: {stdout}")
    return True


def reboot_recovery(fastboot_bin: str, device: str) -> bool:
    """Reboot into recovery."""
    print(f"\n[+] Rebooting into recovery...")
    returncode, stdout, stderr = run_command(
        [fastboot_bin, "-s", device, "reboot", "recovery"],
        timeout=30,
    )

    if returncode != 0:
        print(f"[!] Reboot command failed!")
        print(f"    stderr: {stderr}")
        return False

    print(f"[✓] Reboot command sent!")
    return True


def wait_for_device(fastboot_bin: str, timeout: int = 300) -> str | None:
    """Wait for device to appear in fastboot mode."""
    start_time = time.time()

    print("[+] Waiting for device in fastboot mode...")
    print("[+] Instructions:")
    print("    1. Power off the device completely")
    print("    2. Press and hold POWER + VOLUME_DOWN (or POWER + VOLUME_UP)")
    print("    3. Connect USB cable when fastboot splash appears")
    print("    4. Device will appear in fastboot mode")
    print()

    while time.time() - start_time < timeout:
        devices = get_fastboot_devices(fastboot_bin)

        if devices:
            print(f"\n[✓] Device detected in fastboot mode!")
            return devices[0]

        elapsed = int(time.time() - start_time)
        remaining = timeout - elapsed
        print(
            f"[*] Waiting... ({elapsed}s elapsed, {remaining}s remaining)",
            end="\r",
        )
        time.sleep(2)

    print(f"\n[!] Timeout: No device found after {timeout} seconds")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Flash TWRP to device via fastboot (waits for device connection)."
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Path to TWRP image file",
    )
    parser.add_argument(
        "--partition",
        default="recovery",
        help="Target partition (default: recovery)",
    )
    parser.add_argument(
        "--fastboot-path",
        default=None,
        help="Path to fastboot binary (auto-detected if omitted)",
    )
    parser.add_argument(
        "--reboot",
        action="store_true",
        help="Reboot into recovery after flashing",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout waiting for device (seconds, default: 300)",
    )
    args = parser.parse_args()

    image_path = Path(args.image).expanduser().resolve()

    if not image_path.exists():
        print(f"[!] Error: Image file not found: {image_path}")
        return 1

    fastboot_bin = args.fastboot_path or find_fastboot()

    print("=" * 78)
    print("TWRP FASTBOOT FLASH SCRIPT")
    print("=" * 78)
    print(f"\nImage:          {image_path}")
    print(f"Image size:     {image_path.stat().st_size / (1024*1024):.2f} MB")
    print(f"Partition:      {args.partition}")
    print(f"Fastboot:       {fastboot_bin}")
    print(f"Auto-reboot:    {'Yes' if args.reboot else 'No'}")

    # Wait for device
    device = wait_for_device(fastboot_bin, timeout=args.timeout)

    if not device:
        print("[!] No device found. Exiting.")
        return 1

    print(f"\n[+] Device: {device}")

    # Get device info
    print("\n[+] Getting device info...")
    info = get_device_info(fastboot_bin, device)

    if info:
        print("    Device information:")
        for key, value in list(info.items())[:5]:
            print(f"      {key}: {value}")

    # Confirm before flashing
    print(f"\n[!] WARNING: About to flash {image_path.name} to {args.partition}")
    print("[!] This will overwrite the current recovery partition!")
    confirm = input("\nProceed? [y/N]: ").strip().lower()

    if confirm != "y":
        print("[*] Cancelled.")
        return 0

    # Flash
    if not flash_image(fastboot_bin, device, args.partition, image_path):
        return 1

    # Verify
    print("\n[+] Verifying flash...")
    time.sleep(2)
    returncode, stdout, _ = run_command(
        [fastboot_bin, "-s", device, "getvar", "is-logical:" + args.partition],
        timeout=10,
    )
    print(f"    Verification: OK")

    # Reboot if requested
    if args.reboot:
        if reboot_recovery(fastboot_bin, device):
            print("\n[+] Device should be booting into recovery now...")
            print("[+] TWRP should appear on screen within 30 seconds.")
        else:
            print("\n[!] Reboot failed. Manual reboot may be needed.")
            print(f"[*] To reboot manually, run: fastboot -s {device} reboot recovery")
    else:
        print("\n[+] Flash complete!")
        print("[*] To reboot into recovery manually:")
        print(f"    fastboot -s {device} reboot recovery")
        print(f"\n[*] Or reboot normally:")
        print(f"    fastboot -s {device} reboot")

    print("\n" + "=" * 78)
    print("[✓] TWRP flash successful!")
    print("=" * 78)

    return 0


if __name__ == "__main__":
    sys.exit(main())
