"""
ADB Scanner module for AppGuard.

Handles all communication with Android devices via ADB (Android Debug Bridge).
Extracts package metadata, permissions, certificates, and device info.
"""

from __future__ import annotations

import re
import subprocess
import shutil
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .data_models import AppInfo, AppCertificate, ScanSummary


console = Console()


class ADBError(Exception):
    """Raised when an ADB command fails or device is not available."""
    pass


class ADBScanner:
    """Scans an Android device via ADB for installed app information."""

    # Known Play Store / official installer packages
    OFFICIAL_STORES = {
        "com.android.vending",
        "com.google.android.packageinstaller",
        "com.sec.android.app.samsungapps",
        "com.amazon.venezia",
        "com.huawei.appmarket",
        "com.xiaomi.market",
    }

    def __init__(self, adb_path: Optional[str] = None):
        """
        Initialize ADB scanner.

        Args:
            adb_path: Custom path to adb executable. If None, uses PATH.
        """
        self.adb_path = adb_path or self._find_adb()
        if not self.adb_path:
            raise ADBError(
                "ADB not found. Install Android SDK Platform Tools and ensure "
                "'adb' is on your system PATH.\n"
                "Download: https://developer.android.com/tools/releases/platform-tools"
            )

    def _find_adb(self) -> Optional[str]:
        """Locate the adb executable on the system."""
        adb = shutil.which("adb")
        if adb:
            return adb
        # Check common installation paths on Windows
        import os
        common_paths = [
            os.path.expanduser(r"~\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
            r"C:\Android\platform-tools\adb.exe",
            r"C:\Program Files\Android\platform-tools\adb.exe",
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path
        return None

    def _run_adb(self, *args: str, timeout: int = 30) -> str:
        """
        Execute an ADB command and return stdout.

        Args:
            *args: ADB command arguments (e.g., "shell", "pm", "list", "packages")
            timeout: Command timeout in seconds.

        Returns:
            Command stdout as string.

        Raises:
            ADBError: If the command fails.
        """
        cmd = [self.adb_path] + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0 and result.stderr.strip():
                raise ADBError(f"ADB command failed: {result.stderr.strip()}")
            return result.stdout
        except FileNotFoundError:
            raise ADBError(f"ADB executable not found at: {self.adb_path}")
        except subprocess.TimeoutExpired:
            raise ADBError(f"ADB command timed out after {timeout}s: {' '.join(cmd)}")

    def check_device_connected(self) -> bool:
        """
        Check if an Android device is connected and authorized.

        Returns:
            True if a device is connected and ready.

        Raises:
            ADBError: If no device is connected or device is unauthorized.
        """
        output = self._run_adb("devices")
        lines = [l.strip() for l in output.strip().splitlines() if l.strip()]

        # Filter out the header line "List of devices attached"
        device_lines = [l for l in lines if not l.startswith("List")]

        if not device_lines:
            raise ADBError(
                "No Android device connected.\n"
                "  1. Connect your device via USB\n"
                "  2. Enable USB Debugging in Developer Options\n"
                "  3. Accept the debugging prompt on your device"
            )

        for line in device_lines:
            if "unauthorized" in line:
                raise ADBError(
                    "Device is unauthorized. Please accept the USB debugging "
                    "prompt on your Android device."
                )
            if "device" in line:
                return True

        raise ADBError(
            "Device found but not ready. Check USB connection and USB debugging."
        )

    def get_device_info(self) -> dict[str, str]:
        """Get basic device information."""
        info = {}
        props = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "device_name": "ro.product.name",
        }
        for key, prop in props.items():
            try:
                value = self._run_adb("shell", "getprop", prop).strip()
                info[key] = value if value else "Unknown"
            except ADBError:
                info[key] = "Unknown"
        return info

    def get_installed_packages(self, third_party_only: bool = True) -> list[str]:
        """
        Get list of installed package names.

        Args:
            third_party_only: If True, exclude system apps (recommended).

        Returns:
            List of package name strings.
        """
        flag = "-3" if third_party_only else ""
        cmd_parts = ["shell", "pm", "list", "packages"]
        if flag:
            cmd_parts.append(flag)

        output = self._run_adb(*cmd_parts)
        packages = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return sorted(packages)

    def get_package_info(self, package_name: str) -> AppInfo:
        """
        Extract detailed information for a single package.

        Args:
            package_name: The Android package name (e.g., "com.whatsapp").

        Returns:
            Populated AppInfo dataclass.
        """
        app = AppInfo(package_name=package_name)

        # Get full dumpsys output for the package
        try:
            dumpsys = self._run_adb(
                "shell", "dumpsys", "package", package_name,
                timeout=15,
            )
        except ADBError:
            dumpsys = ""

        if dumpsys:
            self._parse_version_info(app, dumpsys)
            self._parse_permissions(app, dumpsys)
            self._parse_installer(app, dumpsys)
            self._parse_timestamps(app, dumpsys)
            self._parse_sdk_info(app, dumpsys)
            self._parse_certificate(app, dumpsys)

        # Try to get human-readable app label
        app.app_label = self._get_app_label(package_name)

        # Determine if sideloaded
        app.is_sideloaded = (
            app.installer_package not in self.OFFICIAL_STORES
            and not app.is_system_app
        )

        return app

    def _get_app_label(self, package_name: str) -> str:
        """Attempt to get the human-readable app name."""
        try:
            # Method 1: Use 'dumpsys package' applicationInfo label
            output = self._run_adb(
                "shell", "pm", "dump", package_name,
                timeout=10,
            )
            # Look for "Application Label:" in the output
            for line in output.splitlines():
                if "Application Label:" in line:
                    label = line.split("Application Label:")[-1].strip()
                    if label:
                        return label
        except ADBError:
            pass

        # Fallback: use package name's last segment as a readable name
        parts = package_name.split(".")
        if len(parts) > 1:
            return parts[-1].capitalize()
        return package_name

    def _parse_version_info(self, app: AppInfo, dumpsys: str):
        """Extract version name and code from dumpsys output."""
        for line in dumpsys.splitlines():
            line = line.strip()
            if line.startswith("versionName="):
                app.version_name = line.split("=", 1)[1].strip()
            elif line.startswith("versionCode="):
                # Format: "versionCode=123 minSdk=21 targetSdk=34"
                parts = line.split()
                for part in parts:
                    if part.startswith("versionCode="):
                        app.version_code = part.split("=", 1)[1]
                    elif part.startswith("minSdk="):
                        app.min_sdk = part.split("=", 1)[1]
                    elif part.startswith("targetSdk="):
                        app.target_sdk = part.split("=", 1)[1]

    def _parse_permissions(self, app: AppInfo, dumpsys: str):
        """Extract requested and granted permissions."""
        in_requested = False
        in_install_perms = False

        for line in dumpsys.splitlines():
            stripped = line.strip()

            # Detect requested permissions section
            if "requested permissions:" in stripped.lower():
                in_requested = True
                in_install_perms = False
                continue
            elif "install permissions:" in stripped.lower():
                in_requested = False
                in_install_perms = True
                continue
            elif stripped == "" or (not stripped.startswith("android.permission")
                                    and not stripped.startswith("com.")
                                    and in_requested):
                if not stripped.startswith("android.permission") and not stripped.startswith("com."):
                    if in_requested and stripped and not stripped.startswith(" "):
                        in_requested = False
                    if in_install_perms and stripped and ":" in stripped and "permission" not in stripped.lower():
                        in_install_perms = False

            if in_requested and stripped:
                # Permission lines look like: "android.permission.INTERNET"
                perm = stripped.rstrip(":")
                if "." in perm and not perm.startswith("//"):
                    app.requested_permissions.append(perm)

            if in_install_perms and stripped:
                # Install permission lines: "android.permission.INTERNET: granted=true"
                if "granted=true" in stripped:
                    perm_name = stripped.split(":")[0].strip()
                    if "." in perm_name:
                        app.granted_permissions.append(perm_name)

        # Also look for runtime permissions
        runtime_section = False
        for line in dumpsys.splitlines():
            stripped = line.strip()
            if "runtime permissions:" in stripped.lower():
                runtime_section = True
                continue
            if runtime_section:
                if stripped == "" or (not stripped.startswith("android.permission")
                                      and not stripped.startswith("com.")):
                    if not stripped.startswith(" ") and stripped:
                        runtime_section = False
                        continue
                if "granted=true" in stripped:
                    perm_name = stripped.split(":")[0].strip()
                    if "." in perm_name and perm_name not in app.granted_permissions:
                        app.granted_permissions.append(perm_name)

        # Deduplicate
        app.requested_permissions = list(dict.fromkeys(app.requested_permissions))
        app.granted_permissions = list(dict.fromkeys(app.granted_permissions))

    def _parse_installer(self, app: AppInfo, dumpsys: str):
        """Extract the installer package name."""
        for line in dumpsys.splitlines():
            stripped = line.strip()
            if "installerPackageName=" in stripped:
                val = stripped.split("installerPackageName=")[-1].strip()
                if val and val != "null":
                    app.installer_package = val
                    break

    def _parse_timestamps(self, app: AppInfo, dumpsys: str):
        """Extract install and update timestamps."""
        for line in dumpsys.splitlines():
            stripped = line.strip()
            if stripped.startswith("firstInstallTime="):
                app.install_time = stripped.split("=", 1)[1].strip()
            elif stripped.startswith("lastUpdateTime="):
                app.update_time = stripped.split("=", 1)[1].strip()

    def _parse_sdk_info(self, app: AppInfo, dumpsys: str):
        """Extract SDK version targets if not already found."""
        if not app.target_sdk or not app.min_sdk:
            for line in dumpsys.splitlines():
                stripped = line.strip()
                if "targetSdk=" in stripped and not app.target_sdk:
                    match = re.search(r"targetSdk=(\d+)", stripped)
                    if match:
                        app.target_sdk = match.group(1)
                if "minSdk=" in stripped and not app.min_sdk:
                    match = re.search(r"minSdk=(\d+)", stripped)
                    if match:
                        app.min_sdk = match.group(1)

    def _parse_certificate(self, app: AppInfo, dumpsys: str):
        """Extract signing certificate information."""
        cert = app.certificate
        in_signing = False

        for line in dumpsys.splitlines():
            stripped = line.strip()

            if "Signing details:" in stripped or "signing certificates:" in stripped.lower():
                in_signing = True
                continue

            if in_signing:
                if stripped.startswith("Subject:"):
                    cert.signer = stripped.split("Subject:")[-1].strip()
                elif stripped.startswith("Issuer:"):
                    cert.issuer = stripped.split("Issuer:")[-1].strip()
                elif "SHA-256" in stripped or "sha256" in stripped.lower():
                    match = re.search(r"[0-9a-fA-F:]{95}", stripped)
                    if match:
                        cert.fingerprint_sha256 = match.group(0)
                elif stripped.startswith("Valid from:"):
                    cert.valid_from = stripped.split("Valid from:")[-1].strip()
                elif stripped.startswith("Valid until:"):
                    cert.valid_to = stripped.split("Valid until:")[-1].strip()

                # Check for self-signed and debug keys
                if cert.signer and cert.issuer:
                    if cert.signer == cert.issuer:
                        cert.is_self_signed = True
                    if "debug" in cert.signer.lower() or "android debug" in cert.signer.lower():
                        cert.is_debug_signed = True

    def batch_scan(
        self,
        packages: Optional[list[str]] = None,
        third_party_only: bool = True,
    ) -> list[AppInfo]:
        """
        Scan all (or specified) packages on the device.

        Args:
            packages: Specific packages to scan, or None for all.
            third_party_only: If True and packages is None, scan only 3rd-party apps.

        Returns:
            List of AppInfo objects with extracted data.
        """
        if packages is None:
            packages = self.get_installed_packages(third_party_only=third_party_only)

        if not packages:
            console.print("[yellow]No packages found to scan.[/yellow]")
            return []

        apps: list[AppInfo] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning apps...", total=len(packages)
            )

            for pkg in packages:
                progress.update(task, description=f"[cyan]Scanning: {pkg}")
                try:
                    app_info = self.get_package_info(pkg)
                    apps.append(app_info)
                except Exception as e:
                    console.print(
                        f"  [dim red]⚠ Failed to scan {pkg}: {e}[/dim red]"
                    )
                progress.advance(task)

        return apps

    def build_scan_summary(self, apps: list[AppInfo]) -> ScanSummary:
        """
        Create a ScanSummary with device info.

        Args:
            apps: List of scanned AppInfo objects.

        Returns:
            ScanSummary with device metadata populated.
        """
        device_info = self.get_device_info()
        summary = ScanSummary(
            device_model=f"{device_info.get('manufacturer', '')} {device_info.get('model', '')}".strip(),
            android_version=device_info.get("android_version", "Unknown"),
            total_apps_scanned=len(apps),
        )
        return summary
