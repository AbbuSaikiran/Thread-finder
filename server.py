"""
AppGuard API Server

Lightweight Python server that:
1. Serves the web dashboard (static files)
2. Provides REST API endpoints for ADB device scanning
3. Bridges the web frontend with real Android devices

Usage:
    python server.py
    Then open http://localhost:5000 in your browser
"""

import json
import os
import sys
import subprocess
import shutil
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# ── Configuration ──
PORT = 5000
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# ── ADB Helper ──
class ADBBridge:
    """Minimal ADB bridge for the web API."""

    def __init__(self):
        self.adb_path = self._find_adb()

    def _find_adb(self):
        """Locate ADB executable."""
        adb = shutil.which("adb")
        if adb:
            return adb
        # Windows common paths
        common = [
            os.path.expanduser(r"~\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
            r"C:\Android\platform-tools\adb.exe",
            r"C:\Program Files\Android\platform-tools\adb.exe",
        ]
        for p in common:
            if os.path.isfile(p):
                return p
        return None

    def _run(self, *args, timeout=15):
        """Run an ADB command and return stdout."""
        if not self.adb_path:
            raise Exception("ADB not found on system PATH")
        cmd = [self.adb_path] + list(args)
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace"
        )
        if result.returncode != 0 and result.stderr.strip():
            raise Exception(f"ADB error: {result.stderr.strip()}")
        return result.stdout

    def check_available(self):
        """Check if ADB is installed."""
        return self.adb_path is not None

    def get_connected_devices(self):
        """List connected devices."""
        if not self.adb_path:
            return []
        output = self._run("devices")
        devices = []
        for line in output.strip().splitlines()[1:]:
            line = line.strip()
            if line and "\t" in line:
                serial, status = line.split("\t", 1)
                devices.append({"serial": serial, "status": status.strip()})
        return devices

    def get_device_info(self):
        """Get connected device information."""
        props = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "device_name": "ro.product.name",
            "brand": "ro.product.brand",
        }
        info = {}
        for key, prop in props.items():
            try:
                info[key] = self._run("shell", "getprop", prop).strip() or "Unknown"
            except Exception:
                info[key] = "Unknown"
        return info

    def get_installed_packages(self, third_party_only=True):
        """Get list of installed package names."""
        flag = "-3" if third_party_only else ""
        args = ["shell", "pm", "list", "packages"]
        if flag:
            args.append(flag)
        output = self._run(*args, timeout=30)
        packages = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.replace("package:", "").strip())
        return sorted(packages)

    def get_package_details(self, package_name):
        """Get detailed info for a single package."""
        app = {
            "packageName": package_name,
            "appLabel": "",
            "versionName": "",
            "versionCode": "",
            "targetSdk": "",
            "minSdk": "",
            "installerPackage": "",
            "isSystemApp": False,
            "isSideloaded": False,
            "requestedPermissions": [],
            "grantedPermissions": [],
            "certificate": {
                "signer": "Unknown",
                "isSelfSigned": False,
                "isDebugSigned": False,
                "isExpired": False,
            },
        }

        try:
            dumpsys = self._run("shell", "dumpsys", "package", package_name, timeout=15)
        except Exception:
            dumpsys = ""

        if dumpsys:
            # Version info
            for line in dumpsys.splitlines():
                stripped = line.strip()
                if stripped.startswith("versionName="):
                    app["versionName"] = stripped.split("=", 1)[1].strip()
                elif stripped.startswith("versionCode="):
                    parts = stripped.split()
                    for part in parts:
                        if part.startswith("versionCode="):
                            app["versionCode"] = part.split("=", 1)[1]
                        elif part.startswith("minSdk="):
                            app["minSdk"] = part.split("=", 1)[1]
                        elif part.startswith("targetSdk="):
                            app["targetSdk"] = part.split("=", 1)[1]

            # Installer
            for line in dumpsys.splitlines():
                if "installerPackageName=" in line:
                    val = line.split("installerPackageName=")[-1].strip()
                    if val and val != "null":
                        app["installerPackage"] = val
                        break

            # Permissions - requested
            in_requested = False
            for line in dumpsys.splitlines():
                stripped = line.strip()
                if "requested permissions:" in stripped.lower():
                    in_requested = True
                    continue
                if in_requested:
                    if stripped and ("android.permission." in stripped or "com." in stripped):
                        perm = stripped.rstrip(":")
                        if "." in perm and not perm.startswith("//"):
                            app["requestedPermissions"].append(perm)
                    elif stripped and not stripped.startswith(" ") and "permission" not in stripped.lower():
                        in_requested = False

            # Permissions - granted (install + runtime)
            for section_name in ["install permissions:", "runtime permissions:"]:
                in_section = False
                for line in dumpsys.splitlines():
                    stripped = line.strip()
                    if section_name in stripped.lower():
                        in_section = True
                        continue
                    if in_section:
                        if "granted=true" in stripped:
                            perm_name = stripped.split(":")[0].strip()
                            if "." in perm_name and perm_name not in app["grantedPermissions"]:
                                app["grantedPermissions"].append(perm_name)
                        elif stripped and not stripped.startswith(" ") and ":" not in stripped:
                            in_section = False

            # Certificate
            in_signing = False
            for line in dumpsys.splitlines():
                stripped = line.strip()
                if "Signing details:" in stripped or "signing certificates:" in stripped.lower():
                    in_signing = True
                    continue
                if in_signing:
                    if stripped.startswith("Subject:"):
                        cert_subject = stripped.split("Subject:")[-1].strip()
                        app["certificate"]["signer"] = cert_subject
                    elif stripped.startswith("Issuer:"):
                        issuer = stripped.split("Issuer:")[-1].strip()
                        if app["certificate"]["signer"] and app["certificate"]["signer"] == issuer:
                            app["certificate"]["isSelfSigned"] = True
                        if "debug" in issuer.lower():
                            app["certificate"]["isDebugSigned"] = True

            # SDK targets fallback
            if not app["targetSdk"]:
                match = re.search(r"targetSdk=(\d+)", dumpsys)
                if match:
                    app["targetSdk"] = match.group(1)
            if not app["minSdk"]:
                match = re.search(r"minSdk=(\d+)", dumpsys)
                if match:
                    app["minSdk"] = match.group(1)

        # App label
        app["appLabel"] = self._get_app_label(package_name)

        # Sideloaded check
        official_stores = {
            "com.android.vending", "com.google.android.packageinstaller",
            "com.sec.android.app.samsungapps", "com.amazon.venezia",
            "com.huawei.appmarket", "com.xiaomi.market",
        }
        app["isSideloaded"] = (
            app["installerPackage"] not in official_stores
            and not app["isSystemApp"]
        )

        # Deduplicate permissions
        app["requestedPermissions"] = list(dict.fromkeys(app["requestedPermissions"]))
        app["grantedPermissions"] = list(dict.fromkeys(app["grantedPermissions"]))

        return app

    def _get_app_label(self, package_name):
        """Try to get human-readable app name."""
        try:
            output = self._run("shell", "pm", "dump", package_name, timeout=10)
            for line in output.splitlines():
                if "Application Label:" in line:
                    label = line.split("Application Label:")[-1].strip()
                    if label:
                        return label
        except Exception:
            pass
        parts = package_name.split(".")
        return parts[-1].capitalize() if len(parts) > 1 else package_name

    def scan_all_apps(self, third_party_only=True):
        """Scan all installed apps and return detailed info."""
        packages = self.get_installed_packages(third_party_only)
        results = []
        for pkg in packages:
            try:
                details = self.get_package_details(pkg)
                results.append(details)
            except Exception as e:
                print(f"  ⚠ Failed to scan {pkg}: {e}")
        return results


# ── Global ADB instance ──
adb = ADBBridge()


# ── HTTP Request Handler ──
class AppGuardHandler(SimpleHTTPRequestHandler):
    """Serves static files + REST API for device scanning."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ── API Routes ──
        if path.startswith("/api/"):
            self._handle_api(path, parsed)
            return

        # ── Static Files ──
        super().do_GET()

    def _handle_api(self, path, parsed):
        """Route API requests."""
        try:
            if path == "/api/status":
                self._json_response({
                    "adbAvailable": adb.check_available(),
                    "adbPath": adb.adb_path or "",
                })

            elif path == "/api/devices":
                if not adb.check_available():
                    self._json_response({"error": "ADB not found"}, 503)
                    return
                devices = adb.get_connected_devices()
                self._json_response({"devices": devices})

            elif path == "/api/device-info":
                info = adb.get_device_info()
                self._json_response(info)

            elif path == "/api/packages":
                params = parse_qs(parsed.query)
                third_party = params.get("thirdParty", ["true"])[0].lower() == "true"
                packages = adb.get_installed_packages(third_party)
                self._json_response({
                    "packages": packages,
                    "count": len(packages),
                })

            elif path == "/api/scan":
                params = parse_qs(parsed.query)
                pkg = params.get("package", [None])[0]

                if pkg:
                    # Single package scan
                    details = adb.get_package_details(pkg)
                    self._json_response({"apps": [details]})
                else:
                    # Full scan
                    third_party = params.get("thirdParty", ["true"])[0].lower() == "true"
                    apps = adb.scan_all_apps(third_party)
                    self._json_response({
                        "apps": apps,
                        "count": len(apps),
                        "deviceInfo": adb.get_device_info(),
                    })

            elif path == "/api/scan-package":
                params = parse_qs(parsed.query)
                pkg = params.get("package", [None])[0]
                if not pkg:
                    self._json_response({"error": "Missing ?package= parameter"}, 400)
                    return
                details = adb.get_package_details(pkg)
                self._json_response(details)

            else:
                self._json_response({"error": "Unknown API endpoint"}, 404)

        except Exception as e:
            self._json_response({"error": str(e)}, 500)

    def _json_response(self, data, status=200):
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, format, *args):
        """Custom log format."""
        msg = format % args
        if "/api/" in msg:
            print(f"  🔌 API: {msg}")
        elif not any(ext in msg for ext in [".css", ".js", ".ico", ".png", ".woff"]):
            print(f"  📄 {msg}")


# ── Main ──
def main():
    print("╔══════════════════════════════════════════════════╗")
    print("║  🛡️  AppGuard Server                             ║")
    print("║  AI-Powered App Security Analyzer                ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    # Check ADB
    if adb.check_available():
        print(f"  ✅ ADB found: {adb.adb_path}")
        devices = adb.get_connected_devices()
        if devices:
            for d in devices:
                status_icon = "📱" if d["status"] == "device" else "⚠️"
                print(f"  {status_icon} Device: {d['serial']} ({d['status']})")
        else:
            print("  📵 No devices connected (connect via USB + enable USB Debugging)")
    else:
        print("  ⚠️  ADB not found — device scanning disabled")
        print("     Install Android SDK Platform Tools to enable device scanning")
        print("     Download: https://developer.android.com/tools/releases/platform-tools")

    print()
    print(f"  🌐 Dashboard: http://localhost:{PORT}")
    print(f"  📡 API:       http://localhost:{PORT}/api/status")
    print()
    print("  Press Ctrl+C to stop")
    print("─" * 54)

    server = HTTPServer(("0.0.0.0", PORT), AppGuardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  🛑 Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
