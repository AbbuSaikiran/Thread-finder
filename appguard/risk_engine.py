"""
Risk Engine for AppGuard.

Provides rule-based security risk scoring before LLM analysis.
Maintains a database of dangerous Android permissions with categories
and risk weights.
"""

from __future__ import annotations

from .data_models import (
    AppInfo,
    AppSecurityReport,
    FlaggedIssue,
    PermissionInfo,
    PermissionCategory,
    RiskLevel,
)


# ──────────────────────────────────────────────────────────────────────
# Dangerous Permission Database
# Each entry: (permission_name, category, risk_weight, description)
# ──────────────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS: list[tuple[str, PermissionCategory, int, str]] = [
    # Location
    ("android.permission.ACCESS_FINE_LOCATION", PermissionCategory.LOCATION, 15,
     "Precise GPS location access"),
    ("android.permission.ACCESS_COARSE_LOCATION", PermissionCategory.LOCATION, 10,
     "Approximate location access"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", PermissionCategory.LOCATION, 20,
     "Background location tracking — can track user even when app is closed"),

    # Camera & Microphone
    ("android.permission.CAMERA", PermissionCategory.CAMERA_MIC, 15,
     "Can access device camera to take photos/videos"),
    ("android.permission.RECORD_AUDIO", PermissionCategory.CAMERA_MIC, 20,
     "Can record audio via microphone"),

    # Contacts & SMS
    ("android.permission.READ_CONTACTS", PermissionCategory.CONTACTS_SMS, 15,
     "Can read entire contact list"),
    ("android.permission.WRITE_CONTACTS", PermissionCategory.CONTACTS_SMS, 15,
     "Can modify contacts"),
    ("android.permission.READ_SMS", PermissionCategory.CONTACTS_SMS, 20,
     "Can read all SMS messages — potential for credential theft"),
    ("android.permission.SEND_SMS", PermissionCategory.CONTACTS_SMS, 25,
     "Can send SMS — potential for premium rate fraud"),
    ("android.permission.RECEIVE_SMS", PermissionCategory.CONTACTS_SMS, 15,
     "Can intercept incoming SMS messages"),

    # Storage
    ("android.permission.READ_EXTERNAL_STORAGE", PermissionCategory.STORAGE, 8,
     "Can read files from shared storage"),
    ("android.permission.WRITE_EXTERNAL_STORAGE", PermissionCategory.STORAGE, 10,
     "Can write/modify files on shared storage"),
    ("android.permission.MANAGE_EXTERNAL_STORAGE", PermissionCategory.STORAGE, 20,
     "Full access to all files on device — very broad storage permission"),

    # Phone
    ("android.permission.READ_PHONE_STATE", PermissionCategory.PHONE, 10,
     "Can read phone number, IMEI, carrier info"),
    ("android.permission.CALL_PHONE", PermissionCategory.PHONE, 15,
     "Can make phone calls without user interaction"),
    ("android.permission.READ_CALL_LOG", PermissionCategory.PHONE, 15,
     "Can read call history"),
    ("android.permission.WRITE_CALL_LOG", PermissionCategory.PHONE, 15,
     "Can modify or delete call history"),
    ("android.permission.ANSWER_PHONE_CALLS", PermissionCategory.PHONE, 10,
     "Can answer incoming calls programmatically"),
    ("android.permission.PROCESS_OUTGOING_CALLS", PermissionCategory.PHONE, 15,
     "Can monitor and redirect outgoing calls"),

    # System / Admin
    ("android.permission.SYSTEM_ALERT_WINDOW", PermissionCategory.SYSTEM, 20,
     "Can draw overlays on top of other apps — phishing risk"),
    ("android.permission.REQUEST_INSTALL_PACKAGES", PermissionCategory.SYSTEM, 25,
     "Can request to install APK files — malware distribution risk"),
    ("android.permission.BIND_DEVICE_ADMIN", PermissionCategory.SYSTEM, 25,
     "Device administrator access — can lock device, wipe data"),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", PermissionCategory.SYSTEM, 25,
     "Accessibility service — can read screen content and perform actions"),
    ("android.permission.CHANGE_WIFI_STATE", PermissionCategory.SYSTEM, 5,
     "Can change Wi-Fi connection state"),
    ("android.permission.RECEIVE_BOOT_COMPLETED", PermissionCategory.SYSTEM, 5,
     "Starts automatically when device boots"),
    ("android.permission.WAKE_LOCK", PermissionCategory.SYSTEM, 3,
     "Can prevent device from sleeping — battery drain"),
    ("android.permission.REQUEST_DELETE_PACKAGES", PermissionCategory.SYSTEM, 10,
     "Can request to uninstall other apps"),
    ("android.permission.QUERY_ALL_PACKAGES", PermissionCategory.SYSTEM, 10,
     "Can see all installed apps — fingerprinting risk"),

    # Network
    ("android.permission.INTERNET", PermissionCategory.NETWORK, 2,
     "Can access the internet — nearly universal but enables data exfiltration"),
    ("android.permission.ACCESS_NETWORK_STATE", PermissionCategory.NETWORK, 1,
     "Can check network connectivity status"),
    ("android.permission.CHANGE_NETWORK_STATE", PermissionCategory.NETWORK, 5,
     "Can change network connectivity state"),

    # Calendar
    ("android.permission.READ_CALENDAR", PermissionCategory.CALENDAR, 10,
     "Can read calendar events and details"),
    ("android.permission.WRITE_CALENDAR", PermissionCategory.CALENDAR, 10,
     "Can modify or create calendar events"),

    # Body Sensors
    ("android.permission.BODY_SENSORS", PermissionCategory.BODY_SENSORS, 10,
     "Can access heart rate, step counter, and other body sensors"),
    ("android.permission.BODY_SENSORS_BACKGROUND", PermissionCategory.BODY_SENSORS, 15,
     "Background body sensor access"),
]

# Build a lookup dict for fast permission matching
_PERMISSION_DB: dict[str, tuple[PermissionCategory, int, str]] = {
    perm: (cat, weight, desc)
    for perm, cat, weight, desc in DANGEROUS_PERMISSIONS
}


class RiskEngine:
    """
    Rule-based security risk scoring engine.

    Analyzes app permissions, certificates, and install source to
    calculate a base risk score (0-100) before LLM analysis.
    """

    # Risk multipliers
    SIDELOAD_PENALTY = 15
    SELF_SIGNED_PENALTY = 10
    DEBUG_SIGNED_PENALTY = 20
    EXPIRED_CERT_PENALTY = 15
    LOW_TARGET_SDK_PENALTY = 10  # targeting old SDK = less security
    EXCESSIVE_PERMISSIONS_THRESHOLD = 10  # more than N dangerous perms = extra risk
    EXCESSIVE_PERMISSIONS_PENALTY = 10

    def analyze(self, app: AppInfo) -> AppSecurityReport:
        """
        Perform rule-based risk analysis on an app.

        Args:
            app: Populated AppInfo with permissions and certificate data.

        Returns:
            AppSecurityReport with base risk score and flagged issues.
        """
        report = AppSecurityReport(app_info=app)
        total_risk = 0

        # ── 1. Permission Analysis ──
        dangerous_found = self._analyze_permissions(app, report)
        total_risk += sum(p.risk_weight for p in dangerous_found)

        # Cap permission risk contribution at 60
        perm_risk = min(sum(p.risk_weight for p in dangerous_found), 60)
        total_risk = perm_risk

        # Excessive permissions bonus
        if len(dangerous_found) > self.EXCESSIVE_PERMISSIONS_THRESHOLD:
            total_risk += self.EXCESSIVE_PERMISSIONS_PENALTY
            report.flagged_issues.append(FlaggedIssue(
                category="Permissions",
                severity="high",
                description=(
                    f"Excessive dangerous permissions: {len(dangerous_found)} "
                    f"(threshold: {self.EXCESSIVE_PERMISSIONS_THRESHOLD})"
                ),
                risk_points=self.EXCESSIVE_PERMISSIONS_PENALTY,
            ))

        # ── 2. Install Source Analysis ──
        if app.is_sideloaded:
            total_risk += self.SIDELOAD_PENALTY
            report.flagged_issues.append(FlaggedIssue(
                category="Install Source",
                severity="medium",
                description=(
                    f"App was sideloaded (installer: "
                    f"{app.install_source_label}). "
                    "Not verified by an official app store."
                ),
                risk_points=self.SIDELOAD_PENALTY,
            ))

        # ── 3. Certificate Analysis ──
        cert = app.certificate
        if cert.is_debug_signed:
            total_risk += self.DEBUG_SIGNED_PENALTY
            report.flagged_issues.append(FlaggedIssue(
                category="Certificate",
                severity="critical",
                description=(
                    "App is signed with a DEBUG certificate. This should never "
                    "appear in production — possible development/test build leak."
                ),
                risk_points=self.DEBUG_SIGNED_PENALTY,
            ))
        elif cert.is_self_signed:
            total_risk += self.SELF_SIGNED_PENALTY
            report.flagged_issues.append(FlaggedIssue(
                category="Certificate",
                severity="medium",
                description=(
                    "App uses a self-signed certificate. Most legitimate apps "
                    "are self-signed, but combined with other flags this is notable."
                ),
                risk_points=self.SELF_SIGNED_PENALTY,
            ))

        if cert.is_expired:
            total_risk += self.EXPIRED_CERT_PENALTY
            report.flagged_issues.append(FlaggedIssue(
                category="Certificate",
                severity="high",
                description="App's signing certificate has expired.",
                risk_points=self.EXPIRED_CERT_PENALTY,
            ))

        # ── 4. SDK Target Analysis ──
        if app.target_sdk:
            try:
                sdk = int(app.target_sdk)
                if sdk < 28:  # Android 9
                    total_risk += self.LOW_TARGET_SDK_PENALTY
                    report.flagged_issues.append(FlaggedIssue(
                        category="SDK Target",
                        severity="medium",
                        description=(
                            f"App targets SDK {sdk} (Android "
                            f"{self._sdk_to_android(sdk)}). Old SDK targets "
                            "bypass modern security protections."
                        ),
                        risk_points=self.LOW_TARGET_SDK_PENALTY,
                    ))
            except ValueError:
                pass

        # ── 5. Suspicious Permission Combinations ──
        combo_risk = self._check_suspicious_combos(app, report)
        total_risk += combo_risk

        # ── Finalize Score ──
        report.base_risk_score = min(max(total_risk, 0), 100)
        report.final_risk_score = report.base_risk_score  # LLM may adjust later
        report.risk_level = RiskLevel.from_score(report.base_risk_score)

        return report

    def _analyze_permissions(
        self, app: AppInfo, report: AppSecurityReport
    ) -> list[PermissionInfo]:
        """
        Check requested permissions against dangerous permission database.

        Returns list of dangerous PermissionInfo objects found.
        """
        dangerous_found: list[PermissionInfo] = []

        for perm in app.requested_permissions:
            if perm in _PERMISSION_DB:
                cat, weight, desc = _PERMISSION_DB[perm]
                perm_info = PermissionInfo(
                    name=perm,
                    granted=perm in app.granted_permissions,
                    category=cat,
                    risk_weight=weight,
                    description=desc,
                )
                dangerous_found.append(perm_info)

                # Only flag high-risk permissions individually
                if weight >= 15:
                    report.flagged_issues.append(FlaggedIssue(
                        category=f"Permission: {cat.value}",
                        severity="high" if weight >= 20 else "medium",
                        description=f"{perm.split('.')[-1]}: {desc}",
                        risk_points=weight,
                    ))

        app.dangerous_permissions = dangerous_found
        return dangerous_found

    def _check_suspicious_combos(
        self, app: AppInfo, report: AppSecurityReport
    ) -> int:
        """
        Check for suspicious permission combinations that are greater
        than the sum of their individual risks.
        """
        perms = set(app.requested_permissions)
        extra_risk = 0

        # SMS + Internet = potential credential exfiltration
        if ("android.permission.READ_SMS" in perms
                and "android.permission.INTERNET" in perms):
            extra_risk += 10
            report.flagged_issues.append(FlaggedIssue(
                category="Suspicious Combination",
                severity="critical",
                description=(
                    "READ_SMS + INTERNET: App can read SMS and send data "
                    "over the internet — potential 2FA/OTP theft vector."
                ),
                risk_points=10,
            ))

        # Camera + Mic + Internet = surveillance potential
        if ("android.permission.CAMERA" in perms
                and "android.permission.RECORD_AUDIO" in perms
                and "android.permission.INTERNET" in perms):
            extra_risk += 8
            report.flagged_issues.append(FlaggedIssue(
                category="Suspicious Combination",
                severity="high",
                description=(
                    "CAMERA + RECORD_AUDIO + INTERNET: App can capture "
                    "audio/video and transmit over the network."
                ),
                risk_points=8,
            ))

        # Contacts + SMS + Internet = spam/phishing vector
        if ("android.permission.READ_CONTACTS" in perms
                and "android.permission.SEND_SMS" in perms):
            extra_risk += 10
            report.flagged_issues.append(FlaggedIssue(
                category="Suspicious Combination",
                severity="critical",
                description=(
                    "READ_CONTACTS + SEND_SMS: App can read contacts and "
                    "send SMS — potential spam/phishing distribution."
                ),
                risk_points=10,
            ))

        # Overlay + Install packages = classic malware pattern
        if ("android.permission.SYSTEM_ALERT_WINDOW" in perms
                and "android.permission.REQUEST_INSTALL_PACKAGES" in perms):
            extra_risk += 15
            report.flagged_issues.append(FlaggedIssue(
                category="Suspicious Combination",
                severity="critical",
                description=(
                    "SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES: "
                    "Classic malware pattern — overlay phishing + dropper."
                ),
                risk_points=15,
            ))

        # Background location + Internet = persistent tracking
        if ("android.permission.ACCESS_BACKGROUND_LOCATION" in perms
                and "android.permission.INTERNET" in perms):
            extra_risk += 8
            report.flagged_issues.append(FlaggedIssue(
                category="Suspicious Combination",
                severity="high",
                description=(
                    "ACCESS_BACKGROUND_LOCATION + INTERNET: App can "
                    "continuously track location and transmit it."
                ),
                risk_points=8,
            ))

        return extra_risk

    @staticmethod
    def _sdk_to_android(sdk: int) -> str:
        """Convert SDK version number to Android version name."""
        sdk_map = {
            21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1",
            26: "8.0", 27: "8.1", 28: "9.0", 29: "10", 30: "11",
            31: "12", 32: "12L", 33: "13", 34: "14", 35: "15",
        }
        return sdk_map.get(sdk, f"SDK {sdk}")
