"""
Data models for AppGuard.

Defines structured dataclasses for app information, permissions,
certificates, and security reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """Risk classification levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def emoji(self) -> str:
        return {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🟠",
            RiskLevel.CRITICAL: "🔴",
        }[self]

    @property
    def color(self) -> str:
        """Rich color name for terminal output."""
        return {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "dark_orange",
            RiskLevel.CRITICAL: "red",
        }[self]

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        """Determine risk level from a 0-100 score."""
        if score >= 75:
            return cls.CRITICAL
        elif score >= 50:
            return cls.HIGH
        elif score >= 25:
            return cls.MEDIUM
        else:
            return cls.LOW


class PermissionCategory(Enum):
    """Categories of dangerous Android permissions."""
    LOCATION = "Location"
    CAMERA_MIC = "Camera & Microphone"
    CONTACTS_SMS = "Contacts & SMS"
    STORAGE = "Storage"
    PHONE = "Phone"
    SYSTEM = "System"
    NETWORK = "Network"
    CALENDAR = "Calendar"
    BODY_SENSORS = "Body Sensors"
    OTHER = "Other"


@dataclass
class PermissionInfo:
    """Detailed information about a single permission."""
    name: str
    granted: bool = False
    category: PermissionCategory = PermissionCategory.OTHER
    risk_weight: int = 0
    description: str = ""


@dataclass
class AppCertificate:
    """Certificate / signing information for an app."""
    signer: str = "Unknown"
    fingerprint_sha256: str = ""
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    issuer: str = "Unknown"
    is_self_signed: bool = False
    is_expired: bool = False
    is_debug_signed: bool = False


@dataclass
class AppInfo:
    """Complete information about an installed Android app."""
    package_name: str
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    install_time: Optional[str] = None
    update_time: Optional[str] = None
    installer_package: str = ""
    is_system_app: bool = False
    is_sideloaded: bool = False
    target_sdk: str = ""
    min_sdk: str = ""
    uid: str = ""

    # Permissions
    requested_permissions: list[str] = field(default_factory=list)
    granted_permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[PermissionInfo] = field(default_factory=list)

    # Certificate
    certificate: AppCertificate = field(default_factory=AppCertificate)

    @property
    def display_name(self) -> str:
        """Return app label if available, otherwise package name."""
        return self.app_label if self.app_label else self.package_name

    @property
    def install_source_label(self) -> str:
        """Human-readable install source."""
        known_stores = {
            "com.android.vending": "Google Play Store",
            "com.google.android.packageinstaller": "Package Installer",
            "com.samsung.android.scloud": "Samsung Cloud",
            "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
            "com.amazon.venezia": "Amazon Appstore",
            "com.huawei.appmarket": "Huawei AppGallery",
        }
        if self.installer_package in known_stores:
            return known_stores[self.installer_package]
        elif self.installer_package:
            return f"Unknown ({self.installer_package})"
        else:
            return "Sideloaded / Unknown"

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for serialization."""
        data = {
            "package_name": self.package_name,
            "app_label": self.app_label,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "install_time": self.install_time,
            "update_time": self.update_time,
            "installer_package": self.installer_package,
            "install_source": self.install_source_label,
            "is_system_app": self.is_system_app,
            "is_sideloaded": self.is_sideloaded,
            "target_sdk": self.target_sdk,
            "min_sdk": self.min_sdk,
            "requested_permissions": self.requested_permissions,
            "granted_permissions": self.granted_permissions,
            "dangerous_permissions_count": len(self.dangerous_permissions),
            "certificate": {
                "signer": self.certificate.signer,
                "fingerprint_sha256": self.certificate.fingerprint_sha256,
                "is_self_signed": self.certificate.is_self_signed,
                "is_expired": self.certificate.is_expired,
                "is_debug_signed": self.certificate.is_debug_signed,
            },
        }
        return data


@dataclass
class FlaggedIssue:
    """A specific security concern flagged by the risk engine."""
    category: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    risk_points: int


@dataclass
class AppSecurityReport:
    """Complete security analysis report for a single app."""
    app_info: AppInfo
    base_risk_score: int = 0
    final_risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    flagged_issues: list[FlaggedIssue] = field(default_factory=list)
    llm_analysis: str = ""
    llm_concerns: list[str] = field(default_factory=list)
    llm_recommendation: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON/HTML export."""
        return {
            "app": self.app_info.to_dict(),
            "base_risk_score": self.base_risk_score,
            "final_risk_score": self.final_risk_score,
            "risk_level": self.risk_level.value,
            "flagged_issues": [
                {
                    "category": issue.category,
                    "severity": issue.severity,
                    "description": issue.description,
                    "risk_points": issue.risk_points,
                }
                for issue in self.flagged_issues
            ],
            "llm_analysis": self.llm_analysis,
            "llm_concerns": self.llm_concerns,
            "llm_recommendation": self.llm_recommendation,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class ScanSummary:
    """Summary of a full device scan."""
    device_model: str = "Unknown"
    android_version: str = "Unknown"
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    total_apps_scanned: int = 0
    risk_distribution: dict[str, int] = field(default_factory=lambda: {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    })
    reports: list[AppSecurityReport] = field(default_factory=list)

    def update_distribution(self):
        """Recalculate risk distribution from reports."""
        self.risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for report in self.reports:
            self.risk_distribution[report.risk_level.value] += 1
        self.total_apps_scanned = len(self.reports)
