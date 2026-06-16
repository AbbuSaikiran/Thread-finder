/**
 * AppGuard Risk Engine — Browser Edition
 * 
 * Port of the Python risk_engine.py to JavaScript.
 * Performs rule-based security risk scoring for Android apps.
 */

const RiskLevel = {
    LOW: { name: 'LOW', emoji: '🟢', color: '#4ade80', bgColor: 'rgba(74,222,128,0.1)', borderColor: 'rgba(74,222,128,0.2)' },
    MEDIUM: { name: 'MEDIUM', emoji: '🟡', color: '#fbbf24', bgColor: 'rgba(251,191,36,0.1)', borderColor: 'rgba(251,191,36,0.2)' },
    HIGH: { name: 'HIGH', emoji: '🟠', color: '#fb923c', bgColor: 'rgba(251,146,60,0.1)', borderColor: 'rgba(251,146,60,0.2)' },
    CRITICAL: { name: 'CRITICAL', emoji: '🔴', color: '#f87171', bgColor: 'rgba(248,113,113,0.1)', borderColor: 'rgba(248,113,113,0.2)' },
};

function getRiskLevel(score) {
    if (score >= 75) return RiskLevel.CRITICAL;
    if (score >= 50) return RiskLevel.HIGH;
    if (score >= 25) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
}

// ── Dangerous Permissions Database ──
const DANGEROUS_PERMISSIONS = [
    // Location
    { name: 'ACCESS_FINE_LOCATION', full: 'android.permission.ACCESS_FINE_LOCATION', category: 'Location', categoryIcon: '📍', weight: 15, desc: 'Precise GPS location access' },
    { name: 'ACCESS_COARSE_LOCATION', full: 'android.permission.ACCESS_COARSE_LOCATION', category: 'Location', categoryIcon: '📍', weight: 10, desc: 'Approximate location access' },
    { name: 'ACCESS_BACKGROUND_LOCATION', full: 'android.permission.ACCESS_BACKGROUND_LOCATION', category: 'Location', categoryIcon: '📍', weight: 20, desc: 'Background location tracking' },

    // Camera & Mic
    { name: 'CAMERA', full: 'android.permission.CAMERA', category: 'Camera & Mic', categoryIcon: '📷', weight: 15, desc: 'Access device camera' },
    { name: 'RECORD_AUDIO', full: 'android.permission.RECORD_AUDIO', category: 'Camera & Mic', categoryIcon: '📷', weight: 20, desc: 'Record audio via microphone' },

    // Contacts & SMS
    { name: 'READ_CONTACTS', full: 'android.permission.READ_CONTACTS', category: 'Contacts & SMS', categoryIcon: '📱', weight: 15, desc: 'Read entire contact list' },
    { name: 'WRITE_CONTACTS', full: 'android.permission.WRITE_CONTACTS', category: 'Contacts & SMS', categoryIcon: '📱', weight: 15, desc: 'Modify contacts' },
    { name: 'READ_SMS', full: 'android.permission.READ_SMS', category: 'Contacts & SMS', categoryIcon: '📱', weight: 20, desc: 'Read all SMS messages' },
    { name: 'SEND_SMS', full: 'android.permission.SEND_SMS', category: 'Contacts & SMS', categoryIcon: '📱', weight: 25, desc: 'Send SMS (premium rate fraud risk)' },
    { name: 'RECEIVE_SMS', full: 'android.permission.RECEIVE_SMS', category: 'Contacts & SMS', categoryIcon: '📱', weight: 15, desc: 'Intercept incoming SMS' },

    // Storage
    { name: 'READ_EXTERNAL_STORAGE', full: 'android.permission.READ_EXTERNAL_STORAGE', category: 'Storage', categoryIcon: '📂', weight: 8, desc: 'Read files from shared storage' },
    { name: 'WRITE_EXTERNAL_STORAGE', full: 'android.permission.WRITE_EXTERNAL_STORAGE', category: 'Storage', categoryIcon: '📂', weight: 10, desc: 'Write/modify files on storage' },
    { name: 'MANAGE_EXTERNAL_STORAGE', full: 'android.permission.MANAGE_EXTERNAL_STORAGE', category: 'Storage', categoryIcon: '📂', weight: 20, desc: 'Full file system access' },

    // Phone
    { name: 'READ_PHONE_STATE', full: 'android.permission.READ_PHONE_STATE', category: 'Phone', categoryIcon: '📞', weight: 10, desc: 'Read phone number, IMEI, carrier' },
    { name: 'CALL_PHONE', full: 'android.permission.CALL_PHONE', category: 'Phone', categoryIcon: '📞', weight: 15, desc: 'Make calls without interaction' },
    { name: 'READ_CALL_LOG', full: 'android.permission.READ_CALL_LOG', category: 'Phone', categoryIcon: '📞', weight: 15, desc: 'Read call history' },
    { name: 'WRITE_CALL_LOG', full: 'android.permission.WRITE_CALL_LOG', category: 'Phone', categoryIcon: '📞', weight: 15, desc: 'Modify/delete call history' },
    { name: 'ANSWER_PHONE_CALLS', full: 'android.permission.ANSWER_PHONE_CALLS', category: 'Phone', categoryIcon: '📞', weight: 10, desc: 'Answer calls programmatically' },
    { name: 'PROCESS_OUTGOING_CALLS', full: 'android.permission.PROCESS_OUTGOING_CALLS', category: 'Phone', categoryIcon: '📞', weight: 15, desc: 'Monitor/redirect outgoing calls' },

    // System
    { name: 'SYSTEM_ALERT_WINDOW', full: 'android.permission.SYSTEM_ALERT_WINDOW', category: 'System', categoryIcon: '⚙️', weight: 20, desc: 'Draw overlays (phishing risk)' },
    { name: 'REQUEST_INSTALL_PACKAGES', full: 'android.permission.REQUEST_INSTALL_PACKAGES', category: 'System', categoryIcon: '⚙️', weight: 25, desc: 'Install APK files (malware risk)' },
    { name: 'BIND_DEVICE_ADMIN', full: 'android.permission.BIND_DEVICE_ADMIN', category: 'System', categoryIcon: '⚙️', weight: 25, desc: 'Device admin (lock/wipe device)' },
    { name: 'BIND_ACCESSIBILITY_SERVICE', full: 'android.permission.BIND_ACCESSIBILITY_SERVICE', category: 'System', categoryIcon: '⚙️', weight: 25, desc: 'Read screen content & act' },
    { name: 'RECEIVE_BOOT_COMPLETED', full: 'android.permission.RECEIVE_BOOT_COMPLETED', category: 'System', categoryIcon: '⚙️', weight: 5, desc: 'Auto-start on boot' },
    { name: 'WAKE_LOCK', full: 'android.permission.WAKE_LOCK', category: 'System', categoryIcon: '⚙️', weight: 3, desc: 'Prevent device sleep' },
    { name: 'QUERY_ALL_PACKAGES', full: 'android.permission.QUERY_ALL_PACKAGES', category: 'System', categoryIcon: '⚙️', weight: 10, desc: 'See all installed apps' },

    // Network
    { name: 'INTERNET', full: 'android.permission.INTERNET', category: 'Network', categoryIcon: '🌐', weight: 2, desc: 'Internet access' },
    { name: 'ACCESS_NETWORK_STATE', full: 'android.permission.ACCESS_NETWORK_STATE', category: 'Network', categoryIcon: '🌐', weight: 1, desc: 'Check network connectivity' },
    { name: 'CHANGE_NETWORK_STATE', full: 'android.permission.CHANGE_NETWORK_STATE', category: 'Network', categoryIcon: '🌐', weight: 5, desc: 'Change network state' },

    // Calendar
    { name: 'READ_CALENDAR', full: 'android.permission.READ_CALENDAR', category: 'Calendar', categoryIcon: '📅', weight: 10, desc: 'Read calendar events' },
    { name: 'WRITE_CALENDAR', full: 'android.permission.WRITE_CALENDAR', category: 'Calendar', categoryIcon: '📅', weight: 10, desc: 'Modify calendar events' },

    // Body Sensors
    { name: 'BODY_SENSORS', full: 'android.permission.BODY_SENSORS', category: 'Body Sensors', categoryIcon: '🫀', weight: 10, desc: 'Access heart rate, step counter' },
    { name: 'BODY_SENSORS_BACKGROUND', full: 'android.permission.BODY_SENSORS_BACKGROUND', category: 'Body Sensors', categoryIcon: '🫀', weight: 15, desc: 'Background body sensor access' },
];

// Permission lookup map
const PERM_LOOKUP = {};
DANGEROUS_PERMISSIONS.forEach(p => {
    PERM_LOOKUP[p.full] = p;
    PERM_LOOKUP[p.name] = p;
});

// Group permissions by category
function getPermissionsByCategory() {
    const categories = {};
    DANGEROUS_PERMISSIONS.forEach(p => {
        if (!categories[p.category]) {
            categories[p.category] = { icon: p.categoryIcon, perms: [] };
        }
        categories[p.category].perms.push(p);
    });
    return categories;
}

// Known app stores
const OFFICIAL_STORES = new Set([
    'com.android.vending',
    'com.google.android.packageinstaller',
    'com.sec.android.app.samsungapps',
    'com.amazon.venezia',
    'com.huawei.appmarket',
]);

function getInstallSourceLabel(installer) {
    const map = {
        'com.android.vending': 'Google Play Store',
        'com.google.android.packageinstaller': 'Package Installer',
        'com.sec.android.app.samsungapps': 'Samsung Galaxy Store',
        'com.amazon.venezia': 'Amazon Appstore',
        'com.huawei.appmarket': 'Huawei AppGallery',
    };
    if (map[installer]) return map[installer];
    if (installer) return `Unknown (${installer})`;
    return 'Sideloaded / Unknown';
}

// ── Risk Analysis Engine ──

function analyzeApp(appData) {
    const report = {
        app: appData,
        baseRiskScore: 0,
        finalRiskScore: 0,
        riskLevel: RiskLevel.LOW,
        flaggedIssues: [],
        dangerousPermissions: [],
    };

    let totalRisk = 0;

    // 1. Permission Analysis
    const perms = new Set(appData.requestedPermissions || []);
    let permRisk = 0;

    perms.forEach(perm => {
        const info = PERM_LOOKUP[perm];
        if (info) {
            report.dangerousPermissions.push(info);
            permRisk += info.weight;

            if (info.weight >= 15) {
                report.flaggedIssues.push({
                    category: `Permission: ${info.category}`,
                    severity: info.weight >= 20 ? 'critical' : 'high',
                    description: `${info.name}: ${info.desc}`,
                    riskPoints: info.weight,
                });
            }
        }
    });

    totalRisk = Math.min(permRisk, 60);

    // Excessive permissions
    if (report.dangerousPermissions.length > 10) {
        totalRisk += 10;
        report.flaggedIssues.push({
            category: 'Permissions',
            severity: 'high',
            description: `Excessive dangerous permissions: ${report.dangerousPermissions.length} (threshold: 10)`,
            riskPoints: 10,
        });
    }

    // 2. Install Source
    const isSideloaded = !OFFICIAL_STORES.has(appData.installerPackage || '');
    if (isSideloaded && !appData.isSystemApp) {
        totalRisk += 15;
        report.flaggedIssues.push({
            category: 'Install Source',
            severity: 'medium',
            description: `App was sideloaded (${getInstallSourceLabel(appData.installerPackage)}). Not verified by an official app store.`,
            riskPoints: 15,
        });
    }

    // 3. Certificate
    const cert = appData.certificate || {};
    if (cert.isDebugSigned) {
        totalRisk += 20;
        report.flaggedIssues.push({
            category: 'Certificate',
            severity: 'critical',
            description: 'App signed with DEBUG certificate — should never appear in production.',
            riskPoints: 20,
        });
    } else if (cert.isSelfSigned) {
        totalRisk += 10;
        report.flaggedIssues.push({
            category: 'Certificate',
            severity: 'medium',
            description: 'App uses a self-signed certificate.',
            riskPoints: 10,
        });
    }

    if (cert.isExpired) {
        totalRisk += 15;
        report.flaggedIssues.push({
            category: 'Certificate',
            severity: 'high',
            description: "App's signing certificate has expired.",
            riskPoints: 15,
        });
    }

    // 4. SDK Target
    const sdk = parseInt(appData.targetSdk);
    if (!isNaN(sdk) && sdk < 28) {
        totalRisk += 10;
        report.flaggedIssues.push({
            category: 'SDK Target',
            severity: 'medium',
            description: `App targets SDK ${sdk} — old targets bypass modern security protections.`,
            riskPoints: 10,
        });
    }

    // 5. Suspicious Combinations
    if (perms.has('android.permission.READ_SMS') && perms.has('android.permission.INTERNET')) {
        totalRisk += 10;
        report.flaggedIssues.push({
            category: 'Suspicious Combo',
            severity: 'critical',
            description: 'READ_SMS + INTERNET: Potential 2FA/OTP theft vector.',
            riskPoints: 10,
        });
    }

    if (perms.has('android.permission.CAMERA') && perms.has('android.permission.RECORD_AUDIO') && perms.has('android.permission.INTERNET')) {
        totalRisk += 8;
        report.flaggedIssues.push({
            category: 'Suspicious Combo',
            severity: 'high',
            description: 'CAMERA + MIC + INTERNET: Surveillance potential.',
            riskPoints: 8,
        });
    }

    if (perms.has('android.permission.READ_CONTACTS') && perms.has('android.permission.SEND_SMS')) {
        totalRisk += 10;
        report.flaggedIssues.push({
            category: 'Suspicious Combo',
            severity: 'critical',
            description: 'READ_CONTACTS + SEND_SMS: Spam/phishing distribution risk.',
            riskPoints: 10,
        });
    }

    if (perms.has('android.permission.SYSTEM_ALERT_WINDOW') && perms.has('android.permission.REQUEST_INSTALL_PACKAGES')) {
        totalRisk += 15;
        report.flaggedIssues.push({
            category: 'Suspicious Combo',
            severity: 'critical',
            description: 'SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES: Classic malware pattern (overlay + dropper).',
            riskPoints: 15,
        });
    }

    if (perms.has('android.permission.ACCESS_BACKGROUND_LOCATION') && perms.has('android.permission.INTERNET')) {
        totalRisk += 8;
        report.flaggedIssues.push({
            category: 'Suspicious Combo',
            severity: 'high',
            description: 'BACKGROUND_LOCATION + INTERNET: Persistent tracking.',
            riskPoints: 8,
        });
    }

    // Finalize
    report.baseRiskScore = Math.min(Math.max(totalRisk, 0), 100);
    report.finalRiskScore = report.baseRiskScore;
    report.riskLevel = getRiskLevel(report.finalRiskScore);

    // Sort issues by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    report.flaggedIssues.sort((a, b) => (severityOrder[a.severity] || 3) - (severityOrder[b.severity] || 3));

    return report;
}

// Export for use in other scripts
window.RiskEngine = {
    analyzeApp,
    getRiskLevel,
    RiskLevel,
    DANGEROUS_PERMISSIONS,
    PERM_LOOKUP,
    getPermissionsByCategory,
    getInstallSourceLabel,
    OFFICIAL_STORES,
};
