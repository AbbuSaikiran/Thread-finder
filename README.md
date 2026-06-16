<div align="center">

<img src="https://img.shields.io/badge/-%F0%9F%9B%A1%EF%B8%8F%20AppGuard-1a1a1a?style=for-the-badge" alt="AppGuard" />

# AppGuard

**LLM-Powered Android App Security Analyzer**

*Decode what your apps are really doing — 100% offline, 100% private.*

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-black?style=flat-square)](https://ollama.com)
[![ADB](https://img.shields.io/badge/ADB-Android%20Debug%20Bridge-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/tools/adb)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](LICENSE)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Offline-0f6e56?style=flat-square&logo=lock)](https://github.com)

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Risk Scores](#-risk-scores) · [Project Structure](#-project-structure)

</div>

---

## Overview

AppGuard scans your Android device's installed apps via ADB, analyzes permissions and certificates, and uses a **local Ollama LLM** to generate intelligent risk scores and plain-language recommendations.

It decodes the cryptic Android permissions system and exposes suspicious behaviors — like an app quietly requesting both SMS and Internet access (a classic OTP-theft pattern).

> **🔒 Privacy first:** No data ever leaves your machine. Everything runs locally.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 📱 | **ADB Device Scanning** | Extracts metadata, permissions, and certificates directly from your phone |
| 🔒 | **35+ Permission Detection** | Smart categorization across Location, Camera, SMS, Storage, and System |
| ⚠️ | **Suspicious Combo Detection** | Flags dangerous permission pairs — e.g., SMS + Internet signals OTP theft |
| 🤖 | **Local LLM Analysis** | Ollama-powered AI gives context-aware risk scoring, fully offline |
| 📊 | **Web Dashboard + CLI** | Choose a modern web UI or a rich color-coded terminal experience |
| 📁 | **Export Reports** | Save comprehensive security reports as JSON or standalone HTML |

---

## 🚀 Installation

### Prerequisites

- **Python 3.10+**
- **ADB (Android Debug Bridge)** — [Download Platform Tools](https://developer.android.com/tools/releases/platform-tools)
- **Ollama** *(optional, for AI analysis)* — [Download Ollama](https://ollama.com/download)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/AbbuSaikiran/Thread-finder.git
cd Thread-finder

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Pull an Ollama model for AI analysis
ollama pull llama3.1
```

---

## 🖥️ Usage

### Web Dashboard

```bash
# 1. Connect your Android device via USB (USB Debugging enabled)
# 2. Start the API server
python server.py

# 3. Open in your browser
# http://localhost:5000
```

### CLI — Demo Mode *(no device needed)*

```bash
# Test the engine with built-in realistic sample data
python -m appguard --demo
python -m appguard --demo --verbose
python -m appguard --demo --output html
```

### CLI — Scan a Connected Device

```bash
# Scan all third-party apps
python -m appguard --scan

# Include system apps
python -m appguard --scan --all-apps

# Scan a specific package
python -m appguard --package com.whatsapp --verbose
```

### CLI — Advanced Options

```bash
# Use a different LLM model (default: llama3)
python -m appguard --scan --model mistral

# Skip LLM — rule-based scoring only
python -m appguard --scan --no-llm

# Export report as JSON
python -m appguard --scan --output json
```

---

## 📊 Risk Scores

AppGuard generates a composite risk score from **0 to 100** based on permissions, install source, and certificate validity.

| Score | Level | Meaning |
|-------|-------|---------|
| 0 – 24 | 🟢 **LOW** | Minimal risk. Standard permissions for the app's purpose. |
| 25 – 49 | 🟡 **MEDIUM** | Some concerning permissions. Review recommended. |
| 50 – 74 | 🟠 **HIGH** | Significant risk. Multiple dangerous permissions or flags. |
| 75 – 100 | 🔴 **CRITICAL** | Severe risk. Suspicious combos, sideloaded, or debug-signed. |

### What gets flagged

- **Dangerous permissions** — Camera, microphone, SMS, background location
- **Suspicious combos** — e.g., `SYSTEM_ALERT_WINDOW` + `REQUEST_INSTALL_PACKAGES` (malware pattern)
- **Sideloaded apps** — Not installed from an official store like Google Play
- **Certificate issues** — Debug-signed, self-signed, or expired certificates
- **Old SDK targets** — Apps targeting outdated Android versions that bypass modern protections

---

## 🏗️ Project Structure

```
Thread-finder/
├── server.py               # API backend & web server
├── web/                    # Web dashboard
│   ├── index.html          # Dashboard entry point
│   ├── css/                # Styling system
│   └── js/                 # Risk engine & UI logic
└── appguard/               # Python CLI package
    ├── __main__.py         # CLI runner
    ├── main.py             # CLI entry point
    ├── adb_scanner.py      # ADB device communication
    ├── risk_engine.py      # Rule-based risk scoring
    ├── llm_analyzer.py     # Ollama LLM integration
    └── report.py           # Terminal formatting & exports
```

---

<div align="center">

Built for a safer mobile world. 🛡️

**MIT License** — Use freely, contribute generously.

</div>
