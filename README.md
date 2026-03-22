# 🛡️ ACE Threat Intelligence Dashboard

[![Fetch Threat Intelligence](https://github.com/tk-alajmi/ace-threat-intel-dashboard/actions/workflows/fetch-news.yml/badge.svg)](https://github.com/tk-alajmi/ace-threat-intel-dashboard/actions/workflows/fetch-news.yml)
[![demo](https://img.shields.io/badge/demo-live-brightgreen)](https://tk-alajmi.github.io/ace-threat-intel-dashboard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Pages](https://img.shields.io/badge/Hosted%20on-GitHub%20Pages-blue)](https://tk-alajmi.github.io/ace-threat-intel-dashboard/)
[![Powered by Gemini](https://img.shields.io/badge/Powered%20by-Google%20Gemini%20AI-4285F4)](https://ai.google.dev/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Live Demo](#-live-demo)
- [Screenshots](#-screenshots)
- [Features](#-features)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Deployment Guide](#-deployment-guide)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Data Schema](#-data-schema)
- [Security Considerations](#-security-considerations)
- [Troubleshooting](#-troubleshooting)
- [Local Development](#-local-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)
- [Contact](#-contact)

---

## Overview

The **ACE Threat Intelligence Dashboard** is a **production-ready, fully serverless, AI-powered Cyber Threat Intelligence platform** that aggregates cybersecurity news from multiple trusted sources, uses **Google Gemini AI** to analyze and summarize threats, and presents actionable insights in a professional SOC-style interface.

### Key Highlights

- 🚀 **Fully Serverless** - Runs entirely on GitHub Pages + GitHub Actions with no traditional backend required
- 🤖 **AI-Powered Analysis** - Leverages Google Gemini AI for intelligent threat summarization and classification
- 🔄 **Automated Updates** - Threat intelligence is automatically fetched and updated every 6 hours
- 📱 **Responsive Design** - Works seamlessly on desktop, tablet, and mobile devices
- 🌙 **Dark Mode** - Professional dark theme optimized for SOC environments
- 🆓 **100% Free Hosting** - No server costs, runs entirely on GitHub's free tier
- 🔒 **Secure by Design** - API keys stored securely in GitHub Secrets, no client-side exposure

---

## 🌐 Live Demo

**[👉 View Live Dashboard](https://tk-alajmi.github.io/ace-threat-intel-dashboard/)**

The dashboard is automatically updated every 6 hours with the latest threat intelligence from multiple cybersecurity news sources.

---

## 📸 Screenshots

### Dashboard Overview
<img width="834" height="1254" alt="image" src="https://github.com/user-attachments/assets/73e722c9-918d-447e-a042-dfc2b8e1561f" />
*Main dashboard showing KPIs, threat feed, and filtering options*

### Threat Detail Modal
<img width="844" height="1271" alt="image" src="https://github.com/user-attachments/assets/037ec509-3d6c-40a9-bbec-df1a53a7f1a0" />
*Detailed threat analysis with IoCs, MITRE ATT&CK mapping, and recommendations*

### Mobile Responsive
<img width="943" height="2048" alt="image" src="https://github.com/user-attachments/assets/b23d5988-33ea-4b80-8534-6cb4218b4704" />
*Fully responsive design for mobile devices*

> **Note:** Replace placeholder images with actual screenshots after deployment.

---

## ✨ Features

### 🎯 Threat Intelligence

| Feature | Description |
|---------|-------------|
| **AI-Generated Summaries** | Each threat includes comprehensive AI-generated analysis covering what happened, why it matters, recommended actions, executive summary (non-technical), and technical analysis (SOC view) |
| **Severity Classification** | Automatic severity rating (Critical, High, Medium, Low) based on threat characteristics and potential impact |
| **Threat Categorization** | Automatic categorization including Malware, Ransomware, Phishing, APT, Vulnerability, Data Breach, Zero-Day, Supply Chain, DDoS, and Insider Threat |
| **Confidence Levels** | AI-assessed confidence rating (High, Medium, Low) for each threat analysis |

### 🔍 SOC-Level Features

| Feature | Description |
|---------|-------------|
| **Indicators of Compromise (IoCs)** | Extracted IPs, domains, hashes, and other indicators for threat hunting |
| **MITRE ATT&CK Mapping** | Automatic mapping to MITRE ATT&CK framework techniques (e.g., T1190 - Exploit Public-Facing Application) |
| **Threat Actor Identification** | Attribution to known threat actors when available (e.g., APT29, Lazarus Group) |
| **Detection Suggestions** | Actionable detection rules and monitoring recommendations |
| **Kill Chain Analysis** | Mapping to cyber kill chain phases for better understanding of attack progression |

### 📊 GRC/Risk Features

| Feature | Description |
|---------|-------------|
| **Business Impact Assessment** | Analysis of potential business impacts (Operational, Financial, Reputational, Legal) |
| **Risk Rating** | Overall risk rating considering likelihood and impact |
| **Framework Mapping** | Mapping to compliance frameworks (NIST CSF, ISO 27001, PCI-DSS, HIPAA) |
| **Executive Summaries** | Non-technical summaries suitable for executive briefings |
| **Trend Analysis** | Identification of emerging threat trends and patterns |

### 🖥️ Dashboard Features

| Feature | Description |
|---------|-------------|
| **Real-time KPI Cards** | At-a-glance metrics showing total threats, severity breakdown, and most common threat types |
| **Interactive Threat Feed** | Scrollable feed with expandable threat cards showing detailed analysis |
| **Advanced Filtering** | Filter by severity, threat type, date range, and keyword search |
| **Top Threats Panel** | Sidebar highlighting the most critical threats requiring immediate attention |
| **Threat Distribution Chart** | Visual breakdown of threats by category |
| **Dark Mode Interface** | Professional dark theme reducing eye strain in SOC environments |
| **Responsive Design** | Optimized for desktop, tablet, and mobile viewing |
| **Offline Capability** | Dashboard works with cached data when offline |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GITHUB ACTIONS                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Scheduled Workflow (Every 6 Hours)                │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │   │
│  │  │  RSS Feeds   │───▶│   Python     │───▶│   Google Gemini AI   │  │   │
│  │  │  (Multiple   │    │   Script     │    │   (Analysis &        │  │   │
│  │  │   Sources)   │    │              │    │    Summarization)    │  │   │
│  │  └──────────────┘    └──────────────┘    └──────────────────────┘  │   │
│  │                              │                                       │   │
│  │                              ▼                                       │   │
│  │                    ┌──────────────────┐                             │   │
│  │                    │   threats.json   │                             │   │
│  │                    │   (Data Store)   │                             │   │
│  │                    └──────────────────┘                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GITHUB PAGES                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Static Website                               │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │   │
│  │  │  index.html  │    │  script.js   │    │     style.css        │  │   │
│  │  │  (Structure) │    │  (Logic)     │    │     (Styling)        │  │   │
│  │  └──────────────┘    └──────────────┘    └──────────────────────┘  │   │
│  │                              │                                       │   │
│  │                              ▼                                       │   │
│  │                    ┌──────────────────┐                             │   │
│  │                    │   Dashboard UI   │                             │   │
│  │                    │   (Browser)      │                             │   │
│  │                    └──────────────────┘                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Data Collection**: GitHub Actions runs a scheduled workflow every 6 hours
2. **RSS Aggregation**: Python script fetches latest articles from multiple cybersecurity RSS feeds
3. **AI Analysis**: Each article is sent to Google Gemini AI for comprehensive threat analysis
4. **Data Storage**: Analyzed threats are saved to `data/threats.json`
5. **Auto-Commit**: Changes are automatically committed to the repository
6. **GitHub Pages**: Static site is automatically rebuilt and deployed
7. **User Access**: Users access the dashboard via GitHub Pages URL

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) | Dashboard UI |
| **Backend** | Python 3.x | Data fetching and processing |
| **AI Engine** | Google Gemini AI (gemini-1.5-flash) | Threat analysis and summarization |
| **Hosting** | GitHub Pages | Static site hosting (FREE) |
| **Automation** | GitHub Actions | Scheduled data updates |
| **Data Format** | JSON | Threat data storage |
| **RSS Parsing** | feedparser (Python) | RSS feed aggregation |

---

## 📁 Project Structure

```
ace-threat-intel-dashboard/
├── .github/
│   └── workflows/
│       └── fetch-news.yml      # GitHub Actions workflow
├── assets/
│   └── ace-logo.png            # Dashboard logo
├── data/
│   └── threats.json            # Generated threat intelligence data
├── screenshots/                # Screenshot images
├── scripts/
│   └── fetch_news.py           # Python script for fetching threats
├── index.html                  # Main dashboard HTML
├── script.js                   # Dashboard JavaScript logic
├── style.css                   # Dashboard styling
├── requirements.txt            # Python dependencies
├── LICENSE                     # MIT License
└── README.md                   # This file
```

---

## 🚀 Deployment Guide

### Prerequisites

1. **GitHub Account** - Free account is sufficient
2. **Google AI Studio API Key** - Get one free at [Google AI Studio](https://aistudio.google.com/app/apikey)
3. **Git** - For cloning and managing the repository

### Step-by-Step Deployment

#### Step 1: Fork or Clone the Repository

**Option A: Fork (Recommended)**
1. Click the "Fork" button at the top right of this repository
2. Select your GitHub account as the destination

**Option B: Clone**
```bash
git clone https://github.com/tk-alajmi/ace-threat-intel-dashboard.git
cd ace-threat-intel-dashboard
```

#### Step 2: Configure GitHub Secrets

1. Go to your repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add:

| Name | Value |
|------|-------|
| `GEMINI_API_KEY` | Your Google Gemini API key |

> ⚠️ **Important**: Never commit your API key directly to the repository.

#### Step 3: Enable GitHub Pages

1. Go to **Settings** → **Pages**
2. Under "Source", select **Deploy from a branch**
3. Select **main** branch and **/ (root)** folder
4. Click **Save**

#### Step 4: Enable GitHub Actions

1. Go to the **Actions** tab
2. Click **"I understand my workflows, go ahead and enable them"**
3. Manually trigger: Click **"Fetch Threat Intelligence"** → **"Run workflow"**

#### Step 5: Verify Deployment

Visit: `https://YOUR_USERNAME.github.io/ace-threat-intel-dashboard/`

---

## ⚙️ Configuration

### RSS Feed Sources

Edit `scripts/fetch_news.py` to modify sources:

```python
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    # Add more feeds here
]
```

### AI Model Configuration

```python
model = genai.GenerativeModel('gemini-1.5-flash')

generation_config = {
    "temperature": 0.3,
    "top_p": 0.8,
    "max_output_tokens": 2048,
}
```

### Scheduling

Edit `.github/workflows/fetch-news.yml`:

```yaml
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:
```

---

## 📡 API Reference

### Threat Data Endpoint

```
GET https://tk-alajmi.github.io/ace-threat-intel-dashboard/data/threats.json
```

---

## 📊 Data Schema

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier |
| `title` | string | Threat headline |
| `severity` | enum | Critical, High, Medium, Low |
| `threat_type` | enum | Malware, Ransomware, Phishing, etc. |
| `summary` | object | AI-generated analysis |
| `iocs` | object | Indicators of Compromise |
| `mitre_attack` | array | MITRE ATT&CK technique IDs |
| `threat_actor` | string | Attributed threat actor |
| `business_impact` | array | Impact categories |
| `confidence` | enum | High, Medium, Low |

---

## 🔒 Security Considerations

- ✅ API keys stored in GitHub Secrets (encrypted)
- ✅ Keys never exposed in client-side code
- ✅ HTTPS enforced by GitHub Pages
- ✅ No sensitive data collected

---

## 🔧 Troubleshooting

### Workflow Fails
Verify `GEMINI_API_KEY` is correctly set in repository secrets.

### No Threats Displayed
1. Check Actions tab for workflow status
2. Verify `data/threats.json` exists
3. Manually trigger the workflow

### Pages Not Updating
Clear browser cache and wait 5-10 minutes for CDN propagation.

---

## 💻 Local Development

```bash
# Run frontend
python -m http.server 8000

# Test Python script
pip install -r requirements.txt
set GEMINI_API_KEY=your-api-key
python scripts/fetch_news.py
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/AmazingFeature`
3. Commit changes: `git commit -m 'Add AmazingFeature'`
4. Push: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## ⚠️ Disclaimer

This dashboard is for **educational and informational purposes only**. AI-generated analysis should be verified by security professionals before taking action.

---

## 💬 Contact

- **GitHub Issues**: [Open an issue](https://github.com/tk-alajmi/ace-threat-intel-dashboard/issues)

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

[![GitHub stars](https://img.shields.io/github/stars/tk-alajmi/ace-threat-intel-dashboard?style=social)](https://github.com/tk-alajmi/ace-threat-intel-dashboard)

</div>
