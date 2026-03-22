# 🛡️ ACE Threat Intelligence Dashboard

[![Fetch Threat Intelligence](https://github.com/YOUR_USERNAME/ace-threat-intel-dashboard/actions/workflows/fetch-news.yml/badge.svg)](https://github.com/YOUR_USERNAME/ace-threat-intel-dashboard/actions/workflows/fetch-news.yml)
[![GitHub Pages](https://img.shields.io/badge/demo-live-brightgreen)](https://YOUR_USERNAME.github.io/ace-threat-intel-dashboard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **production-ready, AI-powered Cyber Threat Intelligence Dashboard** that aggregates cybersecurity news from multiple sources, uses AI to analyze and summarize threats, and presents insights in a professional SOC-style interface.

**🚀 Fully serverless** - Runs entirely on GitHub Pages + GitHub Actions with no traditional backend required.

---

## 📸 Screenshots

### Dashboard Overview
![Dashboard Overview](screenshots/dashboard-overview.png)
*Main dashboard showing KPIs, threat feed, and filtering options*

### Threat Detail Modal
![Threat Detail](screenshots/threat-detail.png)
*Detailed threat analysis with IoCs, MITRE ATT&CK mapping, and recommendations*

### Mobile Responsive
![Mobile View](screenshots/mobile-view.png)
*Fully responsive design for mobile devices*

> **Note:** Replace placeholder images with actual screenshots after deployment.

---

## ✨ Features

### 🎯 Threat Intelligence
- **AI-Generated Summaries**
  - What happened
  - Why it matters
  - Recommended actions
  - Executive summary (non-technical)
  - Technical analysis (SOC view)

- **Severity Classification**: High / Medium / Low
- **Threat Categorization**: Ransomware, Phishing, Data Breach, Zero-day, APT, Malware, Vulnerability

### 🔍 SOC-Level Features
- **Indicators of Compromise (IoCs)**: IPs, domains, file hashes
- **MITRE ATT&CK Mapping**: Technique identification
- **Threat Actor Identification**: Attribution when available
- **Detection Suggestions**: Actionable SOC recommendations

### 📊 GRC / Risk Features
- **Business Impact Assessment**: Financial, Operational, Reputational, Regulatory
- **Risk Rating**: Critical to Low scale
- **Framework Mapping**: NIST CSF, ISO 27001 references
- **Confidence Levels**: High / Medium / Low

### 🖥️ Dashboard Features
- **KPI Cards**: Total threats, severity counts, common threat types
- **Threat Feed**: Scrollable cards with key information
- **Filtering & Search**: By severity, type, date, keywords
- **Top Threats Panel**: Quick access to high-priority items
- **Threat Distribution Chart**: Visual breakdown by type
- **Dark Mode**: SOC-optimized dark theme (default)
- **Responsive Design**: Works on desktop, tablet, and mobile

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GITHUB REPOSITORY                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │  GitHub Actions  │    │   GitHub Pages   │                   │
│  │  (Scheduled Job) │    │  (Static Host)   │                   │
│  └────────┬─────────┘    └────────▲─────────┘                   │
│           │                       │                              │
│           │ Runs every 2 hours    │ Serves static files          │
│           ▼                       │                              │
│  ┌──────────────────┐             │                              │
│  │  fetch_news.py   │             │                              │
│  │  Python Script   │             │                              │
│  └────────┬─────────┘             │                              │
│           │                       │                              │
│           │ 1. Fetch RSS feeds    │                              │
│           │ 2. Process with AI    │                              │
│           │ 3. Generate JSON      │                              │
│           ▼                       │                              │
│  ┌──────────────────┐             │                              │
│  │  data/news.json  │─────────────┘                              │
│  │  (Threat Data)   │                                            │
│  └──────────────────┘                                            │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Frontend Files                         │   │
│  │  index.html  │  style.css  │  script.js                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              ACE Threat Intelligence Dashboard             │  │
│  │  • Loads static HTML/CSS/JS                               │  │
│  │  • Fetches data/news.json                                 │  │
│  │  • Renders threat intelligence                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      EXTERNAL SERVICES                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │   RSS Feeds      │    │   OpenAI API     │                   │
│  │  • BleepingComp  │    │  • GPT-4o-mini   │                   │
│  │  • Hacker News   │    │  • Analysis      │                   │
│  │  • Krebs         │    │  • Summarization │                   │
│  │  • Dark Reading  │    │                  │                   │
│  │  • SecurityWeek  │    │                  │                   │
│  └──────────────────┘    └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ace-threat-intel-dashboard/
├── index.html                 # Main dashboard HTML
├── style.css                  # Dark mode SOC-style CSS
├── script.js                  # Frontend JavaScript logic
├── README.md                  # This file
├── data/
│   └── news.json              # Processed threat intelligence data
├── scripts/
│   └── fetch_news.py          # Python script for fetching/processing
└── .github/
    └── workflows/
        └── fetch-news.yml     # GitHub Actions workflow
```

---

## 🚀 Deployment Guide

### Prerequisites
- GitHub account
- OpenAI API key ([Get one here](https://platform.openai.com/api-keys))

### Step 1: Fork or Clone Repository

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ace-threat-intel-dashboard.git
cd ace-threat-intel-dashboard
```

### Step 2: Configure GitHub Secrets

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add the following secret:
   - **Name:** `OPENAI_API_KEY`
   - **Value:** Your OpenAI API key

### Step 3: Enable GitHub Pages

1. Go to **Settings** → **Pages**
2. Under **Source**, select:
   - **Branch:** `main`
   - **Folder:** `/ (root)`
3. Click **Save**
4. Wait a few minutes for deployment

### Step 4: Enable GitHub Actions

1. Go to **Actions** tab
2. If prompted, enable workflows
3. The workflow will run automatically every 2 hours
4. You can also trigger it manually via **Run workflow**

### Step 5: Verify Deployment

1. Visit `https://YOUR_USERNAME.github.io/ace-threat-intel-dashboard/`
2. Check the **Actions** tab to verify the workflow runs successfully
3. The dashboard should display threat intelligence data

---

## ⚙️ Configuration

### Adjusting Update Frequency

Edit `.github/workflows/fetch-news.yml`:

```yaml
on:
  schedule:
    # Current: Every 2 hours
    - cron: '0 */2 * * *'
    
    # Alternatives:
    # Every hour:     '0 * * * *'
    # Every 3 hours:  '0 */3 * * *'
    # Every 6 hours:  '0 */6 * * *'
    # Daily at 6 AM:  '0 6 * * *'
```

### Adding RSS Feeds

Edit `scripts/fetch_news.py`:

```python
RSS_FEEDS = [
    {
        "name": "Your Source Name",
        "url": "https://example.com/feed.xml"
    },
    # ... existing feeds
]
```

### Changing AI Model

Edit `scripts/fetch_news.py`:

```python
response = client.chat.completions.create(
    model="gpt-4o-mini",  # Change to "gpt-4o" for better analysis
    # ...
)
```

---

## 🔐 Security Considerations

- ✅ API keys stored securely in GitHub Secrets
- ✅ No sensitive data exposed in frontend code
- ✅ Environment variables used in GitHub Actions
- ✅ Limited API usage (max 10 articles per run)
- ✅ No backend server to secure

---

## 📊 Example JSON Output

```json
{
  "last_updated": "2026-03-22T23:00:00Z",
  "source": "ACE Threat Intelligence Dashboard",
  "version": "1.0.0",
  "threats": [
    {
      "id": "threat-abc123def456",
      "title": "Critical Zero-Day Vulnerability in Enterprise VPN",
      "source": "BleepingComputer",
      "url": "https://example.com/article",
      "published_date": "2026-03-22T18:30:00Z",
      "severity": "High",
      "threat_type": "Zero-day",
      "tags": ["Zero-day", "VPN", "CVE-2026-1234"],
      "ai_summary": {
        "what_happened": "Security researchers discovered...",
        "why_it_matters": "VPN solutions are critical...",
        "recommended_action": "Immediately apply patches...",
        "executive_summary": "A critical vulnerability...",
        "technical_analysis": "The vulnerability exists..."
      },
      "iocs": {
        "ips": ["185.220.101.45"],
        "domains": ["malicious-domain.com"],
        "hashes": ["a1b2c3d4e5f6..."]
      },
      "threat_actor": "APT-Unknown",
      "mitre_attack": ["T1190 - Exploit Public-Facing Application"],
      "business_impact": ["Operational", "Financial"],
      "risk_rating": "Critical",
      "confidence": "High",
      "framework_mapping": "NIST CSF: PR.IP-12",
      "detection_suggestions": ["Monitor for unusual connections..."]
    }
  ]
}
```

---

## 🔗 Live Demo

**🌐 [View Live Dashboard](https://YOUR_USERNAME.github.io/ace-threat-intel-dashboard/)**

> Replace `YOUR_USERNAME` with your GitHub username after deployment.

---

## 🛠️ Local Development

### Running the Frontend

```bash
# Using Python's built-in server
python -m http.server 8000

# Or using Node.js
npx serve .
```

Then open `http://localhost:8000` in your browser.

### Testing the Python Script

```bash
# Install dependencies
pip install feedparser openai requests

# Set environment variable
export OPENAI_API_KEY="your-api-key"

# Run the script
python scripts/fetch_news.py
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⚠️ Disclaimer

This dashboard aggregates publicly available threat intelligence for **educational and informational purposes only**. The AI-generated analysis should be verified by qualified security professionals before taking action. The authors are not responsible for any decisions made based on this information.

---

## 📧 Contact

For questions or feedback, please open an issue on GitHub.

---

**Built with ❤️ for the cybersecurity community**
