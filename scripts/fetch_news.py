#!/usr/bin/env python3
"""
ACE Threat Intelligence Dashboard - News Fetcher

This script fetches cybersecurity news from RSS feeds, processes them using
Google's Gemini API for threat analysis, and outputs structured JSON data.

Designed to run as a GitHub Actions workflow.
"""

import os
import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional
import feedparser
import requests
import google.generativeai as genai

# Configuration
MAX_ARTICLES = 10  # Limit API usage
OUTPUT_FILE = "data/news.json"

# RSS Feeds for cybersecurity news
RSS_FEEDS = [
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/"
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews"
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/"
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml"
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed"
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/"
    }
]

# Gemini model initialization
model = None

def init_gemini():
    """Initialize Gemini client with API key from environment."""
    global model
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash')

def fetch_rss_feeds() -> list:
    """Fetch articles from all configured RSS feeds."""
    articles = []
    
    for feed_config in RSS_FEEDS:
        try:
            print(f"Fetching from {feed_config['name']}...")
            feed = feedparser.parse(feed_config["url"])
            
            for entry in feed.entries[:5]:  # Limit per feed
                article = {
                    "title": entry.get("title", "No Title"),
                    "url": entry.get("link", ""),
                    "source": feed_config["name"],
                    "summary": clean_html(entry.get("summary", entry.get("description", ""))),
                    "published_date": parse_date(entry.get("published", entry.get("updated", "")))
                }
                articles.append(article)
                
        except Exception as e:
            print(f"Error fetching {feed_config['name']}: {e}")
            continue
    
    # Sort by date and limit
    articles.sort(key=lambda x: x["published_date"] or "", reverse=True)
    return articles[:MAX_ARTICLES]

def clean_html(text: str) -> str:
    """Remove HTML tags and clean up text."""
    if not text:
        return ""
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', text)
    # Remove extra whitespace
    clean = ' '.join(clean.split())
    # Limit length
    return clean[:1000] if len(clean) > 1000 else clean

def parse_date(date_str: str) -> Optional[str]:
    """Parse date string to ISO format."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    
    try:
        # Try common formats
        for fmt in [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S"
        ]:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
        
        # Fallback: use feedparser's parsed time if available
        return datetime.now(timezone.utc).isoformat()
        
    except Exception:
        return datetime.now(timezone.utc).isoformat()

def generate_article_id(article: dict) -> str:
    """Generate unique ID for an article."""
    content = f"{article['title']}{article['url']}"
    return f"threat-{hashlib.md5(content.encode()).hexdigest()[:12]}"

def analyze_with_ai(article: dict) -> dict:
    """Use OpenAI to analyze the article and extract threat intelligence."""
    
    prompt = f"""You are a senior cybersecurity threat intelligence analyst. Analyze the following cybersecurity news article and provide a comprehensive threat assessment.

Article Title: {article['title']}
Source: {article['source']}
Summary: {article['summary']}

Provide your analysis in the following JSON format (respond ONLY with valid JSON, no markdown):
{{
    "severity": "High|Medium|Low",
    "threat_type": "Ransomware|Phishing|Data Breach|Zero-day|APT|Malware|Vulnerability|Other",
        "cvss": 0.0,  // CVSS score 0-10 (estimate based on severity and exploitability)
            "epss": 0.0,  // EPSS score 0-1 (probability of exploitation in next 30 days)
                "exploitAvailable": false,  // true if public exploit exists, false otherwise
                    "assetCriticality": 5,  // Asset criticality 1-10 (5=medium, 7-8=high, 9-10=critical)
    "tags": ["tag1", "tag2", "tag3"],
    "ai_summary": {{
        "what_happened": "Brief description of the incident/threat (2-3 sentences)",
        "why_it_matters": "Business and security implications (2-3 sentences)",
        "recommended_action": "Specific actionable recommendations (2-3 sentences)",
        "executive_summary": "Non-technical summary for executives (1-2 sentences)",
        "technical_analysis": "Technical details for SOC analysts (2-3 sentences)"
    }},
    "iocs": {{
        "ips": ["list of IP addresses if mentioned"],
        "domains": ["list of domains if mentioned"],
        "hashes": ["list of file hashes if mentioned"]
    }},
    "threat_actor": "Name of threat actor if known, otherwise 'Unknown'",
    "mitre_attack": ["Relevant MITRE ATT&CK techniques, e.g., T1566 - Phishing"],
    "business_impact": ["Financial", "Operational", "Reputational", "Regulatory"],
    "risk_rating": "Critical|High|Medium|Low",
    "confidence": "High|Medium|Low",
    "framework_mapping": "Relevant NIST CSF or ISO 27001 controls",
    "detection_suggestions": ["Specific detection recommendations for SOC teams"]
}}

Analyze the article thoroughly and provide accurate, actionable intelligence."""
IMPORTANT: For risk scoring:
- CVSS: Estimate 0-10 based on impact and exploitability (Critical=9-10, High=7-8.9, Medium=4-6.9, Low=0-3.9)
- EPSS: Estimate 0-1 probability of exploitation (Zero-days/RCE=0.7-0.9, Known vulns=0.3-0.6, Phishing=0.1-0.3)
- exploitAvailable: true if article mentions public exploit/PoC, false otherwise
- assetCriticality: Estimate 1-10 based on typical target value (Critical infrastructure=9-10, Enterprise=7-8, SMB=5-6)


    try:
        response = model.generate_content(prompt)
        
        # Parse the response
        content = response.text.strip()
        
        # Remove markdown code blocks if present
        if content.startswith("```"):
            content = re.sub(r'^```json?\n?', '', content)
            content = re.sub(r'\n?```$', '', content)
        
        analysis = json.loads(content)
        return analysis
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error for '{article['title']}': {e}")
        return get_default_analysis(article)
    except Exception as e:
        print(f"AI analysis error for '{article['title']}': {e}")
        return get_default_analysis(article)

def get_default_analysis(article: dict) -> dict:
    """Return default analysis when AI fails."""
    return {
        "severity": "Medium",
        "threat_type": "Other",
        "tags": ["Security", "Cybersecurity"],
        "ai_summary": {
            "what_happened": article.get("summary", "No summary available.")[:200],
            "why_it_matters": "This security event may impact organizations. Review the source for full details.",
            "recommended_action": "Monitor for updates and assess relevance to your organization.",
            "executive_summary": "A cybersecurity event has been reported. Review for potential impact.",
            "technical_analysis": "Technical details are available in the source article."
        },
        "iocs": {"ips": [], "domains": [], "hashes": []},
        "threat_actor": "Unknown",
        "mitre_attack": [],
        "business_impact": ["Operational"],
        "risk_rating": "Medium",
        "confidence": "Low",
        "framework_mapping": "NIST CSF: DE.CM-1",
        "detection_suggestions": ["Review source article for specific indicators"]
    }

def process_articles(articles: list) -> list:
    """Process articles with AI analysis."""
    processed = []
    
    for i, article in enumerate(articles):
        print(f"Processing article {i+1}/{len(articles)}: {article['title'][:50]}...")
        
        # Generate unique ID
        article_id = generate_article_id(article)
        
        # Get AI analysis
        analysis = analyze_with_ai(article)
        
        # Combine article data with analysis
        threat_entry = {
            "id": article_id,
            "title": article["title"],
            "source": article["source"],
            "url": article["url"],
            "published_date": article["published_date"],
            "summary": article["summary"],
            **analysis
        }
        
        processed.append(threat_entry)
    
    return processed

def save_output(threats: list):
    """Save processed threats to JSON file."""
    output = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "ACE Threat Intelligence Dashboard",
        "version": "1.0.0",
        "total_threats": len(threats),
        "threats": threats
    }
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"Saved {len(threats)} threats to {OUTPUT_FILE}")

def main():
    """Main execution function."""
    print("="*60)
    print("ACE Threat Intelligence Dashboard - News Fetcher")
    print("Powered by Google Gemini AI")
    print("="*60)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print()
    
    # Initialize Gemini
    print("Initializing Gemini AI...")
    init_gemini()
    
    # Fetch RSS feeds
    print("\nFetching RSS feeds...")
    articles = fetch_rss_feeds()
    print(f"Fetched {len(articles)} articles")
    
    if not articles:
        print("No articles fetched. Exiting.")
        return
    
    # Process with AI
    print("\nProcessing articles with AI analysis...")
    threats = process_articles(articles)
    
    # Save output
    print("\nSaving output...")
    save_output(threats)
    
    print("\n" + "="*60)
    print("Processing complete!")
    print(f"Finished at: {datetime.now(timezone.utc).isoformat()}")
    print("="*60)

if __name__ == "__main__":
    main()
