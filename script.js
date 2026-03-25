/**
 * ACE Threat Intelligence Dashboard
 * Frontend JavaScript - Handles data loading, filtering, and UI interactions
 */

// Global state
let threatData = [];
let filteredData = [];

// DOM Elements

// ============================================================================
// RISK SCORING SYSTEM
// ============================================================================

/**
 *  * Calculate dynamic risk score using weighted formula
 *  * Risk Score = (CVSS Ã— 0.4) + (EPSS Ã— 10 Ã— 0.3) + (Exploit Availability Ã— 0.2) + (Asset Criticality Ã— 0.1)
 *  * 
 *  * @param {Object} threat - Threat object containing risk factors
 *  * @param {number} threat.cvss - CVSS score (0-10)
 *  * @param {number} threat.epss - EPSS score (0-1)
 *  * @param {boolean} threat.exploitAvailable - Whether exploit is publicly available
 *  * @param {number} threat.assetCriticality - Asset criticality score (1-10)
 *  * @returns {number} Risk score (0-10)
 *  */
function calculateRisk(threat) {
    // Start with neutral base score of 50 (middle of range)
    let score = 50;
    let hasHighIndicator = false;
    let hasMediumIndicator = false;
    let hasLowIndicator = false;
    
    const title = (threat.title || '').toLowerCase();
    const description = (threat.description || '').toLowerCase();
    const summary = (threat.summary || '').toLowerCase();
    const aiSummary = (threat.ai_summary?.what_happened || '').toLowerCase();
    const content = title + ' ' + description + ' ' + summary + ' ' + aiSummary;
    
    // ========================================================================
    // HIGH SEVERITY SIGNALS (+25 to +35 each) - Push toward 70-100
    // ========================================================================
    
    // Zero-day / 0-day detection (+35)
    if (content.includes('zero-day') || content.includes('0-day') || content.includes('zero day')) {
        score += 35;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Zero-day: +35`);
    }
    
    // Active exploitation / Exploit available (+30)
    if (threat.exploitAvailable || content.includes('actively exploited') || 
        content.includes('in the wild') || content.includes('exploit available') ||
        content.includes('proof of concept') || content.includes('poc released')) {
        score += 30;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Active exploitation: +30`);
    }
    
    // Data breach / Compromised (+28)
    if (content.includes('breach') || content.includes('compromised') || 
        content.includes('data leak') || content.includes('data stolen') ||
        content.includes('leaked credentials') || content.includes('exposed data')) {
        score += 28;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Breach/Compromised: +28`);
    }
    
    // Critical vulnerability (+25)
    if (content.includes('critical vulnerability') || content.includes('critical flaw') ||
        content.includes('critical security') || content.includes('severity critical')) {
        score += 25;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Critical vulnerability: +25`);
    }
    
    // Ransomware or RCE (+25)
    if (content.includes('ransomware') || content.includes('remote code execution') || 
        content.includes('rce') || content.includes('code execution')) {
        score += 25;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Ransomware/RCE: +25`);
    }
    
    // CVE with high CVSS (+20 to +30)
    const cvss = threat.cvss || 0;
    if (content.includes('cve-') && cvss >= 9.0) {
        score += 30;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Critical CVE (CVSS ${cvss}): +30`);
    } else if (content.includes('cve-') && cvss >= 7.0) {
        score += 20;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - High CVE (CVSS ${cvss}): +20`);
    }
    
    // EPSS high probability (+15)
    const epss = threat.epss || 0;
    if (epss > 0.7) {
        score += 15;
        hasHighIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - High EPSS (${epss}): +15`);
    }
    
    // ========================================================================
    // MEDIUM SEVERITY SIGNALS (+10 to +18 each) - Keep in 40-69 range
    // ========================================================================
    
    // Phishing campaigns (+15)
    if (content.includes('phishing') || content.includes('spear-phishing') ||
        content.includes('credential theft') || content.includes('credential harvesting')) {
        score += 15;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Phishing: +15`);
    }
    
    // Malware (+15)
    if (content.includes('malware') || content.includes('trojan') || 
        content.includes('backdoor') || content.includes('botnet')) {
        score += 15;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Malware: +15`);
    }
    
    // Attack campaign (+12)
    if (content.includes('attack campaign') || content.includes('threat campaign') ||
        content.includes('cyber attack') || content.includes('targeted attack')) {
        score += 12;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Attack campaign: +12`);
    }
    
    // General vulnerability mention (without critical) (+10)
    if (!hasHighIndicator && (content.includes('vulnerability') || content.includes('cve-'))) {
        score += 10;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Vulnerability mention: +10`);
    }
    
    // APT / Threat actor (+12)
    if (content.includes('apt') || content.includes('threat actor') || 
        content.includes('nation-state') || content.includes('advanced persistent')) {
        score += 12;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - APT/Threat actor: +12`);
    }
    
    // Enterprise/Cloud impact (+8)
    if (content.includes('enterprise') || content.includes('corporate') || 
        content.includes('microsoft') || content.includes('aws') || content.includes('azure')) {
        score += 8;
        hasMediumIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Enterprise/Cloud: +8`);
    }
    
    // ========================================================================
    // LOW SEVERITY SIGNALS (-15 to -30 each) - Push toward 0-39
    // ========================================================================
    
    // Research / Analysis / Report content (-20)
    if (content.includes('report') || content.includes('analysis') || 
        content.includes('research') || content.includes('study') ||
        content.includes('survey') || content.includes('findings')) {
        score -= 20;
        hasLowIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Research/Report: -20`);
    }
    
    // Trend / Statistics / Overview (-18)
    if (content.includes('trend') || content.includes('statistics') || 
        content.includes('overview') || content.includes('landscape') ||
        content.includes('forecast') || content.includes('prediction')) {
        score -= 18;
        hasLowIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Trend/Statistics: -18`);
    }
    
    // Best practices / Guidelines / Tips (-15)
    if (content.includes('best practice') || content.includes('guideline') || 
        content.includes('tips') || content.includes('how to') ||
        content.includes('recommendation') || content.includes('advice')) {
        score -= 15;
        hasLowIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Best practices/Tips: -15`);
    }
    
    // Awareness / Education content (-15)
    if (content.includes('awareness') || content.includes('education') || 
        content.includes('training') || content.includes('learn')) {
        score -= 15;
        hasLowIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Awareness/Education: -15`);
    }
    
    // Patched / Fixed / Resolved (-12)
    if (content.includes('patched') || content.includes('fixed') || 
        content.includes('resolved') || content.includes('mitigated') ||
        content.includes('update available') || content.includes('patch released')) {
        score -= 12;
        hasLowIndicator = true;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Patched/Fixed: -12`);
    }
    
    // ========================================================================
    // NEGATIVE SCORING: No real threat indicators -> Push toward LOW
    // ========================================================================
    
    if (!hasHighIndicator && !hasMediumIndicator && !hasLowIndicator) {
        // No threat indicators found - this is likely informational content
        score -= 25;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - No threat indicators: -25`);
    }
    
    // ========================================================================
    // TIME-BASED MODIFIERS
    // ========================================================================
    
    const publishedDate = new Date(threat.published || threat.published_date || Date.now());
    const hoursSincePublished = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60);
    const daysSincePublished = hoursSincePublished / 24;
    
    // Recent threat boost (+10)
    if (hoursSincePublished <= 48) {
        score += 10;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Recent (${Math.round(hoursSincePublished)}h): +10`);
    }
    
    // Old threat penalty (-15)
    if (daysSincePublished > 30) {
        score -= 15;
        console.log(`[SCORE] ${threat.title?.substring(0, 50)} - Old (${Math.round(daysSincePublished)} days): -15`);
    }
    
    // ========================================================================
    // FINAL SCORE CALCULATION
    // ========================================================================
    
    // Ensure score is within 0-100 range
    score = Math.min(Math.max(Math.round(score), 0), 100);
    
    // Determine severity
    const severity = score >= 70 ? 'High' : (score >= 40 ? 'Medium' : 'Low');
    
    // Debug logging
    console.log(`[THREAT] Title: ${threat.title?.substring(0, 60)}`);
    console.log(`[THREAT] Score: ${score} | Severity: ${severity}`);
    console.log(`[THREAT] Indicators - HIGH: ${hasHighIndicator}, MEDIUM: ${hasMediumIndicator}, LOW: ${hasLowIndicator}`);
    console.log('---');
    
    return score;
}

/**
 * Convert risk score to severity level
 * 
 * @param {number} riskScore - Risk score (0-100)
 * @returns {string} Severity level: 'Low', 'Medium', or 'High'
 */
function getSeverity(riskScore) {
    if (riskScore >= 70) return 'High';
    if (riskScore >= 40) return 'Medium';
    return 'Low';
}

/**
 *  * Get severity from threat object (calculates if needed)
 *  * 
 *  * @param {Object} threat - Threat object
 *  * @returns {string} Severity level
 *  */
function getThreatSeverity(threat) {
        // If threat has risk scoring data, calculate severity
            if (threat.cvss !== undefined || threat.epss !== undefined) {
                        const riskScore = calculateRisk(threat);
                                return getSeverity(riskScore);
            }

                // Otherwise use existing severity or default to Medium
                            const riskScore = calculateRisk(threat);
        return getSeverity(riskScore);
        }

        // ============================================================================
        // END RISK SCORING SYSTEM
        // ============================================================================

const elements = {
    totalThreats: document.getElementById('totalThreats'),
    highSeverity: document.getElementById('highSeverity'),
    mediumSeverity: document.getElementById('mediumSeverity'),
        lowSeverity: document.getElementById('lowSeverity'),
    commonThreat: document.getElementById('commonThreat'),
    lastUpdated: document.getElementById('lastUpdated'),
    threatCards: document.getElementById('threatCards'),
    topThreats: document.getElementById('topThreats'),
    threatDistribution: document.getElementById('threatDistribution'),
    resultCount: document.getElementById('resultCount'),
    searchInput: document.getElementById('searchInput'),
    severityFilter: document.getElementById('severityFilter'),
    typeFilter: document.getElementById('typeFilter'),
    dateFilter: document.getElementById('dateFilter'),
    clearFilters: document.getElementById('clearFilters'),
    modal: document.getElementById('threatModal'),
    modalBody: document.getElementById('modalBody'),
    modalClose: document.querySelector('.modal-close')
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadThreatData();
    setupEventListeners();
});

// Load threat data from JSON
async function loadThreatData() {
    try {
        const response = await fetch('data/news.json');
        if (!response.ok) throw new Error('Failed to load data');
        
        const data = await response.json();
        threatData = data.threats || [];

                // Apply dynamic risk scoring to each threat
        console.log('=== APPLYING DYNAMIC RISK SCORING ===');
        threatData = threatData.map(threat => {
            const score = calculateRisk(threat);
            const severity = getSeverity(score);
            return {
                ...threat,
                riskScore: score,
                severity: severity
            };
        });
        
        // Log severity distribution
        const highCount = threatData.filter(t => t.severity === 'High').length;
        const mediumCount = threatData.filter(t => t.severity === 'Medium').length;
        const lowCount = threatData.filter(t => t.severity === 'Low').length;
        console.log('=== SEVERITY DISTRIBUTION ===');
        console.log('HIGH: ' + highCount + ', MEDIUM: ' + mediumCount + ', LOW: ' + lowCount);
        console.log('================================');
        filteredData = [...threatData];
        
        // Update last updated timestamp
        if (data.last_updated) {
            elements.lastUpdated.textContent = formatDate(data.last_updated);
        }
        
        updateDashboard();
    } catch (error) {
        console.error('Error loading threat data:', error);
        showError();
    }
}

// Update all dashboard components
function updateDashboard() {
    updateKPIs();
    renderThreatCards();
    renderTopThreats();
    renderThreatDistribution();
    updateResultCount();
}

// Update KPI cards
function updateKPIs() {
    const total = filteredData.length;
    const high = filteredData.filter(t => t.severity?.toLowerCase() === 'high').length;
    const medium = filteredData.filter(t => t.severity?.toLowerCase() === 'medium').length;
        const low = filteredData.filter(t => t.severity?.toLowerCase() === 'low').length;
    
    // Find most common threat type
    const typeCounts = {};
    filteredData.forEach(t => {
        const type = t.threat_type || 'Unknown';
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    const commonType = Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])[0];
    
    // Animate KPI updates
    animateValue(elements.totalThreats, total);
    animateValue(elements.highSeverity, high);
    animateValue(elements.mediumSeverity, medium);
        animateValue(elements.lowSeverity, low);
    elements.commonThreat.textContent = commonType ? commonType[0] : '-';
}

// Animate number changes
function animateValue(element, newValue) {
    const currentValue = parseInt(element.textContent) || 0;
    const diff = newValue - currentValue;
    const steps = 20;
    const stepValue = diff / steps;
    let current = currentValue;
    let step = 0;
    
    const interval = setInterval(() => {
        step++;
        current += stepValue;
        element.textContent = Math.round(current);
        
        if (step >= steps) {
            element.textContent = newValue;
            clearInterval(interval);
        }
    }, 30);
}

// Render threat cards
function renderThreatCards() {
    if (filteredData.length === 0) {
        elements.threatCards.innerHTML = `
            <div class="no-results">
                <div class="no-results-icon">ðŸ”</div>
                <p>No threats found matching your criteria</p>
            </div>
        `;
        return;
    }
    
    elements.threatCards.innerHTML = filteredData.map(threat => createThreatCard(threat)).join('');
    
    // Add click handlers to cards
    document.querySelectorAll('.threat-card').forEach((card, index) => {
        card.addEventListener('click', () => openModal(filteredData[index]));
    });
}

// Create threat card HTML
function createThreatCard(threat) {
    const severityClass = `severity-${(threat.severity || 'low').toLowerCase()}`;
    const tags = threat.tags || [threat.threat_type].filter(Boolean);
    const iocs = threat.iocs || {};
    const hasIocs = Object.values(iocs).some(arr => arr && arr.length > 0);
    
    return `
        <div class="threat-card" data-id="${threat.id}">
            <div class="threat-card-header">
                <h3 class="threat-card-title">${escapeHtml(threat.title)}</h3>
                <span class="severity-badge ${severityClass}">${threat.severity || 'Unknown'}</span>
            </div>
            
            <div class="threat-card-meta">
                <span class="threat-source">ðŸ“° ${escapeHtml(threat.source || 'Unknown')}</span>
                <span class="threat-date">ðŸ“… ${formatDate(threat.published_date)}</span>
            </div>
            
            <p class="threat-card-summary">${escapeHtml(threat.ai_summary?.what_happened || threat.summary || 'No summary available')}</p>
            
            <div class="threat-card-tags">
                ${tags.map(tag => `<span class="threat-tag ${getTagClass(tag)}">${escapeHtml(tag)}</span>`).join('')}
            </div>
            
            ${hasIocs ? createIocSection(iocs) : ''}
            
            ${threat.ai_summary?.recommended_action ? `
                <div class="threat-card-actions">
                    <div class="action-header">âœ… Recommended Action</div>
                    <p class="action-text">${escapeHtml(threat.ai_summary.recommended_action)}</p>
                </div>
            ` : ''}
        </div>
    `;
}

// Create IoC section HTML
function createIocSection(iocs) {
    const allIocs = [];
    
    if (iocs.ips && iocs.ips.length > 0) {
        allIocs.push(...iocs.ips.slice(0, 3).map(ip => `<span class="ioc-item">ðŸŒ ${escapeHtml(ip)}</span>`));
    }
    if (iocs.domains && iocs.domains.length > 0) {
        allIocs.push(...iocs.domains.slice(0, 3).map(d => `<span class="ioc-item">ðŸ”— ${escapeHtml(d)}</span>`));
    }
    if (iocs.hashes && iocs.hashes.length > 0) {
        allIocs.push(...iocs.hashes.slice(0, 2).map(h => `<span class="ioc-item">#ï¸âƒ£ ${escapeHtml(h.substring(0, 16))}...</span>`));
    }
    
    if (allIocs.length === 0) return '';
    
    return `
        <div class="threat-card-iocs">
            <div class="ioc-header">ðŸš¨ Indicators of Compromise</div>
            <div class="ioc-list">${allIocs.join('')}</div>
        </div>
    `;
}

// Render top threats panel
function renderTopThreats() {
    const topThreats = [...threatData]
        .filter(t => t.severity?.toLowerCase() === 'high')
        .slice(0, 5);
    
    if (topThreats.length === 0) {
        elements.topThreats.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">No high severity threats</p>';
        return;
    }
    
    elements.topThreats.innerHTML = topThreats.map((threat, index) => `
        <div class="top-threat-item" data-id="${threat.id}">
            <span class="top-threat-rank">${index + 1}</span>
            <span class="top-threat-title">${escapeHtml(threat.title)}</span>
            <span class="top-threat-severity severity-badge severity-high">High</span>
        </div>
    `).join('');
    
    // Add click handlers
    document.querySelectorAll('.top-threat-item').forEach((item, index) => {
        item.addEventListener('click', () => openModal(topThreats[index]));
    });
}

// Render threat distribution chart
function renderThreatDistribution() {
    const typeCounts = {};
    threatData.forEach(t => {
        const type = t.threat_type || 'Other';
        typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    
    // Sort and get all categories (not just top 5)
    const sorted = Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1]);
    
    const maxCount = sorted[0]?.[1] || 1;
    
    const colors = {
        'Ransomware': 'var(--accent-red)',
        'Phishing': 'var(--accent-orange)',
        'Data Breach': 'var(--accent-purple)',
        'Zero-day': 'var(--accent-yellow)',
        'APT': 'var(--accent-blue)',
        'Malware': 'var(--accent-red)',
        'Vulnerability': 'var(--accent-cyan)',
        'Other': 'var(--text-muted)'
    };
    
    elements.threatDistribution.innerHTML = sorted.map(([type, count]) => `
        <div class="distribution-item">
            <div class="distribution-label">
                <span>${escapeHtml(type)}</span>
                <span>${count}</span>
            </div>
            <div class="distribution-bar">
                <div class="distribution-fill" style="width: ${(count / maxCount) * 100}%; background: ${colors[type] || colors['Other']}"></div>
            </div>
        </div>
    `).join('');
}

// Update result count
function updateResultCount() {
    elements.resultCount.textContent = `${filteredData.length} threat${filteredData.length !== 1 ? 's' : ''}`;
}

// Filter threats
function filterThreats() {
    const searchTerm = elements.searchInput.value.toLowerCase();
    const severity = elements.severityFilter.value;
    const type = elements.typeFilter.value;
    const dateRange = elements.dateFilter.value;
    
    filteredData = threatData.filter(threat => {
        // Search filter
        if (searchTerm) {
            const searchFields = [
                threat.title,
                threat.summary,
                threat.ai_summary?.what_happened,
                threat.source,
                ...(threat.tags || [])
            ].filter(Boolean).join(' ').toLowerCase();
            
            if (!searchFields.includes(searchTerm)) return false;
        }
        
        // Severity filter
        if (severity !== 'all' && threat.severity?.toLowerCase() !== severity) {
            return false;
        }
        
        // Type filter
        if (type !== 'all') {
            const threatType = (threat.threat_type || '').toLowerCase().replace(/[\s-]/g, '-');
            if (threatType !== type) return false;
        }
        
        // Date filter
        if (dateRange !== 'all' && threat.published_date) {
            const threatDate = new Date(threat.published_date);
            const now = new Date();
            
            switch (dateRange) {
                case 'today':
                    if (threatDate.toDateString() !== now.toDateString()) return false;
                    break;
                case 'week':
                    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    if (threatDate < weekAgo) return false;
                    break;
                case 'month':
                    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    if (threatDate < monthAgo) return false;
                    break;
            }
        }
        
        return true;
    });
    
    updateDashboard();
}

// Clear all filters
function clearFilters() {
    elements.searchInput.value = '';
    elements.severityFilter.value = 'all';
    elements.typeFilter.value = 'all';
    elements.dateFilter.value = 'all';
    filteredData = [...threatData];
    updateDashboard();
}

// Open threat detail modal
function openModal(threat) {
    const severityClass = `severity-${(threat.severity || 'low').toLowerCase()}`;
    
    elements.modalBody.innerHTML = `
        <div class="modal-header">
            <h2 class="modal-title">${escapeHtml(threat.title)}</h2>
            <div class="modal-meta">
                <span class="severity-badge ${severityClass}">${threat.severity || 'Unknown'} Severity</span>
                <span>ðŸ“° ${escapeHtml(threat.source || 'Unknown')}</span>
                <span>ðŸ“… ${formatDate(threat.published_date)}</span>
                ${threat.confidence ? `<span>ðŸŽ¯ Confidence: ${threat.confidence}</span>` : ''}
            </div>
        </div>
        
        ${threat.ai_summary ? `
            <div class="modal-section">
                <h3 class="modal-section-title">ðŸ“ Executive Summary</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.executive_summary || threat.ai_summary.what_happened || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">â“ What Happened</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.what_happened || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">âš ï¸ Why It Matters</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.why_it_matters || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">âœ… Recommended Actions</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.recommended_action || 'N/A')}</div>
            </div>
            
            ${threat.ai_summary.technical_analysis ? `
                <div class="modal-section">
                    <h3 class="modal-section-title">ðŸ”§ Technical Analysis (SOC View)</h3>
                    <div class="modal-section-content">${escapeHtml(threat.ai_summary.technical_analysis)}</div>
                </div>
            ` : ''}
        ` : ''}
        
        <div class="modal-grid">
            <div class="modal-grid-item">
                <div class="modal-grid-label">Threat Type</div>
                <div class="modal-grid-value">${escapeHtml(threat.threat_type || 'Unknown')}</div>
            </div>
            <div class="modal-grid-item">
                <div class="modal-grid-label">Risk Rating</div>
                <div class="modal-grid-value">${escapeHtml(threat.risk_rating || threat.severity || 'Unknown')}</div>
            </div>
            ${threat.threat_actor ? `
                <div class="modal-grid-item">
                    <div class="modal-grid-label">Threat Actor</div>
                    <div class="modal-grid-value">${escapeHtml(threat.threat_actor)}</div>
                </div>
            ` : ''}
            <div class="modal-grid-item">
                <div class="modal-grid-label">MITRE ATT&CK</div>
                <div class="modal-grid-value">${(threat.mitre_attack && threat.mitre_attack.length > 0) ? escapeHtml(Array.isArray(threat.mitre_attack) ? threat.mitre_attack.join(', ') : threat.mitre_attack) : 'N/A'}</div>
                        </div>
            ${threat.business_impact ? `
                <div class="modal-grid-item">
                    <div class="modal-grid-label">Business Impact</div>
                    <div class="modal-grid-value">${escapeHtml(Array.isArray(threat.business_impact) ? threat.business_impact.join(', ') : threat.business_impact)}</div>
                </div>
            ` : ''}
                            <div class="modal-grid-item">
                <div class="modal-grid-label">Framework Mapping</div>
                <div class="modal-grid-value">${threat.framework_mapping ? escapeHtml(threat.framework_mapping) : 'N/A'}</div>
            </div>

        ${threat.iocs && Object.values(threat.iocs).some(arr => arr && arr.length > 0) ? `
            <div class="modal-section">
                <h3 class="modal-section-title">ðŸš¨ Indicators of Compromise (IoCs)</h3>
                <div class="modal-section-content">
                    ${threat.iocs.ips && threat.iocs.ips.length > 0 ? `
                        <p><strong>IP Addresses:</strong></p>
                        <div class="ioc-list" style="margin-bottom: 12px;">
                            ${threat.iocs.ips.map(ip => `<span class="ioc-item">${escapeHtml(ip)}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${threat.iocs.domains && threat.iocs.domains.length > 0 ? `
                        <p><strong>Domains:</strong></p>
                        <div class="ioc-list" style="margin-bottom: 12px;">
                            ${threat.iocs.domains.map(d => `<span class="ioc-item">${escapeHtml(d)}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${threat.iocs.hashes && threat.iocs.hashes.length > 0 ? `
                        <p><strong>File Hashes:</strong></p>
                        <div class="ioc-list">
                            ${threat.iocs.hashes.map(h => `<span class="ioc-item" style="font-size: 0.7rem;">${escapeHtml(h)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        ` : ''}
        
        ${threat.detection_suggestions ? `
            <div class="modal-section">
                <h3 class="modal-section-title">ðŸ” Detection Suggestions</h3>
                <div class="modal-section-content">
                    <ul style="margin-left: 20px;">
                        ${(Array.isArray(threat.detection_suggestions) ? threat.detection_suggestions : [threat.detection_suggestions])
                            .map(s => `<li>${escapeHtml(s)}</li>`).join('')}
                    </ul>
                </div>
            </div>
        ` : ''}
        
        ${threat.url ? `
            <div class="modal-section">
                <h3 class="modal-section-title">ðŸ”— Source</h3>
                <div class="modal-section-content">
                    <a href="${escapeHtml(threat.url)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-cyan);">
                        ${escapeHtml(threat.url)}
                    </a>
                </div>
            </div>
        ` : ''}
    `;
    
    elements.modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

// Close modal
function closeModal() {
    elements.modal.classList.remove('active');
    document.body.style.overflow = '';
}

// Setup event listeners
function setupEventListeners() {
    // Filter listeners
    elements.searchInput.addEventListener('input', debounce(filterThreats, 300));
    elements.severityFilter.addEventListener('change', filterThreats);
    elements.typeFilter.addEventListener('change', filterThreats);
    elements.dateFilter.addEventListener('change', filterThreats);
    elements.clearFilters.addEventListener('click', clearFilters);
    
    // Modal listeners
    elements.modalClose.addEventListener('click', closeModal);
    elements.modal.addEventListener('click', (e) => {
        if (e.target === elements.modal) closeModal();
    });
    
    // Keyboard listener
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });
}

// Utility functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return dateString;
    }
}

function getTagClass(tag) {
    const tagLower = (tag || '').toLowerCase();
    if (tagLower.includes('ransomware')) return 'ransomware';
    if (tagLower.includes('phishing')) return 'phishing';
    if (tagLower.includes('breach')) return 'data-breach';
    if (tagLower.includes('zero-day') || tagLower.includes('0-day')) return 'zero-day';
    if (tagLower.includes('apt')) return 'apt';
    if (tagLower.includes('malware')) return 'malware';
    if (tagLower.includes('vulnerability') || tagLower.includes('cve')) return 'vulnerability';
    return '';
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function showError() {
    elements.threatCards.innerHTML = `
        <div class="no-results">
            <div class="no-results-icon">âš ï¸</div>
            <p>Failed to load threat data. Please try again later.</p>
        </div>
    `;
}

