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
 *  * Risk Score = (CVSS × 0.4) + (EPSS × 10 × 0.3) + (Exploit Availability × 0.2) + (Asset Criticality × 0.1)
 *  * 
 *  * @param {Object} threat - Threat object containing risk factors
 *  * @param {number} threat.cvss - CVSS score (0-10)
 *  * @param {number} threat.epss - EPSS score (0-1)
 *  * @param {boolean} threat.exploitAvailable - Whether exploit is publicly available
 *  * @param {number} threat.assetCriticality - Asset criticality score (1-10)
 *  * @returns {number} Risk score (0-10)
 *  */
function calculateRisk(threat) {
        // Extract risk factors with defaults
            const cvss = threat.cvss || 0;
                const epss = threat.epss || 0;
                    const exploitAvailable = threat.exploitAvailable || false;
                        const assetCriticality = threat.assetCriticality || 5;

                            // Apply weighted formula
                                const cvssWeight = cvss * 0.4;
                                    const epssWeight = (epss * 10) * 0.3;  // Scale EPSS from 0-1 to 0-10
                                        const exploitWeight = (exploitAvailable ? 10 : 0) * 0.2;
                                            const assetWeight = assetCriticality * 0.1;

                                                const riskScore = cvssWeight + epssWeight + exploitWeight + assetWeight;

                                                    // Ensure score is within 0-10 range
                                                        return Math.min(Math.max(riskScore, 0), 10);
}

/**
 *  * Convert risk score to severity level
 *  * 
 *  * @param {number} riskScore - Risk score (0-10)
 *  * @returns {string} Severity level: 'Low', 'Medium', 'High', or 'Critical'
 *  */
function getSeverity(riskScore) {
        if (riskScore >= 9.0) return 'Critical';
            if (riskScore >= 7.0) return 'High';
                if (riskScore >= 4.0) return 'Medium';
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
                    return threat.severity || 'Medium';
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
                <div class="no-results-icon">🔍</div>
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
                <span class="threat-source">📰 ${escapeHtml(threat.source || 'Unknown')}</span>
                <span class="threat-date">📅 ${formatDate(threat.published_date)}</span>
            </div>
            
            <p class="threat-card-summary">${escapeHtml(threat.ai_summary?.what_happened || threat.summary || 'No summary available')}</p>
            
            <div class="threat-card-tags">
                ${tags.map(tag => `<span class="threat-tag ${getTagClass(tag)}">${escapeHtml(tag)}</span>`).join('')}
            </div>
            
            ${hasIocs ? createIocSection(iocs) : ''}
            
            ${threat.ai_summary?.recommended_action ? `
                <div class="threat-card-actions">
                    <div class="action-header">✅ Recommended Action</div>
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
        allIocs.push(...iocs.ips.slice(0, 3).map(ip => `<span class="ioc-item">🌐 ${escapeHtml(ip)}</span>`));
    }
    if (iocs.domains && iocs.domains.length > 0) {
        allIocs.push(...iocs.domains.slice(0, 3).map(d => `<span class="ioc-item">🔗 ${escapeHtml(d)}</span>`));
    }
    if (iocs.hashes && iocs.hashes.length > 0) {
        allIocs.push(...iocs.hashes.slice(0, 2).map(h => `<span class="ioc-item">#️⃣ ${escapeHtml(h.substring(0, 16))}...</span>`));
    }
    
    if (allIocs.length === 0) return '';
    
    return `
        <div class="threat-card-iocs">
            <div class="ioc-header">🚨 Indicators of Compromise</div>
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
                <span>📰 ${escapeHtml(threat.source || 'Unknown')}</span>
                <span>📅 ${formatDate(threat.published_date)}</span>
                ${threat.confidence ? `<span>🎯 Confidence: ${threat.confidence}</span>` : ''}
            </div>
        </div>
        
        ${threat.ai_summary ? `
            <div class="modal-section">
                <h3 class="modal-section-title">📝 Executive Summary</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.executive_summary || threat.ai_summary.what_happened || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">❓ What Happened</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.what_happened || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">⚠️ Why It Matters</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.why_it_matters || 'N/A')}</div>
            </div>
            
            <div class="modal-section">
                <h3 class="modal-section-title">✅ Recommended Actions</h3>
                <div class="modal-section-content">${escapeHtml(threat.ai_summary.recommended_action || 'N/A')}</div>
            </div>
            
            ${threat.ai_summary.technical_analysis ? `
                <div class="modal-section">
                    <h3 class="modal-section-title">🔧 Technical Analysis (SOC View)</h3>
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
                <h3 class="modal-section-title">🚨 Indicators of Compromise (IoCs)</h3>
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
                <h3 class="modal-section-title">🔍 Detection Suggestions</h3>
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
                <h3 class="modal-section-title">🔗 Source</h3>
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
            <div class="no-results-icon">⚠️</div>
            <p>Failed to load threat data. Please try again later.</p>
        </div>
    `;
}
