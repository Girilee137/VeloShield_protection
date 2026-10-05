let currentUser = null;
let liveTestInterval = null;
let selectedPreFiles = [];
let currentPreScanId = null;
let currentPostScanId = null;
let currentPreFindings = [];
let currentPostFindings = [];

// Safe DOM Helper Functions
function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = (text !== undefined && text !== null ? text : '');
}

function setElHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = (html !== undefined && html !== null ? html : '');
}

document.addEventListener('DOMContentLoaded', async () => {
    try {
        currentUser = await API.me();
        setElText('user-email', currentUser.email);
        const avatar = document.getElementById('user-avatar');
        if (avatar && currentUser.email) {
            avatar.textContent = currentUser.email.substring(0, 2).toUpperCase();
        }
    } catch (e) {
        window.location.href = 'index.html';
        return;
    }

    // Navigation setup
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const nav = e.currentTarget.dataset.nav;
            switchToSection(nav);
        });
    });

    // Logout
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try { await API.logout(); } catch(_) {}
            window.location.href = 'index.html';
        });
    }

    // Initial Overview Load
    loadSectionData('overview');

    // Setup Drag and Drop for Pre-deployment
    setupFileDropzone();

    // Form handlers
    setupPreDeployForm();
    setupPostDeployForm();
    setupTargetAndLoadForms();
});

function switchToSection(nav) {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.dashboard-section').forEach(s => s.classList.remove('active'));

    const navLink = document.querySelector(`.nav-link[data-nav="${nav}"]`);
    if (navLink) navLink.classList.add('active');

    const sec = document.getElementById(`${nav}-section`);
    if (sec) sec.classList.add('active');

    loadSectionData(nav);
}

async function loadSectionData(section) {
    try {
        if (section === 'overview') {
            const [preScans, postScans, tests, targets] = await Promise.all([
                API.getAssessments('BEFORE_DEPLOYMENT').catch(() => []),
                API.getAssessments('AFTER_DEPLOYMENT').catch(() => []),
                API.getTests().catch(() => []),
                API.getTargets().catch(() => [])
            ]);

            setElText('stat-pre-scans', preScans.length);
            setElText('stat-post-scans', postScans.length);
            setElText('stat-load-tests', tests.length);
            setElText('stat-total-targets', targets.length);

            // Backwards compatibility elements
            setElText('stat-verified-targets', targets.filter(t => t.verified).length);
            setElText('stat-total-tests', tests.length);

            renderRecentAssessments([...preScans, ...postScans]);
        } else if (section === 'load-test' || section === 'targets' || section === 'tests') {
            loadTargetsAndTests();
        } else if (section === 'history') {
            loadHistoryList('ALL');
        }
    } catch (e) {
        console.error('Error loading section:', e);
    }
}

// ==========================================
// WORKFLOW A: BEFORE DEPLOYMENT
// ==========================================

function setupFileDropzone() {
    const dropzone = document.getElementById('file-dropzone');
    const input = document.getElementById('file-input');

    if (!dropzone || !input) return;

    ['dragenter', 'dragover'].forEach(name => {
        dropzone.addEventListener(name, (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(name => {
        dropzone.addEventListener(name, (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
        });
    });

    dropzone.addEventListener('drop', (e) => {
        if (e.dataTransfer && e.dataTransfer.files) {
            handleFilesSelection(e.dataTransfer.files);
        }
    });

    input.addEventListener('change', (e) => {
        if (e.target.files) {
            handleFilesSelection(e.target.files);
        }
    });
}

function handleFilesSelection(fileList) {
    for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const reader = new FileReader();
        reader.onload = (event) => {
            selectedPreFiles.push({
                path: file.webkitRelativePath || file.name,
                content: event.target.result
            });
            renderSelectedFilesList();
        };
        reader.readAsText(file);
    }
}

function renderSelectedFilesList() {
    const container = document.getElementById('selected-files-list');
    if (!container) return;

    if (selectedPreFiles.length === 0) {
        container.innerHTML = '<span class="text-xs text-secondary">No files selected yet.</span>';
        return;
    }

    container.innerHTML = selectedPreFiles.map((f, idx) => `
        <span class="file-chip">
            <span>${f.path}</span>
            <button type="button" onclick="removePreFile(${idx})" style="background:none;border:none;color:var(--text-secondary);cursor:pointer;font-size:0.9rem;">&times;</button>
        </span>
    `).join('');
}

function removePreFile(idx) {
    selectedPreFiles.splice(idx, 1);
    renderSelectedFilesList();
}

function loadSampleProject(type = 'vulnerable_node') {
    const projInput = document.getElementById('pre-project-name');
    if (type === 'clean_spring') {
        if (projInput) projInput.value = 'Cloud Security Gateway (Spring Boot 3)';
        selectedPreFiles = [
            {
                path: 'pom.xml',
                content: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.enterprise</groupId>
    <artifactId>secure-gateway</artifactId>
    <version>3.2.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.4</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
            <version>3.2.4</version>
        </dependency>
    </dependencies>
</project>`
            },
            {
                path: 'src/main/resources/application.properties',
                content: `server.port=8080\nspring.datasource.url=\${DB_JDBC_URL}\nspring.datasource.username=\${DB_USER}\nspring.datasource.password=\${DB_PASSWORD}\nserver.error.include-stacktrace=never\nserver.error.include-message=never`
            },
            {
                path: 'src/main/java/com/enterprise/SecurityConfig.java',
                content: `@Configuration\npublic class SecurityConfig {\n    @Bean\n    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n        return http.csrf(Customizer.withDefaults()).headers(h -> h.httpStrictTransportSecurity(Customizer.withDefaults())).authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n    }\n}`
            }
        ];
        showToast('Clean Spring Boot 3 enterprise sample loaded!', 'success');
    } else if (type === 'python_flask') {
        if (projInput) projInput.value = 'Analytics API (Python Flask)';
        selectedPreFiles = [
            {
                path: 'requirements.txt',
                content: `Flask==2.0.1\nrequests==2.25.1\npsycopg2-binary==2.9.1`
            },
            {
                path: 'app.py',
                content: `from flask import Flask, jsonify, request\napp = Flask(__name__)\napp.config['SECRET_KEY'] = 'AKIAIOSFODNN7EXAMPLE_SAMPLE_KEY'\n\n@app.route('/api/debug/dump', methods=['GET'])\ndef debug_dump():\n    return jsonify({'config': dict(app.config)})\n\nif __name__ == '__main__':\n    app.run(debug=True, host='0.0.0.0')`
            },
            {
                path: '.env',
                content: `JWT_SECRET=superSecretToken987654321!\nDEBUG=True\nDATABASE_URL=postgres://root:p@ssw0rd@db:5432/app`
            }
        ];
        showToast('Python Flask sample with exposed debug & secrets loaded!', 'success');
    } else {
        if (projInput) projInput.value = 'E-Commerce Microservice (Node.js)';
        selectedPreFiles = [
            {
                path: 'package.json',
                content: JSON.stringify({
                    name: 'sample-app',
                    version: '1.0.0',
                    dependencies: {
                        'express': '^4.18.2',
                        'axios': '0.19.0',
                        'lodash': '4.17.15',
                        'pg': '^8.11.0'
                    }
                }, null, 2)
            },
            {
                path: 'config/database.js',
                content: `// Database Configuration\nconst dbUrl = "postgresql://dbuser:superSecretPass123!@db.internal.aws:5432/production";\nconst debug = true;\nmodule.exports = { dbUrl, debug };`
            },
            {
                path: 'routes/admin.js',
                content: `const express = require('express');\nconst router = express.Router();\n\n// Unprotected admin route\nrouter.get('/admin/users', (req, res) => {\n  try {\n    res.json({ users: [] });\n  } catch (e) {\n    e.printStackTrace();\n    res.status(500).send(e.message);\n  }\n});\n\nmodule.exports = router;`
            },
            {
                path: 'public/index.html',
                content: `<!DOCTYPE html><html><head><script src="http://insecure-cdn.com/analytics.js"></script></head><body><div id="app"></div></body></html>`
            }
        ];
        showToast('Vulnerable Node.js sample loaded! Ready to scan.', 'success');
    }
    renderSelectedFilesList();
}

function fillPostUrl(url) {
    const input = document.getElementById('post-target-url');
    if (input) {
        input.value = url;
        showToast(`Target URL set to ${url}`, 'success');
    }
}

function setupPreDeployForm() {
    const form = document.getElementById('pre-deploy-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const projInput = document.getElementById('pre-project-name');
        const projectName = projInput ? projInput.value.trim() : 'Project';

        if (selectedPreFiles.length === 0) {
            showToast('Please select at least one project file or click "Load Sample Project Files"', 'error');
            return;
        }

        const btn = document.getElementById('start-pre-scan-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Running Static Analysis...';
        }

        // Animate checklist
        animateChecklist('pre', [
            'step-pre-structure',
            'step-pre-deps',
            'step-pre-secrets',
            'step-pre-config',
            'step-pre-api',
            'step-pre-errors',
            'step-pre-score'
        ]);

        try {
            const res = await API.startPreDeploymentScan(projectName, selectedPreFiles);
            currentPreScanId = res.id;
            currentPreFindings = res.findings || [];

            renderPreScanResults(res);
            showToast('Pre-deployment scan completed successfully!', 'success');
            loadSectionData('overview');
        } catch (error) {
            showToast(error.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Start Safe Project Analysis';
            }
        }
    });
}

function renderPreScanResults(data) {
    const container = document.getElementById('pre-results-container');
    if (container) container.style.display = 'block';

    const scores = data.scores || {};
    const overall = scores.overall ?? 0;
    const status = scores.status || 'UNKNOWN';

    setElText('pre-results-project-title', data.projectName || 'Project Assessment');

    const badge = document.getElementById('pre-results-status-badge');
    if (badge) {
        badge.textContent = status;
        badge.className = 'badge ' + (status.includes('READY FOR') ? 'badge-completed' : (status.includes('READY WITH') ? 'badge-pending' : 'badge-failed'));
    }

    const circle = document.getElementById('pre-overall-circle');
    if (circle) circle.className = 'score-circle ' + (overall >= 85 ? 'ready' : (overall >= 65 ? 'changes' : 'danger'));

    setElText('pre-score-overall', overall);
    setElText('pre-score-security', scores.security ?? 0);
    setElText('pre-score-config', scores.configuration ?? 0);
    setElText('pre-score-deps', scores.dependencies ?? 0);
    setElText('pre-summary-recommendation', scores.recommendation || 'Review findings below.');

    renderFindingsAccordion('pre-findings-list', currentPreFindings);
    setElText('pre-findings-count', currentPreFindings.length);

    if (container) container.scrollIntoView({ behavior: 'smooth' });
}

let currentPreSeverityFilter = 'ALL';
let currentPostSeverityFilter = 'ALL';
let currentPreSearchQuery = '';
let currentPostSearchQuery = '';

function filterFindings(sev) {
    currentPreSeverityFilter = sev;
    const container = document.getElementById('pre-severity-filters');
    if (container) {
        container.querySelectorAll('button').forEach(btn => {
            btn.classList.toggle('active', btn.textContent.trim() === sev);
        });
    }
    applyFindingsFilter('pre');
}

function filterPostFindings(sev) {
    currentPostSeverityFilter = sev;
    const container = document.getElementById('post-severity-filters');
    if (container) {
        container.querySelectorAll('button').forEach(btn => {
            btn.classList.toggle('active', btn.textContent.trim() === sev);
        });
    }
    applyFindingsFilter('post');
}

function filterFindingsBySearch(type) {
    if (type === 'pre') {
        const input = document.getElementById('pre-search-input');
        currentPreSearchQuery = input ? input.value.trim().toLowerCase() : '';
        applyFindingsFilter('pre');
    } else {
        const input = document.getElementById('post-search-input');
        currentPostSearchQuery = input ? input.value.trim().toLowerCase() : '';
        applyFindingsFilter('post');
    }
}

function applyFindingsFilter(type) {
    if (type === 'pre') {
        const list = currentPreFindings.filter(f => {
            const matchesSev = (currentPreSeverityFilter === 'ALL' || (f.severity && f.severity.toUpperCase() === currentPreSeverityFilter));
            const matchesSearch = !currentPreSearchQuery ||
                (f.title && f.title.toLowerCase().includes(currentPreSearchQuery)) ||
                (f.description && f.description.toLowerCase().includes(currentPreSearchQuery)) ||
                (f.affectedFileOrUrl && f.affectedFileOrUrl.toLowerCase().includes(currentPreSearchQuery)) ||
                (f.category && f.category.toLowerCase().includes(currentPreSearchQuery));
            return matchesSev && matchesSearch;
        });
        renderFindingsAccordion('pre-findings-list', list);
        setElText('pre-findings-count', list.length);
    } else {
        const list = currentPostFindings.filter(f => {
            const matchesSev = (currentPostSeverityFilter === 'ALL' || (f.severity && f.severity.toUpperCase() === currentPostSeverityFilter));
            const matchesSearch = !currentPostSearchQuery ||
                (f.title && f.title.toLowerCase().includes(currentPostSearchQuery)) ||
                (f.description && f.description.toLowerCase().includes(currentPostSearchQuery)) ||
                (f.affectedFileOrUrl && f.affectedFileOrUrl.toLowerCase().includes(currentPostSearchQuery)) ||
                (f.category && f.category.toLowerCase().includes(currentPostSearchQuery));
            return matchesSev && matchesSearch;
        });
        renderFindingsAccordion('post-findings-list', list);
        setElText('post-findings-count', list.length);
    }
}

function renderFindingsAccordion(containerId, findings) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div style="padding: 2.25rem 1rem; text-align: center; background: rgba(255,255,255,0.02); border-radius: 12px; border: 1px dashed rgba(255,255,255,0.08); margin-top: 0.5rem;">
                <div style="font-size: 1.5rem; margin-bottom: 0.5rem; color: var(--text-muted)">✓</div>
                <div class="text-sm font-bold" style="color: var(--text-secondary)">No findings match the active criteria</div>
                <div class="text-xs text-muted mt-1">Try switching filters or clearing the search box.</div>
            </div>`;
        return;
    }

    container.innerHTML = findings.map((f, i) => {
        const isSecret = f.evidence && (f.evidence.includes('***') || (f.title && (f.title.toLowerCase().includes('credential') || f.title.toLowerCase().includes('secret'))));
        const sevClass = (f.severity || 'INFO').toLowerCase();
        
        return `
        <div class="finding-item" id="${containerId}-finding-${i}">
            <div class="finding-header" onclick="toggleFinding('${containerId}', ${i})">
                <div class="flex items-center gap-3">
                    <span class="badge badge-${sevClass}">${f.severity}</span>
                    <strong class="text-sm" style="color: #f1f5f9;">${f.title}</strong>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-xs text-secondary font-mono" style="background: rgba(255,255,255,0.04); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid rgba(255,255,255,0.06);">${f.category || 'SECURITY'}</span>
                    <span class="text-secondary text-xs" style="transition: transform 0.2s;" id="${containerId}-arrow-${i}">&#9662;</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="mb-3">
                    <div class="section-label">Risk Description & Impact</div>
                    <div class="text-xs text-secondary" style="line-height: 1.6; white-space: pre-line;">${f.description || f.title}</div>
                </div>
                ${f.evidence ? `
                <div class="mb-3">
                    <div class="section-label">${isSecret ? '🔒 Protected Secret Evidence (Masked)' : 'Evidence & Telemetry'}</div>
                    ${isSecret ? `
                        <div class="secret-mask-box">
                            <span>${f.evidence}</span>
                            <span class="text-xs" style="color: #94a3b8; font-family: sans-serif;">🛡️ Zero-Knowledge Masked</span>
                        </div>
                    ` : `
                        <code class="text-xs" style="display:block; padding: 0.65rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; word-break: break-all; font-family: 'JetBrains Mono', monospace; color: #cbd5e1;">${f.evidence}</code>
                    `}
                </div>` : ''}
                ${f.affectedFileOrUrl ? `
                <div class="mb-3">
                    <div class="section-label">Affected Target Resource</div>
                    <div class="text-xs font-mono" style="color: #93c5fd; background: rgba(59, 130, 246, 0.08); padding: 0.35rem 0.65rem; border-radius: 6px; border: 1px solid rgba(59, 130, 246, 0.2); display: inline-block;">${f.affectedFileOrUrl}</div>
                </div>` : ''}
                <div>
                    <div class="section-label">Remediation Guidance</div>
                    <div class="text-xs" style="color: #38bdf8; background: rgba(6, 182, 212, 0.08); padding: 0.65rem 0.85rem; border-radius: 6px; border-left: 3px solid var(--accent-cyan); line-height: 1.6;">${f.recommendation || 'No specific action required.'}</div>
                </div>
            </div>
        </div>
        `;
    }).join('');
}

function toggleFinding(containerId, index) {
    const item = document.getElementById(`${containerId}-finding-${index}`);
    const arrow = document.getElementById(`${containerId}-arrow-${index}`);
    if (item) {
        const isOpen = item.classList.toggle('open');
        if (arrow) {
            arrow.style.transform = isOpen ? 'rotate(180deg)' : 'rotate(0deg)';
        }
    }
}

async function downloadPreReport() {
    if (!currentPreScanId) return;
    try {
        const csv = await API.getPreDeploymentReport(currentPreScanId);
        triggerCsvDownload(csv, `veloshield-predeployment-${currentPreScanId}.csv`);
    } catch (e) {
        showToast('Failed to download CSV report: ' + e.message, 'error');
    }
}

// ==========================================
// WORKFLOW B: AFTER DEPLOYMENT
// ==========================================

function setupPostDeployForm() {
    const form = document.getElementById('post-deploy-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('post-target-url');
        const url = urlInput ? urlInput.value.trim() : '';

        const btn = document.getElementById('start-post-scan-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Executing Safe Scan...';
        }

        animateChecklist('post', [
            'step-post-ssrf',
            'step-post-https',
            'step-post-headers',
            'step-post-cookies',
            'step-post-cors',
            'step-post-info',
            'step-post-errors',
            'step-post-api',
            'step-post-perf',
            'step-post-third'
        ]);

        try {
            const res = await API.startPostDeploymentScan(url);
            currentPostScanId = res.id;
            currentPostFindings = res.findings || [];

            renderPostScanResults(res);
            showToast('Post-deployment live scan finished cleanly!', 'success');
            loadSectionData('overview');
        } catch (error) {
            showToast(error.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Start Safe Website Scan';
            }
        }
    });
}

function renderPostScanResults(data) {
    const container = document.getElementById('post-results-container');
    if (container) container.style.display = 'block';

    const scores = data.scores || {};
    const overall = scores.overall ?? 0;
    const status = scores.status || 'UNKNOWN';

    setElText('post-results-url-title', data.targetUrl || 'Live Website Health');

    const badge = document.getElementById('post-results-status-badge');
    if (badge) {
        badge.textContent = status;
        badge.className = 'badge ' + (status === 'HEALTHY' ? 'badge-completed' : (status === 'DEGRADED' ? 'badge-pending' : 'badge-failed'));
    }

    const circle = document.getElementById('post-overall-circle');
    if (circle) circle.className = 'score-circle ' + (overall >= 85 ? 'ready' : (overall >= 65 ? 'changes' : 'danger'));

    setElText('post-score-overall', overall);
    setElText('post-score-security', scores.security ?? 0);
    setElText('post-score-perf', scores.performance ?? 0);
    setElText('post-score-api', scores.apiHealth ?? 0);

    const perf = data.performance || {};
    const tp = data.thirdParty || {};
    setElText('post-telemetry-latency', (perf.totalResponseTimeMs || data.metrics?.totalLatencyMs || 0) + ' ms');
    setElText('post-telemetry-size', (perf.pageSizeFormatted || '0 KB'));
    setElText('post-telemetry-resources', (perf.totalResources || 0));

    setElText('post-telemetry-domains', (tp.externalDomainsCount || 0));
    setElText('post-telemetry-analytics', (tp.analyticsCount || 0));
    setElText('post-telemetry-ads', (tp.adCount || 0));

    const jumpBtn = document.getElementById('post-jump-to-load-btn');
    if (jumpBtn) {
        jumpBtn.onclick = () => switchToSection('load-test');
    }

    renderFindingsAccordion('post-findings-list', currentPostFindings);
    setElText('post-findings-count', currentPostFindings.length);

    if (container) container.scrollIntoView({ behavior: 'smooth' });
}

async function downloadPostReport() {
    if (!currentPostScanId) return;
    try {
        const csv = await API.getPostDeploymentReport(currentPostScanId);
        triggerCsvDownload(csv, `veloshield-postdeployment-${currentPostScanId}.csv`);
    } catch (e) {
        showToast('Failed to download CSV: ' + e.message, 'error');
    }
}

function animateChecklist(prefix, stepIds) {
    stepIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.className = 'step-item';
            const icon = el.querySelector('.step-icon');
            if (icon) icon.innerHTML = '&#9675;';
        }
    });

    let current = 0;
    const interval = setInterval(() => {
        if (current > 0 && current - 1 < stepIds.length) {
            const prev = document.getElementById(stepIds[current - 1]);
            if (prev) {
                prev.className = 'step-item done';
                const icon = prev.querySelector('.step-icon');
                if (icon) icon.innerHTML = '&#10003;';
            }
        }
        if (current < stepIds.length) {
            const el = document.getElementById(stepIds[current]);
            if (el) {
                el.className = 'step-item active';
                const icon = el.querySelector('.step-icon');
                if (icon) icon.innerHTML = '&bull;';
            }
            current++;
        } else {
            clearInterval(interval);
        }
    }, 250);
}

// ==========================================
// SECTION 4: RESILIENCE & LOAD TESTING
// ==========================================

function setupTargetAndLoadForms() {
    const addTargetForm = document.getElementById('add-target-form');
    if (addTargetForm) {
        addTargetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('target-url');
            const url = urlInput ? urlInput.value : '';
            const btn = e.target.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Adding...';
            }
            try {
                await API.addTarget(url);
                showToast('Target domain added!', 'success');
                hideModal('add-target-modal');
                if (urlInput) urlInput.value = '';
                loadTargetsAndTests();
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Add Target';
                }
            }
        });
    }

    const testForm = document.getElementById('new-test-form');
    if (testForm) {
        testForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const targetEl = document.getElementById('test-target');
            const concEl = document.getElementById('test-concurrency');
            const durEl = document.getElementById('test-duration');
            const maxEl = document.getElementById('test-max-reqs');

            const targetId = targetEl ? parseInt(targetEl.value) : 0;
            const conc = concEl ? parseInt(concEl.value) : 10;
            const dur = durEl ? parseInt(durEl.value) : 30;
            const max = maxEl ? parseInt(maxEl.value) : 1000;

            if (!targetId) { showToast('Please select a verified target', 'error'); return; }

            const btn = e.target.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Launching...';
            }
            try {
                const test = await API.startTest(targetId, conc, dur, max);
                showToast('Resilience assessment launched!', 'success');
                startLiveMonitor(test.testId || test.id);
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Start Resilience Assessment';
                }
            }
        });
    }

    const stopBtn = document.getElementById('stop-monitor-btn');
    if (stopBtn) {
        stopBtn.addEventListener('click', () => {
            stopLiveMonitor();
            const liveCard = document.getElementById('live-test-card');
            if (liveCard) liveCard.style.display = 'none';
            showToast('Monitoring stopped.', 'success');
        });
    }
}

async function loadTargetsAndTests() {
    try {
        const [targets, tests] = await Promise.all([API.getTargets(), API.getTests()]);

        const select = document.getElementById('test-target');
        if (select) {
            select.innerHTML = '<option value="">-- Select Target URL --</option>';
            targets.forEach(t => {
                select.innerHTML += `<option value="${t.id}">${t.url} ${t.verified ? '(Verified)' : '(Pending Verification)'}</option>`;
            });
        }

        const tbody = document.querySelector('#targets-table tbody');
        if (tbody) {
            tbody.innerHTML = '';
            if (targets.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary">No targets registered yet.</td></tr>';
            } else {
                targets.forEach(t => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${t.url}</strong></td>
                        <td><span class="badge ${t.verified ? 'badge-completed' : 'badge-pending'}">${t.verified ? 'VERIFIED' : 'PENDING'}</span></td>
                        <td>${formatDate(t.createdAt)}</td>
                        <td>
                            <div class="flex gap-2">
                                ${!t.verified ? `<button class="btn btn-secondary" style="padding:0.25rem 0.5rem;font-size:0.75rem;" onclick="verifyDomainTarget(${t.id})">Verify</button>` : ''}
                                <button class="btn btn-secondary" style="padding:0.25rem 0.5rem;font-size:0.75rem;" onclick="deleteDomainTarget(${t.id})">Delete</button>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        }
    } catch (e) {
        console.error('Failed to load targets/tests:', e);
    }
}

async function verifyDomainTarget(id) {
    try {
        const res = await API.verifyTarget(id);
        if (res.verified) {
            showToast('Domain ownership verified successfully!', 'success');
        } else {
            showToast(res.message || 'Verification token not found on target server.', 'error');
        }
        loadTargetsAndTests();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function deleteDomainTarget(id) {
    if (!confirm('Are you sure you want to remove this target?')) return;
    try {
        await API.deleteTarget(id);
        showToast('Target deleted.', 'success');
        loadTargetsAndTests();
    } catch (e) {
        showToast(e.message, 'error');
    }
}

function startLiveMonitor(testId) {
    const liveCard = document.getElementById('live-test-card');
    if (liveCard) liveCard.style.display = 'flex';
    stopLiveMonitor();

    const poll = async () => {
        try {
            const test = await API.getTest(testId);
            setElText('live-attempted', test.attempted ?? 0);
            setElText('live-succeeded', test.succeeded ?? 0);
            setElText('live-failed', test.failed ?? 0);
            setElText('live-latency', (test.avgLatencyMs ?? 0).toFixed(1) + 'ms');

            const badge = document.getElementById('live-status');
            if (badge) {
                badge.className = `badge badge-${test.status.toLowerCase()}`;
                badge.textContent = test.status.toUpperCase();
            }

            const att = test.attempted || 0;
            const fail = test.failed || 0;
            const rate = att > 0 ? (fail / att * 100) : 0;
            setElText('live-error-rate-text', rate.toFixed(1) + '%');
            const bar = document.getElementById('live-error-rate-bar');
            if (bar) bar.style.width = Math.min(rate, 100) + '%';

            if (test.status === 'completed' || test.status === 'failed') {
                stopLiveMonitor();
                showToast(`Resilience test ${test.status}! Error rate: ${rate.toFixed(1)}%`, test.status === 'completed' ? 'success' : 'error');
            }
        } catch (e) {
            console.error('Telemetry error:', e);
        }
    };

    poll();
    liveTestInterval = setInterval(poll, 1500);
}

function stopLiveMonitor() {
    if (liveTestInterval) {
        clearInterval(liveTestInterval);
        liveTestInterval = null;
    }
}

// ==========================================
// SECTION 5: HISTORY & COMPARISON DIFF
// ==========================================

async function loadHistoryList(type = 'ALL') {
    try {
        const queryType = type === 'ALL' ? '' : type;
        const scans = await API.getAssessments(queryType);

        const tbody = document.querySelector('#history-table tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-secondary">No historical scans recorded.</td></tr>';
            return;
        }

        scans.forEach(s => {
            const overall = s.scores?.overall ?? 'N/A';
            const status = s.scores?.status || s.status;
            const isPre = s.assessmentType === 'BEFORE_DEPLOYMENT';
            const typeLabel = isPre ? 'BEFORE DEPLOYMENT' : 'AFTER DEPLOYMENT';
            const typeBadge = isPre ? 'background:rgba(139,92,246,0.15);color:#a78bfa;' : 'background:rgba(6,182,212,0.15);color:#38bdf8;';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>#${s.id}</td>
                <td><span class="badge" style="${typeBadge}">${typeLabel}</span></td>
                <td><strong>${s.targetRef}</strong></td>
                <td><span class="badge ${status.includes('READY') || status === 'HEALTHY' ? 'badge-completed' : 'badge-pending'}">${status}</span></td>
                <td><strong>${overall}</strong> / 100</td>
                <td>${formatDate(s.startedAt)}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.75rem;" onclick="downloadHistReport(${s.id}, '${s.assessmentType}')">CSV</button>
                        <button class="btn btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.75rem;" onclick="deleteHistAssessment(${s.id})">Delete</button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('History load error:', e);
    }
}

function filterHistory(type) {
    document.querySelectorAll('#history-section .flex gap-2 button').forEach(b => b.classList.remove('active'));
    const elAll = document.getElementById('filter-hist-all');
    const elPre = document.getElementById('filter-hist-pre');
    const elPost = document.getElementById('filter-hist-post');

    if (type === 'ALL' && elAll) elAll.classList.add('active');
    if (type === 'BEFORE_DEPLOYMENT' && elPre) elPre.classList.add('active');
    if (type === 'AFTER_DEPLOYMENT' && elPost) elPost.classList.add('active');
    loadHistoryList(type);
}

async function downloadHistReport(id, type) {
    try {
        const csv = type === 'BEFORE_DEPLOYMENT'
            ? await API.getPreDeploymentReport(id)
            : await API.getPostDeploymentReport(id);
        triggerCsvDownload(csv, `veloshield-assessment-${id}.csv`);
    } catch (e) {
        showToast('Download error: ' + e.message, 'error');
    }
}

async function deleteHistAssessment(id) {
    if (!confirm(`Delete assessment record #${id}?`)) return;
    try {
        await API.deleteAssessment(id);
        showToast('Assessment deleted.', 'success');
        loadHistoryList('ALL');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function openDiffModal() {
    try {
        const scans = await API.getAssessments();
        if (scans.length < 2) {
            showToast('You need at least 2 scans to run a comparative diff.', 'error');
            return;
        }

        const curSelect = document.getElementById('diff-current-select');
        const prevSelect = document.getElementById('diff-prev-select');
        if (!curSelect || !prevSelect) return;

        curSelect.innerHTML = '';
        prevSelect.innerHTML = '';

        scans.forEach((s) => {
            const opt = `<option value="${s.id}">#${s.id} - ${s.targetRef} (${s.assessmentType}) - Score: ${s.scores?.overall ?? 'N/A'}</option>`;
            curSelect.innerHTML += opt;
            prevSelect.innerHTML += opt;
        });

        if (scans.length > 1) {
            prevSelect.selectedIndex = 1;
        }

        showModal('diff-modal');
    } catch (e) {
        showToast('Failed to load scan list: ' + e.message, 'error');
    }
}

async function executeDiffComparison() {
    const curSelect = document.getElementById('diff-current-select');
    const prevSelect = document.getElementById('diff-prev-select');
    if (!curSelect || !prevSelect) return;

    const curId = curSelect.value;
    const prevId = prevSelect.value;

    if (curId === prevId) {
        showToast('Please select two distinct scans to compare.', 'error');
        return;
    }

    try {
        const diff = await API.getAssessmentDiff(curId, prevId);
        const resDiv = document.getElementById('diff-results');
        if (resDiv) resDiv.style.display = 'block';

        const change = diff.scoreChange || 0;
        const changeEl = document.getElementById('diff-score-change');
        if (changeEl) {
            changeEl.textContent = (change >= 0 ? '+' : '') + change + ' pts';
            changeEl.style.color = change >= 0 ? 'var(--status-completed)' : 'var(--status-failed)';
        }

        setElText('diff-new-count', diff.newFindings?.length || 0);
        setElText('diff-resolved-count', diff.resolvedFindings?.length || 0);

        const container = document.getElementById('diff-findings-breakdown');
        if (!container) return;

        let html = '';

        if (diff.newFindings && diff.newFindings.length > 0) {
            html += `<h5 style="color:var(--status-failed); margin-top:1rem;">New Findings Detected (${diff.newFindings.length})</h5>`;
            html += diff.newFindings.map(f => `<div class="text-xs text-secondary mt-1">&bull; <strong style="color:var(--text-primary)">[${f.severity}]</strong> ${f.title} (${f.category})</div>`).join('');
        }

        if (diff.resolvedFindings && diff.resolvedFindings.length > 0) {
            html += `<h5 style="color:var(--status-completed); margin-top:1rem;">Resolved Baseline Findings (${diff.resolvedFindings.length})</h5>`;
            html += diff.resolvedFindings.map(f => `<div class="text-xs text-secondary mt-1">&bull; <strong style="color:var(--text-primary)">[${f.severity}]</strong> ${f.title} (${f.category})</div>`).join('');
        }

        if (diff.recurringFindings && diff.recurringFindings.length > 0) {
            html += `<h5 style="color:var(--text-secondary); margin-top:1rem;">Recurring Findings (${diff.recurringFindings.length})</h5>`;
            html += diff.recurringFindings.map(f => `<div class="text-xs text-secondary mt-1">&bull; [${f.severity}] ${f.title}</div>`).join('');
        }

        container.innerHTML = html;

    } catch (e) {
        showToast('Failed to generate diff: ' + e.message, 'error');
    }
}

// Helpers
function renderRecentAssessments(assessments) {
    const tbody = document.querySelector('#recent-assessments-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (assessments.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary">No assessments performed yet. Choose a workflow above to start!</td></tr>';
        return;
    }

    assessments.slice(0, 6).forEach(s => {
        const isPre = s.assessmentType === 'BEFORE_DEPLOYMENT';
        const typeLabel = isPre ? 'BEFORE DEPLOYMENT' : 'AFTER DEPLOYMENT';
        const overall = s.scores?.overall ?? 'N/A';
        const status = s.scores?.status || s.status;

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="badge" style="font-size:0.7rem; ${isPre ? 'background:rgba(139,92,246,0.15);color:#a78bfa;' : 'background:rgba(6,182,212,0.15);color:#38bdf8;'}">${typeLabel}</span></td>
            <td><strong>${s.targetRef}</strong></td>
            <td>${overall} / 100</td>
            <td><span class="badge ${status.includes('READY') || status === 'HEALTHY' ? 'badge-completed' : 'badge-pending'}">${status}</span></td>
            <td>${formatDate(s.startedAt)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function triggerCsvDownload(csvContent, filename) {
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
    showToast('CSV report downloaded.', 'success');
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
        return dateStr;
    }
}

function showModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
}

function hideModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active');
}

document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('active');
    }
});

function showToast(msg, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${msg}</span>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;cursor:pointer;font-size:1.1rem;line-height:1;">&times;</button>
    `;
    container.appendChild(toast);
    setTimeout(() => { if (toast.parentElement) toast.remove(); }, 5000);
}
