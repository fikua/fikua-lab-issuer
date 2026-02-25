// S0: Theme toggle
(() => {
    const toggle = document.getElementById('theme-toggle');
    const html = document.documentElement;
    const saved = localStorage.getItem('fikua-theme');
    if (saved) {
        html.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        html.setAttribute('data-theme', 'dark');
    }
    toggle.addEventListener('click', () => {
        const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('fikua-theme', next);
    });
})();

// S1-S8: Main application
(() => {
    const WALLET_URL = 'https://wallet.lab.fikua.com';

    // S1: Helpers
    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    async function api(method, path, body) {
        const opts = { method, headers: {} };
        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(path, opts);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error_description || err.error || `HTTP ${res.status}`);
        }
        return res.json();
    }

    function formatDate(iso) {
        if (!iso) return '-';
        try {
            const d = new Date(iso);
            return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                + ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        } catch { return iso; }
    }

    function shortId(id) {
        return id ? id.substring(0, 8) : '-';
    }

    function formatConfigId(id) {
        if (!id) return '-';
        if (id.includes('pid.mdoc')) return 'PID mdoc';
        if (id.includes('pid')) return 'PID sd-jwt';
        if (id.includes('student-id')) return 'Student ID';
        return id;
    }

    // Backend-managed claims that the form should not show
    const HIDDEN_CLAIMS = new Set(['issuing_authority', 'issuing_country']);

    // Default test data per credential type (keyed by config ID prefix)
    const DEFAULT_DATA = {
        'eu.europa.ec.eudi.pid': {
            given_name: 'Max',
            family_name: 'Mustermann',
            birth_date: '1990-06-15',
        },
        'student-id': {
            identifier: 'STU-2025-001',
            familyName: 'Mustermann',
            firstName: 'Max',
            displayName: 'Max Mustermann',
            commonName: 'M. Mustermann',
            dateOfBirth: '2000-03-20',
            mail: 'max.mustermann@university.edu',
            schacPersonalUniqueCode: 'urn:schac:personalUniqueCode:int:esi:university.edu:12345',
            schacPersonalUniqueID: 'urn:schac:personalUniqueID:int:esi:university.edu:12345',
            schacHomeOrganization: 'university.edu',
            eduPersonPrincipalName: 'max@university.edu',
            eduPersonPrimaryAffiliation: 'student',
            eduPersonAffiliation: 'student;member',
            eduPersonScopedAffiliation: 'student@university.edu',
            eduPersonAssurance: 'https://refeds.org/assurance/IAP/medium',
        },
    };

    function getDefaults(configId) {
        for (const prefix of Object.keys(DEFAULT_DATA)) {
            if (configId.startsWith(prefix)) return DEFAULT_DATA[prefix];
        }
        return null;
    }

    // S2: Tab switching
    const tabs = document.querySelectorAll('.tab');
    const tabIssue = document.getElementById('tab-issue');
    const tabRecords = document.getElementById('tab-records');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const target = tab.dataset.tab;
            tabIssue.classList.toggle('hidden', target !== 'issue');
            tabRecords.classList.toggle('hidden', target !== 'records');
            if (target === 'records') loadRecords();
        });
    });

    // S3: Credential selector
    let credConfigs = {};
    let selectedConfigId = null;

    async function loadCredentialConfigs() {
        try {
            const meta = await api('GET', '/.well-known/openid-credential-issuer');
            credConfigs = meta.credential_configurations_supported || {};
            renderConfigGrid();
        } catch (err) {
            document.getElementById('config-grid').innerHTML =
                `<div class="empty-state">Failed to load configurations: ${esc(err.message)}</div>`;
        }
    }

    function renderConfigGrid() {
        const grid = document.getElementById('config-grid');
        const entries = Object.entries(credConfigs);
        if (entries.length === 0) {
            grid.innerHTML = '<div class="empty-state">No credential configurations available</div>';
            return;
        }

        grid.innerHTML = entries.map(([id, config]) => {
            const display = config.credential_metadata?.display?.[0] || {};
            const name = display.name || id;
            const desc = display.description || '';
            const format = config.format === 'mso_mdoc' ? 'mdoc' : 'sd-jwt';
            return `
                <div class="config-card" data-config-id="${esc(id)}">
                    <div class="config-card-header">
                        <span class="config-card-name">${esc(name)}</span>
                        <span class="badge badge-format">${esc(format)}</span>
                    </div>
                    ${desc ? `<span class="config-card-desc">${esc(desc)}</span>` : ''}
                    <span class="config-card-id">${esc(id)}</span>
                </div>`;
        }).join('');

        grid.querySelectorAll('.config-card').forEach(card => {
            card.addEventListener('click', () => selectConfig(card.dataset.configId));
        });
    }

    function selectConfig(configId) {
        selectedConfigId = configId;
        const config = credConfigs[configId];
        if (!config) return;

        const display = config.credential_metadata?.display?.[0] || {};
        document.getElementById('form-title').textContent = display.name || configId;
        document.getElementById('form-sub').textContent = display.description || configId;

        // Build form fields from claims
        const claims = config.credential_metadata?.claims || [];
        const fieldsEl = document.getElementById('form-fields');
        fieldsEl.innerHTML = '';

        claims.forEach(claim => {
            const path = claim.path?.[0];
            if (!path || HIDDEN_CLAIMS.has(path)) return;
            const claimDisplay = claim.display?.[0] || {};
            const label = claimDisplay.name || path;
            const isDate = path.includes('date') || path.includes('expiry');
            const inputType = isDate ? 'date' : 'text';

            fieldsEl.innerHTML += `
                <div class="form-group">
                    <label for="field-${esc(path)}">${esc(label)}</label>
                    <input type="${inputType}" id="field-${esc(path)}" name="${esc(path)}" required>
                </div>`;
        });

        // Add "Fill defaults" button if defaults exist for this config
        const defaults = getDefaults(configId);
        if (defaults) {
            const btnWrap = document.createElement('div');
            btnWrap.className = 'form-defaults-wrap';
            btnWrap.innerHTML = `<button type="button" id="btn-fill-defaults" class="btn btn-sm">Fill test data</button>`;
            fieldsEl.prepend(btnWrap);
            document.getElementById('btn-fill-defaults').addEventListener('click', () => {
                for (const [key, value] of Object.entries(defaults)) {
                    const input = document.getElementById('field-' + key);
                    if (input) input.value = value;
                }
            });
        }

        // Show delivery method selector when credential has an email claim
        const deliveryEl = document.getElementById('delivery-method');
        const hasEmailClaim = claims.some(c => c.path?.[0] === 'mail');
        deliveryEl.classList.toggle('hidden', !hasEmailClaim);
        if (!hasEmailClaim) {
            document.getElementById('delivery-screen').checked = true;
        }

        showStep('form');
    }

    // S4: Form steps
    const stepSelect = document.getElementById('step-select');
    const stepForm = document.getElementById('step-form');
    const stepResult = document.getElementById('step-result');

    function showStep(step) {
        stepSelect.classList.toggle('hidden', step !== 'select');
        stepForm.classList.toggle('hidden', step !== 'form');
        stepResult.classList.toggle('hidden', step !== 'result');
    }

    document.getElementById('btn-back-select').addEventListener('click', () => showStep('select'));
    document.getElementById('btn-issue-another').addEventListener('click', () => {
        showStep('select');
        selectedConfigId = null;
    });

    // S5: Issuance
    document.getElementById('issuance-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Issuing...';

        try {
            const formData = new FormData(form);
            const credentialData = {};
            for (const [key, value] of formData.entries()) {
                if (key !== 'tx_code_required') credentialData[key] = value;
            }

            const txCodeRequired = document.getElementById('chk-tx-code').checked;
            const deliveryMethod = document.querySelector('input[name="delivery_method"]:checked')?.value || 'screen';

            const result = await api('POST', '/oid4vci/v1/issuance', {
                credential_type: selectedConfigId,
                credential_data: credentialData,
                source_type: 'admin_portal',
                source_ref: 'Manual issuance from issuer UI',
                tx_code_required: txCodeRequired,
                delivery_method: deliveryMethod,
            });

            renderResult(result);
            showStep('result');
        } catch (err) {
            alert('Issuance failed: ' + err.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Issue Credential`;
        }
    });

    function renderResult(data) {
        const content = document.getElementById('result-content');
        let html = '';
        const emailDelivery = !!data.email_sent_to;

        // Email delivery: show confirmation only, no QR/deep link/tx_code on screen
        if (emailDelivery) {
            html += `
                <div class="result-draft">
                    <div class="result-draft-icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 2L11 13"/><path d="M22 2L15 22 11 13 2 9l20-7z"/>
                        </svg>
                    </div>
                    <div class="result-draft-title">Invitation Sent</div>
                    <div class="result-draft-desc">A credential invitation email has been sent to:</div>
                    <div class="result-draft-email">${esc(data.email_sent_to)}</div>
                    ${data.tx_code ? '<div class="result-draft-desc" style="margin-top:0.75rem;">A verification code will be sent when the wallet claims the credential.</div>' : ''}
                </div>`;
            content.innerHTML = html;
            return;
        }

        // Screen delivery: show QR + deep link + tx_code
        const offerUri = data.credential_offer_uri;
        const offer = data.credential_offer;
        const txCode = data.tx_code;

        if (txCode) {
            html += `<div class="result-tx-code"><span class="result-tx-label">TX Code</span> ${esc(txCode)}</div>`;
        }

        let qrContent = '';
        if (offerUri) {
            const walletLink = `${WALLET_URL}/?credential_offer_uri=${encodeURIComponent(offerUri)}`;
            qrContent = walletLink;
            html += `<div class="result-qr"><canvas id="qr-canvas"></canvas></div>`;
            html += `<div class="result-uri" title="Click to copy" id="offer-uri">${esc(walletLink)}</div>`;
            html += `<div class="result-deeplink"><a href="${esc(walletLink)}" class="btn btn-accent" target="_blank">Open in Wallet</a></div>`;
        } else if (offer) {
            const offerJson = JSON.stringify(offer, null, 2);
            const walletLink = `${WALLET_URL}/?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
            qrContent = walletLink;
            html += `<div class="result-qr"><canvas id="qr-canvas"></canvas></div>`;
            html += `<pre class="result-uri" style="text-align:left;white-space:pre-wrap">${esc(offerJson)}</pre>`;
            html += `<div class="result-deeplink"><a href="${esc(walletLink)}" class="btn btn-accent" target="_blank">Open in Wallet</a></div>`;
        }

        content.innerHTML = html;

        // Generate QR code with the full deeplink URI
        if (qrContent) {
            const canvas = document.getElementById('qr-canvas');
            if (canvas) generateQR(canvas, qrContent);

            // Copy URI on click
            const uriEl = document.getElementById('offer-uri');
            if (uriEl) {
                uriEl.addEventListener('click', () => {
                    navigator.clipboard.writeText(offerUri).then(() => {
                        uriEl.style.borderColor = 'var(--success)';
                        setTimeout(() => uriEl.style.borderColor = '', 1500);
                    });
                });
            }
        }
    }

    // S6: Records table
    let recordsState = { page: 1, size: 20, sort: 'created_at', order: 'desc' };

    async function loadRecords() {
        const { page, size, sort, order } = recordsState;
        const body = document.getElementById('records-body');
        body.innerHTML = '<tr><td colspan="5" class="empty-state">Loading...</td></tr>';

        try {
            const data = await api('GET', `/oid4vci/v1/issuance?page=${page}&size=${size}&sort=${sort}&order=${order}`);
            renderRecords(data);
        } catch (err) {
            body.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${esc(err.message)}</td></tr>`;
        }
    }

    function renderRecords(data) {
        const records = data.records || [];
        const total = data.total || 0;
        const body = document.getElementById('records-body');

        if (records.length === 0) {
            body.innerHTML = '<tr><td colspan="5" class="empty-state">No issuance records</td></tr>';
        } else {
            body.innerHTML = records.map(r => `
                <tr data-record='${esc(JSON.stringify(r))}'>
                    <td class="cell-id">${esc(shortId(r.id))}</td>
                    <td>${esc(r.subject_name || '-')}</td>
                    <td class="cell-type"><span class="badge badge-format">${esc(formatConfigId(r.credential_type))}</span></td>
                    <td><span class="badge badge-${esc(r.status || 'pending')}">${esc(r.status || 'pending')}</span></td>
                    <td>${esc(formatDate(r.created_at))}</td>
                </tr>`).join('');

            body.querySelectorAll('tr').forEach(row => {
                row.addEventListener('click', () => {
                    try {
                        const record = JSON.parse(row.dataset.record);
                        showRecordDetail(record);
                    } catch {}
                });
            });
        }

        // Pagination
        const totalPages = Math.ceil(total / recordsState.size) || 1;
        document.getElementById('page-info').textContent = `Page ${recordsState.page} of ${totalPages}`;
        document.getElementById('btn-prev').disabled = recordsState.page <= 1;
        document.getElementById('btn-next').disabled = recordsState.page >= totalPages;
    }

    document.getElementById('btn-prev').addEventListener('click', () => {
        if (recordsState.page > 1) { recordsState.page--; loadRecords(); }
    });
    document.getElementById('btn-next').addEventListener('click', () => {
        recordsState.page++;
        loadRecords();
    });

    // Sorting
    document.querySelectorAll('.table th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const field = th.dataset.sort;
            if (recordsState.sort === field) {
                recordsState.order = recordsState.order === 'desc' ? 'asc' : 'desc';
            } else {
                recordsState.sort = field;
                recordsState.order = 'desc';
            }
            recordsState.page = 1;

            // Update active sort visual
            document.querySelectorAll('.table th.sortable').forEach(h => {
                h.classList.remove('active-sort');
                const arrow = h.querySelector('.sort-arrow');
                if (arrow) arrow.remove();
            });
            th.classList.add('active-sort');
            const arrow = document.createElement('span');
            arrow.className = 'sort-arrow';
            arrow.innerHTML = recordsState.order === 'desc' ? '&#9660;' : '&#9650;';
            th.appendChild(arrow);

            loadRecords();
        });
    });

    // S7: Record detail
    const dialog = document.getElementById('record-dialog');
    document.getElementById('btn-close-dialog').addEventListener('click', () => dialog.close());
    dialog.addEventListener('click', (e) => {
        if (e.target === dialog) dialog.close();
    });

    function showRecordDetail(record) {
        const content = document.getElementById('dialog-content');

        let html = '';
        html += dialogRow('ID', record.id);
        html += dialogRow('Type', record.credential_type);
        html += dialogRowHtml('Status', `<span class="badge badge-${esc(record.status)}">${esc(record.status)}</span>`);
        html += dialogRow('Subject', record.subject_name || '-');
        if (record.recipient_email) html += dialogRow('Recipient Email', record.recipient_email);
        html += dialogRow('Source Type', record.source_type || '-');
        html += dialogRow('Source Ref', record.source_ref || '-');
        html += dialogRow('Created', formatDate(record.created_at));
        html += dialogRow('Updated', formatDate(record.updated_at));
        if (record.pre_auth_code) html += dialogRow('Pre-Auth Code', record.pre_auth_code);
        if (record.offer_id) html += dialogRow('Offer ID', record.offer_id);

        // Credential data
        if (record.credential_data) {
            let data;
            try { data = typeof record.credential_data === 'string' ? JSON.parse(record.credential_data) : record.credential_data; } catch { data = null; }
            if (data && typeof data === 'object') {
                html += '<div class="dialog-section">Credential Data</div>';
                for (const [key, value] of Object.entries(data)) {
                    html += dialogRow(key, String(value));
                }
            }
        }

        content.innerHTML = html;
        dialog.showModal();
    }

    function dialogRow(label, value) {
        return `<div class="dialog-row"><span class="dialog-label">${esc(label)}</span><span class="dialog-value">${esc(value)}</span></div>`;
    }

    function dialogRowHtml(label, html) {
        return `<div class="dialog-row"><span class="dialog-label">${esc(label)}</span><span class="dialog-value">${html}</span></div>`;
    }

    // S8: QR Code generator
    function generateQR(canvas, text) {
        if (window.qrcode) {
            renderQR(canvas, text);
            return;
        }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';
        script.onload = () => renderQR(canvas, text);
        script.onerror = () => {
            const ctx = canvas.getContext('2d');
            canvas.width = 200;
            canvas.height = 200;
            ctx.fillStyle = '#f1f5f9';
            ctx.fillRect(0, 0, 200, 200);
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('QR unavailable', 100, 105);
        };
        document.head.appendChild(script);
    }

    function renderQR(canvas, text) {
        try {
            const qr = qrcode(0, 'M');
            qr.addData(text);
            qr.make();
            const modules = qr.getModuleCount();
            const cellSize = Math.max(4, Math.floor(240 / modules));
            const size = modules * cellSize;
            canvas.width = size;
            canvas.height = size;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, size, size);
            ctx.fillStyle = '#000000';
            for (let row = 0; row < modules; row++) {
                for (let col = 0; col < modules; col++) {
                    if (qr.isDark(row, col)) {
                        ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
                    }
                }
            }
        } catch {
            canvas.width = 200;
            canvas.height = 200;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#f1f5f9';
            ctx.fillRect(0, 0, 200, 200);
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('QR generation failed', 100, 105);
        }
    }

    // S9: Init
    loadCredentialConfigs();
})();
