// Theme toggle
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

(() => {
    const CERT_URL = '/cert';

    const phases = {
        identify: document.getElementById('phase-identify'),
        loading: document.getElementById('phase-loading'),
        success: document.getElementById('phase-success')
    };

    const offersSection = document.getElementById('offers');
    const issuedSection = document.getElementById('issued');

    function showPhase(name) {
        Object.entries(phases).forEach(([key, el]) => {
            el.classList.toggle('hidden', key !== name);
        });
    }

    // Certificate identification
    document.getElementById('btn-identify').addEventListener('click', () => {
        // Redirect to cert.lab for certificate selection
        const returnUrl = encodeURIComponent(window.location.origin);
        window.location.href = `https://cert.lab.fikua.com?return_url=${returnUrl}`;
    });

    // Check for callback with certificate data
    function checkCallback() {
        const params = new URLSearchParams(window.location.search);
        const certData = params.get('cert');

        if (certData) {
            showPhase('loading');

            setTimeout(() => {
                try {
                    const cert = JSON.parse(atob(certData));
                    showCertSuccess(cert);
                } catch {
                    showCertSuccess({
                        subject: params.get('subject') || 'Unknown',
                        issuer: params.get('issuer') || 'Unknown',
                        serial: params.get('serial') || 'N/A'
                    });
                }
            }, 1200);

            // Clean URL
            window.history.replaceState({}, '', window.location.pathname);
        }
    }

    function showCertSuccess(cert) {
        showPhase('success');
        offersSection.classList.remove('hidden');
        issuedSection.classList.remove('hidden');

        const certInfo = document.getElementById('cert-info');
        certInfo.innerHTML = `
            <div class="cert-row">
                <span class="cert-label">Subject</span>
                <span>${esc(cert.subject || cert.cn || 'N/A')}</span>
            </div>
            <div class="cert-row">
                <span class="cert-label">Issuer</span>
                <span>${esc(cert.issuer || 'N/A')}</span>
            </div>
            <div class="cert-row">
                <span class="cert-label">Serial</span>
                <span>${esc(cert.serial || 'N/A')}</span>
            </div>
        `;

        triggerIssuance(cert);
    }

    async function triggerIssuance(cert) {
        const offersList = document.getElementById('offers-list');
        offersList.innerHTML = '<span class="empty-state">Creating credential offer...</span>';

        // Build credential_data from certificate claims
        const credentialData = {};
        const givenName = cert.givenName || cert.given_name;
        const familyName = cert.surname || cert.family_name;
        const birthDate = cert.birth_date || cert.birthDate;
        if (givenName) credentialData.given_name = givenName;
        if (familyName) credentialData.family_name = familyName;
        if (birthDate) credentialData.birth_date = birthDate;

        try {
            const res = await fetch('/oid4vci/v1/issuance', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    credential_type: 'eu.europa.ec.eudi.pid.1',
                    credential_data: credentialData,
                    source_type: 'x509_cert',
                    source_ref: cert.subject || cert.serial || ''
                })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();

            if (data.credential_offer_uri) {
                const deepLink = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(data.credential_offer_uri)}`;
                offersList.innerHTML = `
                    <div class="cert-info">
                        <div class="cert-row">
                            <span class="cert-label">Type</span>
                            <span>PID (SD-JWT VC)</span>
                        </div>
                        <div class="cert-row">
                            <span class="cert-label">Offer URI</span>
                            <span style="word-break:break-all; font-family:var(--font-mono); font-size:0.8rem">${esc(data.credential_offer_uri)}</span>
                        </div>
                        <a href="${esc(deepLink)}" class="btn btn-accent" style="margin-top:1rem; display:inline-block">Open in Wallet</a>
                    </div>`;
            } else if (data.credential_offer) {
                const offerJson = JSON.stringify(data.credential_offer, null, 2);
                const deepLink = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(data.credential_offer))}`;
                offersList.innerHTML = `
                    <div class="cert-info">
                        <div class="cert-row">
                            <span class="cert-label">Type</span>
                            <span>PID (SD-JWT VC)</span>
                        </div>
                        <pre style="margin:0.5rem 0; font-size:0.8rem; overflow-x:auto">${esc(offerJson)}</pre>
                        <a href="${esc(deepLink)}" class="btn btn-accent" style="margin-top:1rem; display:inline-block">Open in Wallet</a>
                    </div>`;
            }
        } catch (err) {
            offersList.innerHTML = `<span class="empty-state">Error: ${esc(err.message)}</span>`;
        }
    }

    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    checkCallback();
})();
