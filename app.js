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
    }

    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    checkCallback();
})();
