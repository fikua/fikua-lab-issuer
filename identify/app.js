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

// Identification flow
(() => {
    const CERT_LAB_URL = 'https://cert.fikua.com';
    // Page lives at https://lab.fikua.com/issuer/identify/; backend prefixes
// (e.g. /oid4vci/v1/...) hang off the issuer role, so we build the API
// base by going one level up and prepending the OID4VCI prefix.
const ISSUER_API = '/issuer/oid4vci/v1';

    // Fields auto-filled by the backend (not shown in forms)
    const BACKEND_FIELDS = ['issuing_authority', 'issuing_country'];

    const params = new URLSearchParams(window.location.search);
    const sessionToken = params.get('session');

    const phases = {
        identify: document.getElementById('phase-identify'),
        loading: document.getElementById('phase-loading'),
        form: document.getElementById('phase-form'),
        confirm: document.getElementById('phase-confirm'),
        submitting: document.getElementById('phase-submitting'),
        success: document.getElementById('phase-success'),
        error: document.getElementById('phase-error')
    };

    let certData = null;
    let claimsMetadata = null;

    function showPhase(name) {
        Object.entries(phases).forEach(function(entry) {
            entry[1].classList.toggle('hidden', entry[0] !== name);
        });
    }

    function showError(message) {
        document.getElementById('error-message').textContent = message;
        showPhase('error');
    }

    // Render dynamic form fields from claims metadata
    function renderFormFields(container, claims, prefill) {
        container.innerHTML = '';
        if (!claims) return;
        claims.forEach(function(claim) {
            var fieldName = claim.path[0];
            if (BACKEND_FIELDS.indexOf(fieldName) !== -1) return;

            var label = (claim.display && claim.display[0]) ? claim.display[0].name : fieldName;
            var inputType = fieldName === 'birth_date' ? 'date' : 'text';
            var prefillValue = (prefill && prefill[fieldName]) ? prefill[fieldName] : '';

            var group = document.createElement('div');
            group.className = 'form-group';

            var labelEl = document.createElement('label');
            labelEl.className = 'form-label';
            labelEl.setAttribute('for', 'field-' + fieldName);
            labelEl.textContent = label;

            var input = document.createElement('input');
            input.className = 'form-input';
            input.type = inputType;
            input.id = 'field-' + fieldName;
            input.name = fieldName;
            input.required = true;
            input.value = prefillValue;
            if (prefillValue) {
                input.readOnly = true;
                input.classList.add('form-input--prefilled');
            }

            group.appendChild(labelEl);
            group.appendChild(input);
            container.appendChild(group);
        });
    }

    // Collect form data from a container
    function collectFormData(container) {
        var data = {};
        var fields = container.querySelectorAll('input');
        fields.forEach(function(input) {
            data[input.name] = input.value;
        });
        return data;
    }

    // Validate all required fields are filled
    function validateForm(container) {
        var allFilled = true;
        container.querySelectorAll('input[required]').forEach(function(input) {
            if (!input.value.trim()) {
                input.classList.add('form-input--error');
                allFilled = false;
            } else {
                input.classList.remove('form-input--error');
            }
        });
        return allFilled;
    }

    // Submit identification data to issuer
    function submitIdentification(credentialData, sourceType, sourceRef) {
        showPhase('submitting');
        var body = {
            session: sessionToken,
            credential_data: credentialData,
            source_type: sourceType,
            source_ref: sourceRef
        };

        fetch(ISSUER_API + '/identify/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(res) {
            if (!res.ok) return res.json().then(function(err) { throw new Error(err.error_description || err.error || 'Server error'); });
            return res.json();
        })
        .then(function(data) {
            if (data.redirect) {
                showPhase('success');
                setTimeout(function() { window.location.href = data.redirect; }, 1500);
            } else {
                showError('No redirect URL received from the issuer.');
            }
        })
        .catch(function(err) {
            showError('Identification failed: ' + err.message);
        });
    }

    // --- Initialization ---

    if (!sessionToken) {
        showError('Missing session parameter. This page must be accessed from the issuer authorization flow.');
        return;
    }

    // Fetch claims metadata from backend
    fetch(ISSUER_API + '/identify/claims?session=' + encodeURIComponent(sessionToken))
        .then(function(res) {
            if (!res.ok) throw new Error('Failed to fetch claims');
            return res.json();
        })
        .then(function(data) {
            claimsMetadata = data.claims || [];
        })
        .catch(function(err) {
            console.warn('Could not fetch claims metadata, using fallback', err);
            claimsMetadata = [
                { path: ['given_name'], display: [{ name: 'Given Name', locale: 'en' }] },
                { path: ['family_name'], display: [{ name: 'Surname', locale: 'en' }] },
                { path: ['birth_date'], display: [{ name: 'Date of Birth', locale: 'en' }] }
            ];
        })
        .then(function() {
            // After claims loaded: check if returning from cert.lab
            var certParam = params.get('cert');
            if (certParam) {
                try {
                    certData = JSON.parse(atob(certParam));
                    var nameParts = (certData.subject || '').split(' ');
                    var givenName = nameParts[0] || certData.subject || '';
                    var familyName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

                    document.getElementById('cert-summary-issuer').textContent = certData.issuer || '-';
                    document.getElementById('cert-summary-serial').textContent = certData.serial || '-';

                    renderFormFields(document.getElementById('confirm-form-fields'), claimsMetadata, {
                        given_name: givenName,
                        family_name: familyName
                    });
                    showPhase('confirm');
                } catch (e) {
                    showError('Failed to parse certificate data. Please try again.');
                }
            }
        });

    // --- Method: Digital Certificate ---
    document.getElementById('method-cert').addEventListener('click', function() {
        showPhase('loading');
        var returnUrl = window.location.origin + window.location.pathname + '?session=' + encodeURIComponent(sessionToken);
        setTimeout(function() {
            window.location.href = CERT_LAB_URL + '?return_url=' + encodeURIComponent(returnUrl);
        }, 500);
    });

    // --- Method: Manual Form ---
    document.getElementById('method-form').addEventListener('click', function() {
        if (!claimsMetadata) return;
        renderFormFields(document.getElementById('form-fields'), claimsMetadata, null);
        showPhase('form');
    });

    // Form submit
    document.getElementById('btn-form-submit').addEventListener('click', function() {
        var container = document.getElementById('form-fields');
        if (!validateForm(container)) return;
        var credentialData = collectFormData(container);
        submitIdentification(credentialData, 'manual_form', 'User manual input');
    });

    // Form cancel
    document.getElementById('btn-form-cancel').addEventListener('click', function() {
        showPhase('identify');
    });

    // --- Certificate confirm ---
    document.getElementById('btn-confirm').addEventListener('click', function() {
        if (!sessionToken) return;
        var container = document.getElementById('confirm-form-fields');
        if (!validateForm(container)) return;
        var credentialData = collectFormData(container);
        submitIdentification(credentialData, 'x509_cert',
            certData.subject + ' (serial: ' + certData.serial + ')');
    });

    // Cancel button — go back to identify phase
    document.getElementById('btn-cancel').addEventListener('click', function() {
        certData = null;
        var cleanUrl = window.location.origin + window.location.pathname + '?session=' + encodeURIComponent(sessionToken);
        window.history.replaceState({}, '', cleanUrl);
        showPhase('identify');
    });

    // Retry button
    document.getElementById('btn-retry').addEventListener('click', function() {
        if (sessionToken) {
            certData = null;
            var cleanUrl = window.location.origin + window.location.pathname + '?session=' + encodeURIComponent(sessionToken);
            window.history.replaceState({}, '', cleanUrl);
            showPhase('identify');
        }
    });
})();
