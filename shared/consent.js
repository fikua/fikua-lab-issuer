/* Fikua Lab — Cookie Consent + GA4 with EU Consent Mode v2 */
(() => {
    'use strict';

    var GA_ID = 'G-B68EV9PR3X';
    var COOKIE_NAME = 'fikua_consent';
    var COOKIE_DOMAIN = '.lab.fikua.com';
    var COOKIE_MAX_AGE = 31536000; // 1 year

    // --- 1. Read existing consent from cookie ---
    function getConsent() {
        var match = document.cookie.match(new RegExp('(?:^|; )' + COOKIE_NAME + '=([^;]*)'));
        return match ? match[1] : null;
    }

    function setConsent(value) {
        var isLocalhost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
        var parts = [
            COOKIE_NAME + '=' + value,
            'path=/',
            'max-age=' + COOKIE_MAX_AGE,
            'SameSite=Lax'
        ];
        if (!isLocalhost) {
            parts.push('domain=' + COOKIE_DOMAIN);
            parts.push('Secure');
        }
        document.cookie = parts.join('; ');
    }

    // --- 2. Set Consent Mode v2 defaults BEFORE gtag loads ---
    window.dataLayer = window.dataLayer || [];
    function gtag() { window.dataLayer.push(arguments); }

    gtag('consent', 'default', {
        analytics_storage: 'denied',
        ad_storage: 'denied',
        ad_user_data: 'denied',
        ad_personalization: 'denied',
        wait_for_update: 500
    });

    var existing = getConsent();
    if (existing === 'accepted') {
        gtag('consent', 'update', {
            analytics_storage: 'granted'
        });
    }

    // --- 3. Load gtag.js asynchronously ---
    var script = document.createElement('script');
    script.async = true;
    script.src = 'https://www.googletagmanager.com/gtag/js?id=' + GA_ID;
    document.head.appendChild(script);

    gtag('js', new Date());
    gtag('config', GA_ID, {
        cookie_domain: 'lab.fikua.com',
        cookie_flags: 'SameSite=Lax;Secure'
    });

    // --- 4. Consent banner (only if no prior decision) ---
    if (existing !== null) return;

    function injectBanner() {
        var banner = document.createElement('div');
        banner.id = 'fikua-consent';
        banner.setAttribute('role', 'dialog');
        banner.setAttribute('aria-label', 'Cookie consent');
        banner.innerHTML =
            '<div class="consent-inner">' +
            '  <p class="consent-text">' +
            '    We use analytics cookies (Google Analytics) to understand how visitors ' +
            '    use Fikua Lab. No advertising, no tracking across sites.' +
            '  </p>' +
            '  <div class="consent-actions">' +
            '    <button id="consent-reject" class="consent-btn consent-btn--reject">Necessary only</button>' +
            '    <button id="consent-accept" class="consent-btn consent-btn--accept">Accept analytics</button>' +
            '  </div>' +
            '</div>';

        document.body.appendChild(banner);

        // Force reflow then animate in
        banner.offsetHeight;
        banner.classList.add('consent-visible');

        document.getElementById('consent-accept').addEventListener('click', function () {
            setConsent('accepted');
            gtag('consent', 'update', { analytics_storage: 'granted' });
            closeBanner(banner);
        });

        document.getElementById('consent-reject').addEventListener('click', function () {
            setConsent('rejected');
            closeBanner(banner);
        });
    }

    function closeBanner(banner) {
        banner.classList.remove('consent-visible');
        banner.addEventListener('transitionend', function () {
            banner.remove();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectBanner);
    } else {
        injectBanner();
    }
})();
