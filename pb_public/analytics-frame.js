'use strict';
(() => {
  const origin = 'https://vault.pocketcontext.com';
  // This empty frame isolates Google's automatic capture from the guide's DOM and URL.
  if (window.location.origin !== origin || window.location.pathname !== '/analytics-frame.html' || window.location.search || window.location.hash || window.parent === window) return;
  const measurement = 'G-1X0FZLTWGE';
  const targets = {
    onboarding_copy: new Set(['install_cli', 'install_agent', 'connect', 'initialize', 'keychain', 'sample', 'save', 'round_trip', 'destination_connect', 'compare_prompt', 'compare_commands', 'restore_prompt', 'restore_commands', 'private_diff']),
    onboarding_open: new Set(['install', 'connect', 'initialize', 'round_trip', 'destination_connect', 'compare', 'compare_cli', 'restore', 'restore_cli', 'private_diff', 'server_privacy', 'sharing', 'trusted_agent', 'next_steps']),
    onboarding_method: new Set(['cli', 'agent']),
  };
  let started = false;
  function gtag() { window.dataLayer.push(arguments); }
  window.addEventListener('message', (event) => {
    if (event.origin !== origin || event.source !== window.parent) return;
    if (event.data === 'vault-analytics-start' && !started) {
      started = true;
      window.dataLayer = [];
      gtag('consent', 'default', { analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' });
      gtag('consent', 'update', { analytics_storage: 'granted' });
      gtag('js', new Date());
      gtag('config', measurement, { send_page_view: false, page_location: `${origin}/`, page_title: 'VaultContext', page_referrer: '',
        allow_google_signals: false, allow_ad_personalization_signals: false, cookie_domain: 'vault.pocketcontext.com', cookie_prefix: 'vaultcontext', cookie_flags: 'SameSite=Lax;Secure' });
      const script = document.createElement('script');
      script.async = true;
      script.referrerPolicy = 'no-referrer';
      script.src = `https://www.googletagmanager.com/gtag/js?id=${measurement}`;
      document.head.appendChild(script);
      window.parent.postMessage('vault-analytics-ready', origin);
      return;
    }
    const data = event.data;
    if (!started || !data || data.type !== 'vault-analytics-event') return;
    if (data.name !== 'page_view' && !targets[data.name]?.has(data.target)) return;
    gtag('event', data.name, { ...(data.name === 'page_view' ? {} : { target: data.target }), send_to: measurement,
      page_location: `${origin}/`, page_title: 'VaultContext', page_referrer: '' });
  });
  // Optimizers may defer this script beyond the iframe's load event.
  window.parent.postMessage('vault-analytics-listening', origin);
})();
