'use strict';
// Public onboarding only. Forks and other hosts never contact analytics services.
const trackOnboarding = (() => {
  const origin = 'https://vault.pocketcontext.com';
  if (window.location.origin !== origin || window.location.pathname !== '/') return () => {};
  const key = 'vaultcontext.analytics.v1';
  const notice = document.getElementById('analytics-notice');
  const settings = document.getElementById('analytics-settings');
  const status = document.getElementById('analytics-status');
  const targets = {
    onboarding_copy: new Set(['install_cli', 'install_agent', 'connect', 'initialize', 'keychain', 'sample', 'save', 'round_trip', 'destination_connect', 'compare_prompt', 'compare_commands', 'restore_prompt', 'restore_commands', 'private_diff']),
    onboarding_open: new Set(['install', 'connect', 'initialize', 'round_trip', 'destination_connect', 'compare', 'compare_cli', 'restore', 'restore_cli', 'private_diff', 'server_privacy', 'sharing', 'trusted_agent', 'next_steps']),
    onboarding_method: new Set(['cli', 'agent']),
  };
  let choice;
  let started = false;
  try { choice = localStorage.getItem(key); } catch { /* Choice lasts for this page when storage is unavailable. */ }
  let frame;
  let ready = false;
  const pending = [];
  window.addEventListener('message', (event) => {
    if (event.origin !== origin || event.source !== frame?.contentWindow || choice !== 'accepted') return;
    if (event.data === 'vault-analytics-listening') {
      frame.contentWindow.postMessage('vault-analytics-start', origin);
      return;
    }
    if (event.data !== 'vault-analytics-ready') return;
    ready = true;
    for (const payload of pending.splice(0)) frame.contentWindow.postMessage(payload, origin);
  });
  function emit(name, target) {
    if (choice !== 'accepted' || window.location.origin !== origin || window.location.pathname !== '/') return;
    if (name !== 'page_view' && !targets[name]?.has(target)) return;
    const properties = name === 'page_view' ? {} : { target };
    try {
      fetch('https://rybbit.getcolors.ai/api/track', {
        method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer', keepalive: true,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site_id: 'd8b36ba4a63f', type: name === 'page_view' ? 'pageview' : 'custom_event',
          hostname: 'vault.pocketcontext.com', pathname: '/', page_title: 'VaultContext', querystring: '', referrer: '',
          ...(name === 'page_view' ? {} : { event_name: name, properties: JSON.stringify(properties) }) }),
      }).catch(() => {});
      const payload = { type: 'vault-analytics-event', name, target };
      if (ready) frame.contentWindow.postMessage(payload, origin);
      else pending.push(payload);
    } catch { /* Analytics must never interrupt the guide or a successful copy. */ }
  }
  function start() {
    if (started) return;
    started = true;
    frame = document.createElement('iframe');
    frame.hidden = true;
    frame.title = 'Optional website analytics';
    frame.referrerPolicy = 'no-referrer';
    frame.src = '/analytics-frame.html';
    document.body.appendChild(frame);
    emit('page_view');
  }
  function choose(next) {
    choice = next;
    try { localStorage.setItem(key, choice); } catch { /* Keep in-memory choice. */ }
    notice.hidden = true;
    settings.focus();
    if (choice === 'accepted') {
      start();
      status.textContent = 'Website analytics enabled. Change your choice using Analytics settings.';
    } else {
      frame?.remove();
      frame = undefined;
      started = false;
      ready = false;
      pending.length = 0;
      // Remove this site's GA cookies; do not disturb the marketing site's cookies.
      for (const item of document.cookie.split(';')) {
        const name = item.trim().split('=')[0];
        if (name === 'vaultcontext_ga' || name === 'vaultcontext_ga_1X0FZLTWGE') {
          document.cookie = `${name}=; Max-Age=0; Path=/; Domain=vault.pocketcontext.com; Secure; SameSite=Lax`;
          document.cookie = `${name}=; Max-Age=0; Path=/; Secure; SameSite=Lax`;
        }
      }
      status.textContent = 'Website analytics disabled.';
    }
  }
  window.addEventListener('storage', (event) => {
    if (event.key === key && event.newValue !== 'accepted') {
      // Revocation in another tab also stops this page; consent is never granted by an event.
      choose('rejected');
    }
  });
  settings.hidden = false;
  settings.addEventListener('click', () => { notice.hidden = false; document.getElementById('analytics-reject').focus(); });
  document.getElementById('analytics-accept').addEventListener('click', () => choose('accepted'));
  document.getElementById('analytics-reject').addEventListener('click', () => choose('rejected'));
  notice.hidden = choice === 'accepted' || choice === 'rejected';
  if (choice === 'accepted') start();
  return emit;
})();
for (const details of document.querySelectorAll('details[data-analytics-id]')) {
  let wasOpen = details.open;
  details.addEventListener('toggle', () => {
    if (details.open && !wasOpen) trackOnboarding('onboarding_open', details.dataset.analyticsId);
    wasOpen = details.open;
  });
}
for (const button of document.querySelectorAll('[data-method]')) {
  button.addEventListener('click', () => {
    if (button.getAttribute('aria-pressed') !== 'true') trackOnboarding('onboarding_method', button.dataset.method);
    for (const option of document.querySelectorAll('[data-method]')) {
      const selected = option === button;
      option.classList.toggle('active', selected);
      option.setAttribute('aria-pressed', String(selected));
      document.getElementById(`${option.dataset.method}-panel`).hidden = !selected;
    }
  });
}
for (const button of document.querySelectorAll('.copy')) {
  button.addEventListener('click', async () => {
    const code = button.parentElement.querySelector('code');
    try {
      await navigator.clipboard.writeText(code.textContent);
      trackOnboarding('onboarding_copy', button.parentElement.dataset.analyticsId);
      button.textContent = 'Copied';
      document.getElementById('copy-status').textContent = 'Copied. Replace example paths and placeholders before use.';
      setTimeout(() => { button.textContent = 'Copy'; }, 2000);
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(code);
      selection.removeAllRanges();
      selection.addRange(range);
      document.getElementById('copy-status').textContent = 'Automatic copy unavailable. Commands selected; use your keyboard or touch menu to copy.';
    }
  });
}
