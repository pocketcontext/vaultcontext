'use strict';
for (const button of document.querySelectorAll('[data-method]')) {
  button.addEventListener('click', () => {
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
      button.textContent = 'Copied';
      document.getElementById('copy-status').textContent = 'Commands copied. Replace any placeholders before running.';
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
