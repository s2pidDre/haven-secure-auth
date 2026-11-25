'use strict';
// The browser enhances usability. Every security decision is enforced on the server.
document.querySelectorAll('[data-toggle-password]').forEach(button => {
  button.addEventListener('click', () => {
    const field = document.getElementById(button.dataset.togglePassword);
    const show = field.type === 'password';
    field.type = show ? 'text' : 'password';
    button.textContent = show ? 'Hide' : 'Show';
    button.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} password`);
    button.setAttribute('aria-pressed', String(show));
  });
});
const password = document.getElementById('password');
const confirmation = document.getElementById('confirm-password');
if (password && confirmation) {
  const match = () => confirmation.setCustomValidity(confirmation.value && password.value !== confirmation.value ? 'Your passwords do not match.' : '');
  password.addEventListener('input', match); confirmation.addEventListener('input', match);
}
document.querySelectorAll('[data-copy]').forEach(button => {
  const target = document.getElementById(button.dataset.copy);
  if (!target || !target.textContent.trim()) { button.hidden = true; return; }
  button.addEventListener('click', async () => {
    const content = target.matches('ul') ? [...target.querySelectorAll('code')].map(code => code.textContent).join('\n') : target.textContent.trim();
    const announcement = document.getElementById('announcement');
    try {
      await navigator.clipboard.writeText(content);
      announcement.textContent = 'Copied. Store it somewhere private.';
      button.textContent = 'Copied ✓';
    } catch {
      announcement.textContent = 'Copy was unavailable. Select the text and copy it manually.';
      button.textContent = 'Select and copy the text above';
    }
  });
});
document.querySelectorAll('form[data-submit-label]').forEach(form => {
  form.addEventListener('submit', () => {
    const button = form.querySelector('[type="submit"]');
    if (!button || button.disabled) return;
    button.disabled = true;
    const label = button.querySelector('span');
    if (label) { label.dataset.originalLabel = label.textContent; label.textContent = form.dataset.submitLabel; }
    form.setAttribute('aria-busy', 'true');
  });
});
document.querySelectorAll('[data-local-time]').forEach(element => {
  const date = new Date(element.dateTime);
  if (!Number.isNaN(date.getTime())) element.textContent = date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
});
window.addEventListener('pageshow', event => {
  // A page restored from memory must re-check its server-side session.
  if (event.persisted) { window.location.reload(); return; }
  document.querySelectorAll('form[aria-busy]').forEach(form => {
    form.removeAttribute('aria-busy');
    const button = form.querySelector('[type="submit"]');
    if (button) button.disabled = false;
    const label = button?.querySelector('[data-original-label]');
    if (label) label.textContent = label.dataset.originalLabel;
  });
});
const notice = document.querySelector('.notice-error');
if (notice) notice.focus({ preventScroll: true });
