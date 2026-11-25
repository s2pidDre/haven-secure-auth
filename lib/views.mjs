import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('../templates/', import.meta.url));
const templates = new Map();
for (const file of ['layout', 'login', 'register', 'mfa', 'recovery', 'logged-in', 'error']) {
  templates.set(file, readFileSync(join(root, `${file}.html`), 'utf8'));
}
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
})[c]);
const raw = value => ({ trustedHtml: value });
function template(name, values) {
  return templates.get(name).replace(/\{\{([a-z_]+)\}\}/g, (_, key) => {
    const value = values[key] ?? '';
    return value && typeof value === 'object' && 'trustedHtml' in value ? value.trustedHtml : escapeHtml(value);
  });
}
export function page(name, values = {}) {
  const error = values.error ? `<div class="notice notice-error" role="alert" tabindex="-1">${escapeHtml(values.error)}</div>` : '';
  const message = values.message ? `<div class="notice notice-success" role="status">${escapeHtml(values.message)}</div>` : '';
  const security = `<details class="security-details"><summary>How your sign-in is protected</summary><ul>
    <li>Your connection is encrypted with HTTPS.</li><li>Passwords are stored as salted Argon2id hashes.</li>
    <li>An authenticator code is required to finish signing in.</li><li>Attempts are limited and security events are recorded without passwords.</li>
    <li>Sessions use protected cookies and expire after inactivity.</li></ul></details>`;
  const enrollment = values.enrollment ? `<div class="setup-box"><span class="field-label">Add an account in your authenticator app</span>
    <p>Choose “Enter setup key.” Use your account email, select time-based codes, and enter this key:</p>
    <code class="setup-key" id="setup-key">${escapeHtml(values.setup_key)}</code>
    <button type="button" class="text-button" data-copy="setup-key">Copy setup key</button>
    <p class="helper">Works with Google Authenticator, Microsoft Authenticator, 2FAS, and other TOTP apps. Keep this key private.</p></div>` : '';
  const recoverySwitch = !values.enrollment ? `<details class="recovery-switch"><summary>Use a recovery code instead</summary>
    <p class="helper">Each recovery code can be used once. Enter it in the same field above.</p></details>` : '';
  const codeList = (values.codes || []).map(code => `<li><code>${escapeHtml(code)}</code></li>`).join('');
  const body = template(name, { ...values, error: raw(error), message: raw(message),
    enrollment: raw(enrollment), recovery_switch: raw(recoverySwitch), code_list: raw(codeList) });
  return template('layout', { title: values.title || 'Secure access', body: raw(body),
    security: raw(security), page_name: name });
}
