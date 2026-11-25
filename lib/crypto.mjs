import { argon2, randomBytes, createHash, createHmac, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { promisify } from 'node:util';
const derive = promisify(argon2);
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const params = { memory: 65536, passes: 3, parallelism: 1, tagLength: 32 };

export class BusyError extends Error {}
// At most two concurrent 64 MiB hashes; overload fails without an unbounded queue.
let activeHashes = 0;
async function argon(message, salt) {
  if (activeHashes >= 2) throw new BusyError('Authentication capacity reached.');
  activeHashes++;
  try { return await derive('argon2id', { ...params, message, nonce: salt }); }
  finally { activeHashes--; }
}
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await argon(password, salt);
  return `$argon2id$v=19$m=65536,t=3,p=1$${salt.toString('base64')}$${hash.toString('base64')}`;
}
export async function verifyPassword(password, encoded) {
  const match = /^\$argon2id\$v=19\$m=65536,t=3,p=1\$([A-Za-z0-9+/]{22}==)\$([A-Za-z0-9+/]{43}=)$/.exec(encoded);
  if (!match) throw new Error('Unsupported password record.');
  const result = await argon(password, Buffer.from(match[1], 'base64'));
  return timingSafeEqual(result, Buffer.from(match[2], 'base64'));
}
export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value).digest('hex');
export function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function keyFor(secret, purpose) { return createHmac('sha256', secret).update(purpose).digest(); }
export function fingerprint(secret, purpose, value) {
  return createHmac('sha256', keyFor(secret, purpose)).update(value).digest('hex');
}
export function seal(secret, value, purpose) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyFor(secret, 'encryption'), iv);
  cipher.setAAD(Buffer.from(purpose));
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}
export function unseal(secret, value, purpose) {
  const bytes = Buffer.from(value, 'base64url');
  const cipher = createDecipheriv('aes-256-gcm', keyFor(secret, 'encryption'), bytes.subarray(0, 12));
  cipher.setAAD(Buffer.from(purpose));
  cipher.setAuthTag(bytes.subarray(12, 28));
  return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8');
}
export function base32(bytes) {
  let bits = 0; let value = 0; let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
export function decode32(text) {
  let bits = 0; let value = 0; const out = [];
  for (const char of text.replace(/=+$/, '').toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error('Invalid base32.');
    value = (value << 5) | index; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export const newTotpSecret = () => base32(randomBytes(20));
export function totp(secret, step, digits = 6) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', decode32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits)).padStart(digits, '0');
}
export function verifyTotp(secret, code, lastStep = -1, now = Date.now()) {
  if (!/^\d{6}$/.test(code)) return null;
  const step = Math.floor(now / 30000);
  let matched = null;
  for (const candidate of [step - 1, step, step + 1]) {
    if (candidate >= 0 && equal(totp(secret, candidate), code) && candidate > lastStep) matched = candidate;
  }
  return matched;
}
export function recoveryCodes() {
  return Array.from({ length: 8 }, () => base32(randomBytes(10)).match(/.{4}/g).join('-'));
}
export function normalizeRecovery(value) { return value.toUpperCase().replace(/[\s-]/g, ''); }

const common = new Set([
  'password', 'password123', 'password123456', '123456789012345', '1234567890123456',
  'qwertyuiopasdfgh', 'letmeinletmein', 'iloveyouiloveyou', 'correcthorsebatterystaple',
  'adminadminadmin', 'welcome123456789', 'thisisapassword', 'changemechangeme',
  'passwordpassword', 'password123456789', 'qwerty1234567890', 'aaaaaaaaaaaaaaa'
]);
export function passwordProblem(password, email) {
  const size = Array.from(password).length;
  if (size < 15 || size > 128 || Buffer.byteLength(password, 'utf8') > 512) return 'Use a password with 15–128 characters.';
  if (/[\u0000-\u001f\u007f]/u.test(password)) return 'Use printable characters in your password.';
  const lower = password.toLowerCase();
  if (common.has(lower) || /^(.)\1+$/u.test(password) || lower === email.toLowerCase()) return 'Choose a less predictable password or a unique passphrase.';
  return '';
}
export async function isBreached(password, fetcher = fetch) {
  // SHA-1 is used ONLY for the HIBP protocol. Password storage always uses Argon2id.
  const hash = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const response = await fetcher(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { 'Add-Padding': 'true', 'User-Agent': 'SecureAuth548/1.0' },
    signal: AbortSignal.timeout(5000), redirect: 'error'
  });
  if (!response.ok) throw new Error('Password screening unavailable.');
  // Bound third-party response consumption.
  let data = ''; let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.byteLength;
    if (bytes > 2_000_000) throw new Error('Password screening response too large.');
    data += Buffer.from(chunk).toString('ascii');
  }
  return data.split(/\r?\n/).some(line => {
    const [suffix, count] = line.split(':');
    return suffix === hash.slice(5) && Number(count) > 0;
  });
}
