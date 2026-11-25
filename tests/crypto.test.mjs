import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { hashPassword, verifyPassword, base32, decode32, totp, verifyTotp, seal, unseal,
  passwordProblem, recoveryCodes, normalizeRecovery, isBreached } from '../lib/crypto.mjs';

test('Argon2id uses unique salts and verifies only the correct password', async () => {
  const password = 'Bright rivers carry 82 lanterns!';
  const a = await hashPassword(password); const b = await hashPassword(password);
  assert.notEqual(a, b); assert.match(a, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
  assert.equal(await verifyPassword(password, a), true);
  assert.equal(await verifyPassword('Wrong rivers carry 82 lanterns!', a), false);
});
test('AES-GCM encryption is authenticated and bound to its record', () => {
  const key = randomBytes(32); const encoded = seal(key, 'private-value', 'totp:one');
  assert.equal(unseal(key, encoded, 'totp:one'), 'private-value');
  assert.throws(() => unseal(key, encoded, 'totp:two'));
  const bytes = Buffer.from(encoded, 'base64url'); bytes[bytes.length - 1] ^= 1;
  assert.throws(() => unseal(key, bytes.toString('base64url'), 'totp:one'));
});
test('TOTP matches RFC 6238 SHA-1 test vectors', () => {
  const secret = base32(Buffer.from('12345678901234567890'));
  const vectors = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [seconds, expected] of vectors) assert.equal(totp(secret, Math.floor(seconds / 30), 8), expected);
  assert.equal(decode32(secret).toString(), '12345678901234567890');
});
test('TOTP rejects replay, expired windows, and malformed codes', () => {
  const secret = base32(randomBytes(20)); const now = 1800000000000; const step = Math.floor(now / 30000);
  const code = totp(secret, step);
  assert.equal(verifyTotp(secret, code, -1, now), step);
  assert.equal(verifyTotp(secret, code, step, now), null);
  assert.equal(verifyTotp(secret, code, -1, now + 120000), null);
  assert.equal(verifyTotp(secret, '12345a', -1, now), null);
});
test('Password policy bounds work and supports long Unicode passphrases', () => {
  assert.ok(passwordProblem('short', 'a@example.com'));
  assert.ok(passwordProblem('x'.repeat(129), 'a@example.com'));
  assert.ok(passwordProblem('passwordpassword', 'a@example.com'));
  assert.equal(passwordProblem('🌊 Moonlit rivers carry 82 lanterns!', 'a@example.com'), '');
  assert.equal(passwordProblem('aB!7'.repeat(32), 'a@example.com'), '');
});
test('Recovery codes contain 80 bits of randomness per code in a usable format', () => {
  const codes = recoveryCodes(); assert.equal(codes.length, 8); assert.equal(new Set(codes).size, 8);
  for (const code of codes) {
    assert.match(code, /^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$/);
    assert.equal(normalizeRecovery(code.toLowerCase()).length, 16);
  }
});
test('HIBP sends only a five-character prefix, requests padding, and ignores padded zero counts', async () => {
  const password = 'A private password under test!'; const hash = createHash('sha1').update(password).digest('hex').toUpperCase();
  let seen = 0;
  const fetcher = async (url, options) => {
    seen++; assert.equal(url, `https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
    assert.equal(options.headers['Add-Padding'], 'true'); assert.equal(options.redirect, 'error');
    assert.equal(options.body, undefined);
    return new Response(`${hash.slice(5)}:${seen === 1 ? 42 : 0}\r\n`);
  };
  assert.equal(await isBreached(password, fetcher), true);
  assert.equal(await isBreached(password, fetcher), false);
  await assert.rejects(() => isBreached(password, async () => new Response('', { status: 503 })));
});
