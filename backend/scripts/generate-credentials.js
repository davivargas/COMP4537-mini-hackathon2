'use strict';

// Prints a random password, secret and JWT key that satisfy the hackathon
// rules (password: 6 characters; secret: fewer than 20 characters, no spaces).
// Uses the cryptographic random generator, so the values cannot be guessed.

const crypto = require('node:crypto');

const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// Symbols that are safe to paste into a hosting dashboard or a .env file.
const PASSWORD_CHARS = `${ALPHANUMERIC}!@%^*-_+?`;

function randomString(alphabet, length) {
  let out = '';
  for (let i = 0; i < length; i += 1) out += alphabet[crypto.randomInt(alphabet.length)];
  return out;
}

console.log(`ADMIN_PASSWORD=${randomString(PASSWORD_CHARS, 6)}`);
console.log(`SECRET=${randomString(ALPHANUMERIC, 19)}`);
console.log(`JWT_KEY=${crypto.randomBytes(48).toString('base64url')}`);
