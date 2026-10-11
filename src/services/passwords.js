'use strict';
// bcrypt (native, cost 12 frozen) + password policy (8-72 bytes; bcrypt ignores input beyond 72 bytes).
const bcrypt = require('bcrypt');

function createPasswordService(config) {
  const { bcryptCost } = config;
  const { minBytes, maxBytes } = config.password;
  let dummyHash; // memoised promise: lets unknown-user logins pay the same bcrypt cost

  const bytes = (p) => Buffer.byteLength(p, 'utf8');
  return {
    /** Returns null if acceptable, otherwise a short reason string. */
    validateNew(p) {
      if (typeof p !== 'string') return 'password must be a string';
      const n = bytes(p);
      if (n < minBytes) return `password must be at least ${minBytes} bytes`;
      if (n > maxBytes) return `password must be at most ${maxBytes} bytes`;
      return null;
    },
    /** A password longer than 72 bytes can never have been set, so it can never match. */
    isPlausible(p) { return typeof p === 'string' && bytes(p) >= 1 && bytes(p) <= maxBytes; },
    hash: (p) => bcrypt.hash(p, bcryptCost),
    verify: (p, hash) => bcrypt.compare(p, hash),
    async verifyAgainstDummy(p) {
      dummyHash = dummyHash || bcrypt.hash('dummy-password-for-timing-equalisation', bcryptCost);
      return bcrypt.compare(p, await dummyHash);
    },
  };
}

module.exports = { createPasswordService };
