'use strict';
// Access-token jti revocation (EXPERIMENTS.md 7.6). Active in every configuration.
const { QueryTypes } = require('sequelize');

/** Revoke an access token's jti until the token's own expiry (exp is epoch seconds). Idempotent. */
async function revokeAccessToken(sequelize, { jti, userId, exp }, transaction) {
  // DATE_ADD from the epoch is independent of the session time zone.
  await sequelize.query(
    `INSERT IGNORE INTO revoked_tokens (jti, user_id, expires_at)
     VALUES (:jti, :userId, DATE_ADD('1970-01-01 00:00:00', INTERVAL :exp SECOND))`,
    { replacements: { jti, userId, exp }, type: QueryTypes.INSERT, transaction }
  );
}

async function isRevoked(sequelize, jti) {
  const rows = await sequelize.query('SELECT 1 AS r FROM revoked_tokens WHERE jti = :jti LIMIT 1', {
    replacements: { jti }, type: QueryTypes.SELECT,
  });
  return rows.length > 0;
}

/** Delete revocation rows whose tokens have expired anyway. Run outside measurement windows. */
async function purgeExpiredRevocations(sequelize) {
  const [header, meta] = await sequelize.query('DELETE FROM revoked_tokens WHERE expires_at < NOW(3)');
  const n = (header && header.affectedRows) ?? (meta && meta.affectedRows) ?? meta;
  return Number(n);
}

module.exports = { revokeAccessToken, isRevoked, purgeExpiredRevocations };
