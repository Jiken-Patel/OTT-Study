'use strict';
// Sensitive-operation primitives, shared by Configs A/B/D now and by Config C (inside the OTT
// consume transaction) later. Hashing is separate from the write so bcrypt never runs in a transaction.
const { QueryTypes } = require('sequelize');

function createSensitiveService({ sequelize, passwords }) {
  return {
    preparePasswordChange: (newPassword) => passwords.hash(newPassword),
    writePasswordChange: (userId, hash, transaction) => sequelize.query(
      'UPDATE users SET password_hash = :hash, password_changed_at = NOW(3) WHERE id = :userId',
      { replacements: { hash, userId }, type: QueryTypes.UPDATE, transaction }),
  };
}

module.exports = { createSensitiveService };
