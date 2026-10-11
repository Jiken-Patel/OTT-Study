'use strict';
// Drops all study tables and re-applies db/schema.sql. Used before every run (EXPERIMENTS.md 12)
// and by the test suite. Never run against a database you care about.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

const TABLES = ['security_events', 'one_time_tokens', 'revoked_tokens', 'refresh_tokens', 'users'];

async function resetDb() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'ott',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ott_study',
    multipleStatements: true,
  });
  try {
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    for (const t of TABLES) await conn.query(`DROP TABLE IF EXISTS ${t}`);
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    await conn.query(fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8'));
  } finally {
    await conn.end();
  }
}

module.exports = { resetDb };

if (require.main === module) {
  resetDb().then(() => console.log('database reset')).catch((e) => { console.error(e); process.exit(1); });
}
