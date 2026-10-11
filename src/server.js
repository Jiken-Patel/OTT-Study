'use strict';
// Frozen: libuv threadpool size 16. Must be set before anything uses the pool (bcrypt, crypto, fs).
process.env.UV_THREADPOOL_SIZE = '16';
require('dotenv').config();

const { loadConfig } = require('./config');
const sequelize = require('./config/db');
const { createApp } = require('./app');

async function main() {
  const config = loadConfig(process.env); // throws (and exits) on invalid/forbidden configuration
  await sequelize.authenticate();
  const app = createApp({ sequelize, config });
  app.listen(config.port, () => console.log(`listening on :${config.port} (AUTH_MODE=${config.authMode})`));
}

main().catch((e) => { console.error(e.message); process.exit(1); });
