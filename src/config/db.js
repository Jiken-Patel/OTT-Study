'use strict';
require('dotenv').config();
const { Sequelize } = require('sequelize');

// Frozen variables (EXPERIMENTS.md 3): pool 20, READ COMMITTED (set per transaction),
// innodb_lock_wait_timeout = 5 s.
const sequelize = new Sequelize(
  process.env.DB_NAME || 'ott_study',
  process.env.DB_USER || 'ott',
  process.env.DB_PASSWORD || '',
  {
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    dialect: 'mysql',
    logging: false,
    timezone: '+00:00',
    pool: { max: 20, min: 0, acquire: 30000, idle: 10000 },
    define: { underscored: true, timestamps: false },
    hooks: {
      afterConnect: async (connection) => {
        await connection.promise().query("SET SESSION time_zone = '+00:00'");
        await connection.promise().query('SET SESSION innodb_lock_wait_timeout = 5');
      },
    },
  }
);

module.exports = sequelize;
