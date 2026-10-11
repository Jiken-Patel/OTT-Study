'use strict';
// Sequelize models mirror db/schema.sql (the schema file is authoritative; never use sync()).
const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const User = sequelize.define('User', {
  id: { type: DataTypes.BIGINT.UNSIGNED, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING(255), allowNull: false, unique: true },
  passwordHash: { type: DataTypes.STRING(100), allowNull: false, field: 'password_hash' },
  passwordChangedAt: { type: DataTypes.DATE(3), field: 'password_changed_at' },
}, { tableName: 'users', timestamps: true, createdAt: 'created_at', updatedAt: 'updated_at' });

const RefreshToken = sequelize.define('RefreshToken', {
  id: { type: DataTypes.BIGINT.UNSIGNED, primaryKey: true, autoIncrement: true },
  userId: { type: DataTypes.BIGINT.UNSIGNED, allowNull: false, field: 'user_id' },
  familyId: { type: DataTypes.CHAR(36), allowNull: false, field: 'family_id' },
  jti: { type: DataTypes.CHAR(36), allowNull: false, unique: true },
  tokenHash: { type: DataTypes.CHAR(64), allowNull: false, unique: true, field: 'token_hash' },
  expiresAt: { type: DataTypes.DATE(3), allowNull: false, field: 'expires_at' },
  revokedAt: { type: DataTypes.DATE(3), field: 'revoked_at' },
  replacedBy: { type: DataTypes.BIGINT.UNSIGNED, field: 'replaced_by' },
}, { tableName: 'refresh_tokens', timestamps: true, createdAt: 'created_at', updatedAt: false });

const RevokedToken = sequelize.define('RevokedToken', {
  id: { type: DataTypes.BIGINT.UNSIGNED, primaryKey: true, autoIncrement: true },
  jti: { type: DataTypes.CHAR(36), allowNull: false, unique: true },
  userId: { type: DataTypes.BIGINT.UNSIGNED, allowNull: false, field: 'user_id' },
  expiresAt: { type: DataTypes.DATE(3), allowNull: false, field: 'expires_at' },
  revokedAt: { type: DataTypes.DATE(3), field: 'revoked_at' },
}, { tableName: 'revoked_tokens', timestamps: false });

const OneTimeToken = sequelize.define('OneTimeToken', {
  id: { type: DataTypes.BIGINT.UNSIGNED, primaryKey: true, autoIncrement: true },
  userId: { type: DataTypes.BIGINT.UNSIGNED, allowNull: false, field: 'user_id' },
  tokenHash: { type: DataTypes.CHAR(64), allowNull: false, unique: true, field: 'token_hash' },
  purpose: { type: DataTypes.STRING(64), allowNull: false },
  method: { type: DataTypes.STRING(8), allowNull: false },
  endpoint: { type: DataTypes.STRING(128), allowNull: false },
  contextHash: { type: DataTypes.CHAR(64), allowNull: false, field: 'context_hash' },
  expiresAt: { type: DataTypes.DATE(3), allowNull: false, field: 'expires_at' },
  usedAt: { type: DataTypes.DATE(3), field: 'used_at' },
  supersededAt: { type: DataTypes.DATE(3), field: 'superseded_at' },
  attemptCount: { type: DataTypes.INTEGER.UNSIGNED, allowNull: false, defaultValue: 0, field: 'attempt_count' },
}, { tableName: 'one_time_tokens', timestamps: true, createdAt: 'created_at', updatedAt: false });

const SecurityEvent = sequelize.define('SecurityEvent', {
  id: { type: DataTypes.BIGINT.UNSIGNED, primaryKey: true, autoIncrement: true },
  userId: { type: DataTypes.BIGINT.UNSIGNED, field: 'user_id' },
  eventType: { type: DataTypes.STRING(64), allowNull: false, field: 'event_type' },
  reason: { type: DataTypes.STRING(64) },
  authMode: { type: DataTypes.CHAR(1), field: 'auth_mode' },
  httpMethod: { type: DataTypes.STRING(8), field: 'http_method' },
  endpoint: { type: DataTypes.STRING(128) },
  ip: { type: DataTypes.STRING(45) },
  details: { type: DataTypes.JSON },
}, { tableName: 'security_events', timestamps: true, createdAt: 'created_at', updatedAt: false });

User.hasMany(RefreshToken, { foreignKey: 'userId' });
User.hasMany(OneTimeToken, { foreignKey: 'userId' });
User.hasMany(SecurityEvent, { foreignKey: 'userId' });
RefreshToken.belongsTo(User, { foreignKey: 'userId' });
OneTimeToken.belongsTo(User, { foreignKey: 'userId' });

module.exports = { sequelize, User, RefreshToken, RevokedToken, OneTimeToken, SecurityEvent };
