'use strict';
// Configuration loader. Frozen experimental variables (EXPERIMENTS.md section 3) are constants here,
// NOT environment-configurable, so a run cannot silently drift from the frozen design.

const FROZEN = Object.freeze({
  ACCESS_TTL_SECONDS: 15 * 60,
  REFRESH_TTL_SECONDS: 7 * 24 * 60 * 60,
  OTT_TTL_SECONDS_DEFAULT: 5 * 60,
  JWT_ALGORITHM: 'HS256',
  JWT_ISSUER: 'ott-study-auth',
  JWT_AUDIENCE: 'ott-study-api',
  BCRYPT_COST: 12,
  UV_THREADPOOL_SIZE: 16,
  PASSWORD_MIN_BYTES: 8,
  PASSWORD_MAX_BYTES: 72, // bcrypt ignores input beyond 72 bytes
});

const AUTH_MODES = ['A', 'B', 'C', 'D'];
const APP_PROFILES = ['development', 'test'];
const RATE_LIMIT_PROFILES = ['standard', 'relaxed', 'off'];

function loadConfig(env = process.env) {
  const errors = [];

  const appProfile = env.APP_PROFILE || 'development';
  if (!APP_PROFILES.includes(appProfile)) errors.push(`APP_PROFILE must be one of ${APP_PROFILES.join(', ')}`);

  const authMode = env.AUTH_MODE;
  if (!AUTH_MODES.includes(authMode)) errors.push('AUTH_MODE must be one of A, B, C, D');

  const rateLimitProfile = env.RATE_LIMIT_PROFILE || 'standard';
  if (!RATE_LIMIT_PROFILES.includes(rateLimitProfile)) {
    errors.push(`RATE_LIMIT_PROFILE must be one of ${RATE_LIMIT_PROFILES.join(', ')}`);
  }

  const accessSecret = env.JWT_ACCESS_SECRET || '';
  const refreshSecret = env.JWT_REFRESH_SECRET || '';
  if (accessSecret.length < 32) errors.push('JWT_ACCESS_SECRET must be at least 32 characters');
  if (refreshSecret.length < 32) errors.push('JWT_REFRESH_SECRET must be at least 32 characters');
  if (accessSecret && accessSecret === refreshSecret) errors.push('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ');

  let ottTtlSeconds = FROZEN.OTT_TTL_SECONDS_DEFAULT;
  if (env.OTT_EXPIRES_IN_SECONDS !== undefined && env.OTT_EXPIRES_IN_SECONDS !== '') {
    ottTtlSeconds = Number(env.OTT_EXPIRES_IN_SECONDS);
    if (!Number.isInteger(ottTtlSeconds) || ottTtlSeconds <= 0) {
      errors.push('OTT_EXPIRES_IN_SECONDS must be a positive integer');
    } else if (ottTtlSeconds !== FROZEN.OTT_TTL_SECONDS_DEFAULT && appProfile !== 'test') {
      errors.push('OTT_EXPIRES_IN_SECONDS may only differ from the frozen 300 when APP_PROFILE=test (T06)');
    }
  }

  const unsafe = env.UNSAFE_NON_ATOMIC_CONSUME === 'true' || Number(env.UNSAFE_DELAY_MS || 0) > 0;
  if (unsafe && appProfile !== 'test') errors.push('UNSAFE_* flags are only allowed when APP_PROFILE=test');

  if (appProfile !== 'test' && Number(env.UV_THREADPOOL_SIZE) !== FROZEN.UV_THREADPOOL_SIZE) {
    errors.push(`UV_THREADPOOL_SIZE must be ${FROZEN.UV_THREADPOOL_SIZE} (frozen)`);
  }

  const enableSimulatedOperations = env.ENABLE_SIMULATED_OPERATIONS === 'true';

  // OOB sink (EXPERIMENTS.md 6): only Config C uses it. The URL must be loopback so an OTT can
  // never be sent to an external host by misconfiguration. The app holds the DELIVER key only; it
  // has no key (and no code) to read the inbox.
  let oobSink = null;
  if (authMode === 'C') {
    let url = null;
    try { url = new URL(env.OOB_SINK_URL || ''); } catch (e) { url = null; }
    if (!url || url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
      errors.push('OOB_SINK_URL must be an http URL on loopback (127.0.0.1, localhost or [::1]) when AUTH_MODE=C');
    }
    const key = env.OOB_SINK_KEY || '';
    if (key.length < 16) errors.push('OOB_SINK_KEY must be at least 16 characters when AUTH_MODE=C');
    if (url && key.length >= 16) oobSink = Object.freeze({ url: url.origin, deliverKey: key });
  }

  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 0 || port > 65535) errors.push('PORT must be a valid port number');

  if (errors.length) {
    // Never include secret values in the message.
    const e = new Error(`Invalid configuration:\n- ${errors.join('\n- ')}`);
    e.code = 'INVALID_CONFIG';
    throw e;
  }

  return Object.freeze({
    appProfile, authMode, rateLimitProfile, port, ottTtlSeconds, enableSimulatedOperations, oobSink,
    bcryptCost: FROZEN.BCRYPT_COST,
    password: Object.freeze({ minBytes: FROZEN.PASSWORD_MIN_BYTES, maxBytes: FROZEN.PASSWORD_MAX_BYTES }),
    jwt: Object.freeze({
      algorithm: FROZEN.JWT_ALGORITHM,
      issuer: FROZEN.JWT_ISSUER,
      audience: FROZEN.JWT_AUDIENCE,
      accessSecret, refreshSecret,
      accessTtlSeconds: FROZEN.ACCESS_TTL_SECONDS,
      refreshTtlSeconds: FROZEN.REFRESH_TTL_SECONDS,
    }),
  });
}

module.exports = { loadConfig, FROZEN, AUTH_MODES };
