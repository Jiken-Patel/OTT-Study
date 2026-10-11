-- Stage 1 schema. Matches EXPERIMENTS.md v1.3 (sections 3, 7).
-- Requires MySQL 8.0.16+ (CHECK constraints are enforced). Engine: InnoDB.
-- All timestamps are DATETIME(3); all expiry/state comparisons use DB time (NOW(3)).

CREATE TABLE IF NOT EXISTS users (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email                VARCHAR(255)    NOT NULL,
  password_hash        VARCHAR(100)    NOT NULL,
  password_changed_at  DATETIME(3)     NULL,
  created_at           DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at           DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Refresh tokens: only SHA-256 hashes are stored. family_id groups a rotation chain (7.5).
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id      BIGINT UNSIGNED NOT NULL,
  family_id    CHAR(36)        NOT NULL,
  jti          CHAR(36)        NOT NULL,
  token_hash   CHAR(64)        NOT NULL,
  expires_at   DATETIME(3)     NOT NULL,
  revoked_at   DATETIME(3)     NULL,
  replaced_by  BIGINT UNSIGNED NULL,
  created_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_refresh_jti (jti),
  UNIQUE KEY uq_refresh_hash (token_hash),
  KEY idx_refresh_family (family_id),
  KEY idx_refresh_user (user_id),
  CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_replaced FOREIGN KEY (replaced_by) REFERENCES refresh_tokens (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Revoked access-token jti values (7.6). Purged after expires_at, outside measurement windows.
CREATE TABLE IF NOT EXISTS revoked_tokens (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  jti         CHAR(36)        NOT NULL,
  user_id     BIGINT UNSIGNED NOT NULL,
  expires_at  DATETIME(3)     NOT NULL,
  revoked_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_revoked_jti (jti),
  KEY idx_revoked_expires (expires_at),
  CONSTRAINT fk_revoked_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One-time tokens (7.2-7.4). Only the SHA-256 hash of the OTT is stored; the raw OTT never is.
-- States: active / used (used_at) / superseded (superseded_at) / expired (expires_at passed).
CREATE TABLE IF NOT EXISTS one_time_tokens (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id        BIGINT UNSIGNED NOT NULL,
  token_hash     CHAR(64)        NOT NULL,
  purpose        VARCHAR(64)     NOT NULL,
  method         VARCHAR(8)      NOT NULL,
  endpoint       VARCHAR(128)    NOT NULL,
  context_hash   CHAR(64)        NOT NULL,
  expires_at     DATETIME(3)     NOT NULL,
  used_at        DATETIME(3)     NULL,
  superseded_at  DATETIME(3)     NULL,
  attempt_count  INT UNSIGNED    NOT NULL DEFAULT 0,
  created_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_ott_hash (token_hash),
  KEY idx_ott_binding (user_id, purpose, method, endpoint, used_at, superseded_at),
  CONSTRAINT fk_ott_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  -- Structural invariant (EXPERIMENTS.md 8.1, T27): a row is never both used and superseded.
  CONSTRAINT chk_ott_not_used_and_superseded CHECK (used_at IS NULL OR superseded_at IS NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Security audit events. `details` must never contain raw tokens or passwords.
CREATE TABLE IF NOT EXISTS security_events (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id      BIGINT UNSIGNED NULL,
  event_type   VARCHAR(64)     NOT NULL,
  reason       VARCHAR(64)     NULL,
  auth_mode    CHAR(1)         NULL,
  http_method  VARCHAR(8)      NULL,
  endpoint     VARCHAR(128)    NULL,
  ip           VARCHAR(45)     NULL,
  details      JSON            NULL,
  created_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_events_type_time (event_type, created_at),
  KEY idx_events_user_time (user_id, created_at),
  CONSTRAINT fk_events_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
