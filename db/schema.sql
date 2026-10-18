CREATE TABLE IF NOT EXISTS scan_events (
  id            BIGSERIAL PRIMARY KEY,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip            INET,
  country_code  TEXT,          -- ISO 3166-1 alpha-3, e.g. ZMB
  country_name  TEXT,
  city          TEXT,
  lat           DOUBLE PRECISION,
  lon           DOUBLE PRECISION,
  attack_type   TEXT NOT NULL,
  signature     TEXT,
  confidence    NUMERIC(5,2) NOT NULL,
  action        TEXT NOT NULL CHECK (action IN ('BLOCK', 'ALLOW', 'REVIEW'))
);

-- Earlier versions stored a 2-letter code; widen it so 3-letter codes fit.
ALTER TABLE scan_events ALTER COLUMN country_code TYPE TEXT;

CREATE INDEX IF NOT EXISTS scan_events_created_at_idx ON scan_events (created_at DESC);
CREATE INDEX IF NOT EXISTS scan_events_country_idx ON scan_events (country_code, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_events_ip_idx ON scan_events (ip);
