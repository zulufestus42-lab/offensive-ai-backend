const env = process.env;

export const config = {
  port: Number(env.PORT ?? 8080),
  corsOrigins: (env.CORS_ORIGIN ?? 'http://localhost:5173').split(',').map((s) => s.trim()).filter(Boolean),
  trustProxy: env.TRUST_PROXY === undefined ? 1 : Number(env.TRUST_PROXY),
  databaseUrl: env.DATABASE_URL,
  scannerUrl: env.SCANNER_URL,
  scannerTimeoutMs: Number(env.SCANNER_TIMEOUT_MS ?? 8000),
  geoipDb: env.GEOIP_DB ?? './data/GeoLite2-City.mmdb',
  dashboardToken: env.DASHBOARD_TOKEN,
  ingestToken: env.INGEST_TOKEN,
  demoMode: env.DEMO_MODE === '1' || env.DEMO_MODE === 'true',
};

if (!config.databaseUrl) {
  throw new Error('DATABASE_URL is required');
}
if (!config.dashboardToken || config.dashboardToken.startsWith('change-me')) {
  console.warn('[config] DASHBOARD_TOKEN is not set to a real secret. Set one before deploying.');
}
