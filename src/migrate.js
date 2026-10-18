import { readFile } from 'node:fs/promises';
import { pool } from './db.js';

export async function migrate() {
  const sql = await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8');
  await pool.query(sql);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await migrate();
  console.log('[migrate] schema is up to date');
  await pool.end();
}
