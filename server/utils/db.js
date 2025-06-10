// server/utils/db.js
import pkg from 'pg';
const { Pool } = pkg;

export const pool = new Pool({
  connectionString: 'postgresql://securedrive_user:4YToNdsiPz68V6dv4pYWIrOTLDoK4a1T@dpg-d0o5obali9vc73fn60lg-a.oregon-postgres.render.com/securedrive_6chh?ssl=true',
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});
