// server/middleware/auth.js
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import { pool } from '../utils/db.js';

const PUBLIC_KEY = fs.readFileSync(
  path.resolve(process.env.PUBLIC_KEY_PATH),
  'utf8'
);

export async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    req.jwtId = decoded.jti;
    const result = await pool.query(
      'SELECT id, email, name FROM users WHERE id = $1',
      [decoded.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'User not found' });
    req.user = result.rows[0];
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}
