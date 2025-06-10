// createServiceToken.js
import fs   from 'fs';
import jwt  from 'jsonwebtoken';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config(); // loads PRIVATE_KEY_PATH, etc.

// Load your RSA private key
const privateKey = fs.readFileSync(
  path.resolve(process.env.PRIVATE_KEY_PATH),
  'utf8'
);

// Your “service” payload (use any  UUID you like)
const payload = {
  id:    '00000000-0000-0000-0000-000000000000',
  name:  'drive-service',
  email: 'service@localhost'
};

// Sign with RS256:
const token = jwt.sign(
  payload,
  privateKey,
  {
    algorithm: 'RS256',
    expiresIn: '365d'
  }
);

console.log('\nDRIVE_JWT_RS256=', token, '\n');
