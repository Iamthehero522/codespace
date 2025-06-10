// generateKeys.js
import { generateKeyPairSync } from 'crypto';
import { writeFileSync }       from 'fs';

// Generate a 2048‑bit RSA keypair, private key unencrypted
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type:   'spki',   // public key format
    format: 'pem'
  },
  privateKeyEncoding: {
    type:   'pkcs8',  // private key format
    format: 'pem'
    // <no cipher/passphrase here>
  }
});

// Save to disk
writeFileSync('private.pem', privateKey);
writeFileSync('public.pem',  publicKey);

console.log('✅ RSA keypair generated: private.pem & public.pem');
