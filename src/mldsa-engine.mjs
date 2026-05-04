import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from 'crypto';

export async function mldsaSign(message) {
  const msgBytes = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const seed = new Uint8Array(randomBytes(32));
  const keys = ml_dsa65.keygen(seed);
  const signature = ml_dsa65.sign(keys.secretKey, msgBytes);
  return {
    signature: Buffer.from(signature).toString('base64'),
    publicKey: Buffer.from(keys.publicKey).toString('base64'),
    algorithm: 'ML-DSA-65',
    standard: 'NIST FIPS 204',
    keySize: keys.publicKey.length,
    sigSize: signature.length
  };
}

export async function mldsaVerify(message, signatureB64, publicKeyB64) {
  const msgBytes = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const signature = Buffer.from(signatureB64, 'base64');
  const publicKey = Buffer.from(publicKeyB64, 'base64');
  const valid = ml_dsa65.verify(publicKey, msgBytes, signature);
  return { valid, algorithm: 'ML-DSA-65', standard: 'NIST FIPS 204' };
}
