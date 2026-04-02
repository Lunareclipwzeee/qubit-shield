import { pqcEncrypt, pqcDecrypt, pqcDetect } from './src/pqc-engine.mjs';

console.log('Testing real ML-KEM-768 + AES-256-GCM...\n');

const message = 'LUNARECLIPSE — QUBIT Shield post-quantum encryption test';

// Encrypt
const result = await pqcEncrypt(message);
console.log('Algorithm:', result.algorithm);
console.log('Standard:', result.standard);
console.log('ML-KEM public key size:', result.keySize, 'bytes');
console.log('KEM ciphertext size:', result.cipherSize, 'bytes');
console.log('Encrypted ✅\n');

// Decrypt
const decrypted = await pqcDecrypt(result.envelope);
console.log('Decrypted:', decrypted);
console.log('Match:', decrypted === message ? 'PASSED ✅' : 'FAILED ❌');
console.log('');

// Detect — clean
const clean = await pqcDetect(result.envelope);
console.log('Integrity check (clean):', clean.tampered ? 'TAMPERED ❌' : 'CLEAN ✅');

// Detect — tampered
const tampered = { ...result.envelope, ciphertext: 'dGFtcGVyZWQ=' };
const tResult = await pqcDetect(tampered);
console.log('Integrity check (tampered):', tResult.tampered ? 'TAMPERED DETECTED ✅' : 'MISSED ❌');
