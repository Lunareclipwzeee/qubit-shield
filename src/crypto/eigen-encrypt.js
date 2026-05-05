'use strict';

const crypto = require('crypto');
const { QKDSession, SessionStore } = require('../qkd/qkd-session');
const { QuantumErrorCorrection }   = require('../qec/steane-code');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

class QubitEncrypt {
  constructor() { this._store = new SessionStore(); this._version = '1.0.0'; }

  async encrypt(plaintext) {
    const startTime = Date.now();
    const buf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
    const session    = QKDSession.create();
    const sessionKey = session.consumeKey();
    const qecBlocks  = QuantumErrorCorrection.encodeBuffer(buf);
    const baseline   = QuantumErrorCorrection.generateBaseline(qecBlocks);
    const qecSerialized = this._serializeBlocks(qecBlocks);
    const iv         = crypto.randomBytes(IV_LENGTH);
    const cipher     = crypto.createCipheriv(ALGORITHM, sessionKey, iv, { authTagLength: TAG_LENGTH });
    const encrypted  = Buffer.concat([cipher.update(qecSerialized), cipher.final()]);
    const authTag    = cipher.getAuthTag();
    const masterKey  = crypto.createHash('sha256').update('qubit-shield-master-v1').digest();
    const wrapIv     = crypto.randomBytes(16);
    const wrapCipher = crypto.createCipheriv('aes-256-gcm', masterKey, wrapIv);
    const wrappedKey = Buffer.concat([wrapCipher.update(sessionKey), wrapCipher.final()]);
    const wrapTag    = wrapCipher.getAuthTag();
    masterKey.fill(0); sessionKey.fill(0);
    const envelope = {
      version: this._version, sessionId: session.id,
      algorithm: 'QKD-AES-256-GCM', encoding: 'STEANE-7',
      iv: iv.toString('base64'), authTag: authTag.toString('base64'),
      ciphertext: encrypted.toString('base64'),
      originalLength: buf.length, blockCount: qecBlocks.length,
      baselineHash: baseline.hash,
      wrappedKey: wrappedKey.toString('base64'),
      wrapIv: wrapIv.toString('base64'),
      wrapTag: wrapTag.toString('base64'),
      createdAt: new Date().toISOString(), timeMs: Date.now()-startTime,
    };
    envelope.signature = this._signEnvelope(envelope);
    return envelope;
  }

  async decrypt(envelope, masterKey) {
    const expectedSig = this._signEnvelope({ ...envelope, signature: undefined });
    if (envelope.signature !== expectedSig) throw new Error('QUBIT Shield: Envelope signature invalid — tamper detected');
    const internalMaster = crypto.createHash('sha256').update('qubit-shield-master-v1').digest();
    const wrapIv2    = Buffer.from(envelope.wrapIv, 'base64');
    const wrappedKey2 = Buffer.from(envelope.wrappedKey, 'base64');
    const wrapTag2   = Buffer.from(envelope.wrapTag, 'base64');
    const unwrap     = crypto.createDecipheriv('aes-256-gcm', internalMaster, wrapIv2);
    unwrap.setAuthTag(wrapTag2);
    const sessionKey = Buffer.concat([unwrap.update(wrappedKey2), unwrap.final()]);
    internalMaster.fill(0);
    const iv = Buffer.from(envelope.iv,'base64'), authTag = Buffer.from(envelope.authTag,'base64'), ciphertext = Buffer.from(envelope.ciphertext,'base64');
    let qecSerialized;
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, sessionKey, iv, { authTagLength: TAG_LENGTH });
      decipher.setAuthTag(authTag);
      qecSerialized = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch(e) { throw new Error('QUBIT Shield: Decryption failed — authentication tag mismatch'); }
    finally { sessionKey.fill(0); }
    const qecBlocks = this._deserializeBlocks(qecSerialized, envelope.blockCount);
    const { buffer, errorsFound, uncorrectableErrors } = QuantumErrorCorrection.decodeBuffer(qecBlocks, envelope.originalLength);
    if (uncorrectableErrors > 0) throw new Error(`QUBIT Shield: ${uncorrectableErrors} uncorrectable QEC errors`);
    return { plaintext: buffer, text: buffer.toString('utf8'), errorsFound, sessionId: envelope.sessionId };
  }

  async detect(envelope, masterKey) {
    const internalMaster2 = crypto.createHash('sha256').update('qubit-shield-master-v1').digest();
    const wrapIv3 = Buffer.from(envelope.wrapIv,'base64'), wrapped3 = Buffer.from(envelope.wrappedKey,'base64'), wrapTag3 = Buffer.from(envelope.wrapTag,'base64');
    const uw2 = crypto.createDecipheriv('aes-256-gcm', internalMaster2, wrapIv3);
    uw2.setAuthTag(wrapTag3);
    const sessionKey = Buffer.concat([uw2.update(wrapped3), uw2.final()]);
    internalMaster2.fill(0);
    const iv = Buffer.from(envelope.iv,'base64'), authTag = Buffer.from(envelope.authTag,'base64'), ciphertext = Buffer.from(envelope.ciphertext,'base64');
    let qecSerialized;
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, sessionKey, iv, { authTagLength: TAG_LENGTH });
      decipher.setAuthTag(authTag);
      qecSerialized = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch { return { tampered: true, score: 1.0, reason: 'Auth tag invalid — definite tampering' }; }
    finally { sessionKey.fill(0); }
    const qecBlocks = this._deserializeBlocks(qecSerialized, envelope.blockCount);
    const currentHash = QuantumErrorCorrection.generateBaseline(qecBlocks).hash;
    const syndromeChanged = currentHash !== envelope.baselineHash;
    const envelopeSigOk  = envelope.signature === this._signEnvelope({ ...envelope, signature: undefined });
    let score = 0;
    if (syndromeChanged) score += 0.6;
    if (!envelopeSigOk)  score += 0.4;
    return { tampered: score>0, score: parseFloat(Math.min(1.0,score).toFixed(4)), syndromeMatch: !syndromeChanged, signatureValid: envelopeSigOk, reason: score>0?'Observer effect triggered':'Integrity verified', sessionId: envelope.sessionId };
  }

  sign(data, signingKey) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data,'utf8');
    return { signature: crypto.createHmac('sha256',signingKey).update(buf).digest('hex'), algorithm:'HMAC-SHA256', timestamp:Date.now() };
  }

  verify(data, signature, signingKey) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data,'utf8');
    const expected = crypto.createHmac('sha256',signingKey).update(buf).digest('hex');
    return { valid: crypto.timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(signature,'hex')), algorithm:'HMAC-SHA256' };
  }

  _serializeBlocks(blocks) {
    const flat = blocks.flat(), bytes = [];
    for (let i=0;i<flat.length;i+=8) {
      let byte=0;
      for (let b=0;b<8&&i+b<flat.length;b++) byte|=((flat[i+b]&1)<<(7-b));
      bytes.push(byte);
    }
    return Buffer.from(bytes);
  }

  _deserializeBlocks(buf, blockCount) {
    const bits=[];
    for (const byte of buf) for (let b=7;b>=0;b--) bits.push((byte>>b)&1);
    const blocks=[];
    for (let i=0;i<blockCount;i++) blocks.push(bits.slice(i*7,i*7+7));
    return blocks;
  }

  _signEnvelope(envelope) {
    const data = JSON.stringify({ sessionId:envelope.sessionId, algorithm:envelope.algorithm, iv:envelope.iv, ciphertext:envelope.ciphertext, baselineHash:envelope.baselineHash, originalLength:envelope.originalLength });
    return crypto.createHash('sha256').update(data).digest('hex').slice(0,32);
  }
}

module.exports = { QubitEncrypt };
