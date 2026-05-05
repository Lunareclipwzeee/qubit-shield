'use strict';

const crypto = require('crypto');
const { QubitEncrypt } = require('../crypto/eigen-encrypt');
const { QKDSession }   = require('../qkd/qkd-session');
const { QubitFactory } = require('../core/eigen-engine');
const { QuantumErrorCorrection } = require('../qec/steane-code');

class EigenLock {
  constructor(config = {}) {
    if (!config.apiKey) throw new Error('EigenLock: apiKey is required');
    if (!config.apiKey.startsWith('qs_')) throw new Error('EigenLock: invalid apiKey format');
    this._apiKey = config.apiKey;
    this._mode   = config.mode || 'hybrid';
    this._engine = new QubitEncrypt();
    this._masterKey = crypto.createHash('sha256').update(config.apiKey).update('qubit-shield-v1').digest();
    this._initialized = true;
    this._stats = { encrypted:0, decrypted:0, detected:0, errors:0 };
  }
  async encrypt(data) {
    this._checkInit();
    try {
      const envelope = await this._engine.encrypt(data);
      this._stats.encrypted++;
      return { ok:true, envelope, sessionId:envelope.sessionId };
    } catch(err) { this._stats.errors++; throw new Error(`EigenLock.encrypt: ${err.message}`); }
  }
  async decrypt(envelope) {
    this._checkInit();
    try {
      const result = await this._engine.decrypt(envelope, this._masterKey);
      this._stats.decrypted++;
      return { ok:true, ...result };
    } catch(err) { this._stats.errors++; throw new Error(`EigenLock.decrypt: ${err.message}`); }
  }
  async detect(envelope) {
    this._checkInit();
    try {
      const result = await this._engine.detect(envelope, this._masterKey);
      this._stats.detected++;
      return { ok:true, ...result };
    } catch(err) { this._stats.errors++; throw new Error(`EigenLock.detect: ${err.message}`); }
  }
  sign(data) { this._checkInit(); return this._engine.sign(data, this._masterKey); }
  verify(data, signature) { this._checkInit(); return this._engine.verify(data, signature, this._masterKey); }
  qubit() {
    return {
      zero:     () => QubitFactory.zero(),
      one:      () => QubitFactory.one(),
      plus:     () => QubitFactory.plus(),
      random:   () => QubitFactory.random(),
      bellPair: () => QubitFactory.bellPair(),
      register: (n) => QubitFactory.register(n),
      generateKey: (bits=256) => {
        const session = QKDSession.create();
        const key = session.consumeKey();
        session.destroy();
        return { key: key.toString('hex'), bits };
      },
      qec: {
        encode:  (buf) => QuantumErrorCorrection.encodeBuffer(buf),
        decode:  (blocks,len) => QuantumErrorCorrection.decodeBuffer(blocks,len),
        check:   (blocks,baseline) => QuantumErrorCorrection.verifyBaseline(blocks,baseline),
      }
    };
  }
  status() {
    return { ok:true, version:'1.0.0', mode:this._mode, engine:'EigenLock-v1',
      algorithms:['QKD-BB84','AES-256-GCM','STEANE-7-QEC','HMAC-SHA256'],
      stats:{...this._stats}, uptime:process.uptime(), timestamp:new Date().toISOString() };
  }
  _checkInit() { if (!this._initialized) throw new Error('EigenLock: not initialized'); }
}

module.exports = { EigenLock };
