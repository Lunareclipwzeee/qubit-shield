'use strict';

const crypto = require('crypto');
const { EigenFactory, Gates } = require('../core/eigen-engine');

const BASIS = { RECTILINEAR: 'rectilinear', DIAGONAL: 'diagonal' };

class QKDSession {
  constructor() {
    this.id = 'qs_sess_' + crypto.randomBytes(12).toString('hex');
    this.createdAt = Date.now();
    this._key = null; this._keyUsed = false; this._destroyed = false;
    this._basisSequence = []; this._qubitResults = [];
  }
  generate(bits = 256) {
    if (this._destroyed) throw new Error('QKD: Session destroyed');
    if (this._key) throw new Error('QKD: Key already generated');
    const oversample = bits * 3;
    const senderBases = [], preparedStates = [];
    for (let i = 0; i < oversample; i++) {
      const basis = this._randomBasis(), bitValue = this._randomBit();
      senderBases.push(basis);
      const q = EigenFactory.zero();
      if (bitValue === 1) q.applyGate(Gates.X);
      if (basis === BASIS.DIAGONAL) q.applyGate(Gates.H);
      preparedStates.push({ qubit: q, bit: bitValue, basis });
    }
    const receiverBases = [], receivedBits = [];
    for (let i = 0; i < oversample; i++) {
      const measureBasis = this._randomBasis();
      receiverBases.push(measureBasis);
      const { qubit } = preparedStates[i];
      if (measureBasis === BASIS.DIAGONAL) qubit.applyGate(Gates.H);
      receivedBits.push(qubit.measure('qkd-receiver'));
    }
    const siftedBits = [];
    for (let i = 0; i < oversample; i++) {
      if (senderBases[i] === receiverBases[i]) siftedBits.push(receivedBits[i]);
      if (siftedBits.length >= bits) break;
    }
    if (siftedBits.length < bits) throw new Error(`QKD: Insufficient sifted bits (got ${siftedBits.length})`);
    const keyBytes = [];
    for (let i = 0; i < bits; i += 8) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte |= ((siftedBits[i+b]||0) << (7-b));
      keyBytes.push(byte);
    }
    this._key = crypto.createHash('sha256').update(Buffer.from(keyBytes)).digest();
    this._qubitResults = siftedBits.slice(0, bits);
    return this;
  }
  consumeKey() {
    if (this._destroyed) throw new Error('QKD: Session destroyed');
    if (!this._key) throw new Error('QKD: No key generated');
    if (this._keyUsed) throw new Error('QKD: Key already consumed');
    const key = Buffer.from(this._key);
    this._keyUsed = true; this._key.fill(0); this._key = null;
    return key;
  }
  keyCommitment() {
    if (!this._key) throw new Error('QKD: No key generated');
    return crypto.createHash('sha256').update(this._key).digest('hex');
  }
  destroy() {
    if (this._key) this._key.fill(0);
    this._key = null; this._basisSequence = []; this._qubitResults = []; this._destroyed = true;
  }
  info() {
    return { id: this.id, createdAt: this.createdAt, age: Date.now()-this.createdAt,
      keyGenerated: !!this._key||this._keyUsed, keyUsed: this._keyUsed, destroyed: this._destroyed };
  }
  _randomBasis() { return crypto.randomBytes(1)[0]%2===0 ? BASIS.RECTILINEAR : BASIS.DIAGONAL; }
  _randomBit()   { return crypto.randomBytes(1)[0]%2; }
  static create() { return new QKDSession().generate(256); }
}

class SessionStore {
  constructor() { this._sessions = new Map(); this._maxAge = 30*60*1000; this._startCleanup(); }
  store(session) {
    this._sessions.set(session.id, { commitment: session.keyCommitment(), info: session.info(), storedAt: Date.now() });
    return session.id;
  }
  verify(sessionId, commitment) {
    const stored = this._sessions.get(sessionId);
    if (!stored) return { valid: false, reason: 'Session not found' };
    if (Date.now()-stored.storedAt > this._maxAge) return { valid: false, reason: 'Session expired' };
    if (stored.commitment !== commitment) return { valid: false, reason: 'Commitment mismatch' };
    return { valid: true };
  }
  invalidate(sessionId) { this._sessions.delete(sessionId); }
  _startCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [id,s] of this._sessions) if (now-s.storedAt > this._maxAge) this._sessions.delete(id);
    }, 5*60*1000).unref();
  }
}

module.exports = { QKDSession, SessionStore, BASIS };
