'use strict';

const crypto = require('crypto');

class Complex {
  constructor(re, im = 0) { this.re = re; this.im = im; }
  add(c) { return new Complex(this.re + c.re, this.im + c.im); }
  mul(c) { return new Complex(this.re * c.re - this.im * c.im, this.re * c.im + this.im * c.re); }
  scale(s) { return new Complex(this.re * s, this.im * s); }
  conjugate() { return new Complex(this.re, -this.im); }
  mod2() { return this.re * this.re + this.im * this.im; }
  mod() { return Math.sqrt(this.mod2()); }
}

class QubitState {
  constructor(alpha, beta) {
    this.alpha = alpha instanceof Complex ? alpha : new Complex(alpha);
    this.beta  = beta  instanceof Complex ? beta  : new Complex(beta);
    this._normalize();
    this._collapsed = false; this._collapseVal = null;
    this._observerLog = []; this._id = crypto.randomBytes(8).toString('hex');
  }
  _normalize() {
    const norm = Math.sqrt(this.alpha.mod2() + this.beta.mod2());
    if (norm === 0) throw new Error('QubitState: zero norm');
    this.alpha = this.alpha.scale(1/norm); this.beta = this.beta.scale(1/norm);
  }
  prob0() { return this.alpha.mod2(); }
  prob1() { return this.beta.mod2(); }
  measure(caller = 'system') {
    if (this._collapsed) { this._logObserver(caller, 'remeasure'); return this._collapseVal; }
    const rand = crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF;
    const result = rand < this.prob0() ? 0 : 1;
    if (result === 0) { this.alpha = new Complex(1); this.beta = new Complex(0); }
    else { this.alpha = new Complex(0); this.beta = new Complex(1); }
    this._collapsed = true; this._collapseVal = result;
    this._logObserver(caller, 'measurement');
    return result;
  }
  applyGate(gate) {
    if (this._collapsed) throw new Error('Cannot apply gate to collapsed qubit');
    const newAlpha = gate[0][0].mul(this.alpha).add(gate[0][1].mul(this.beta));
    const newBeta  = gate[1][0].mul(this.alpha).add(gate[1][1].mul(this.beta));
    this.alpha = newAlpha; this.beta = newBeta; this._normalize(); return this;
  }
  _logObserver(caller, action) {
    this._observerLog.push({ caller, action, timestamp: Date.now() });
  }
  detectTamper(authorizedCallers = ['system']) {
    const unauthorized = this._observerLog.filter(e => !authorizedCallers.includes(e.caller));
    return { tampered: unauthorized.length > 0, events: unauthorized, score: Math.min(1.0, unauthorized.length * 0.35) };
  }
  get id() { return this._id; }
  get collapsed() { return this._collapsed; }
}

const Gates = {
  H: [[new Complex(1/Math.SQRT2), new Complex(1/Math.SQRT2)],[new Complex(1/Math.SQRT2), new Complex(-1/Math.SQRT2)]],
  X: [[new Complex(0), new Complex(1)],[new Complex(1), new Complex(0)]],
  Z: [[new Complex(1), new Complex(0)],[new Complex(0), new Complex(-1)]],
  Y: [[new Complex(0), new Complex(0,-1)],[new Complex(0,1), new Complex(0)]],
  S: [[new Complex(1), new Complex(0)],[new Complex(0), new Complex(0,1)]],
  T: [[new Complex(1), new Complex(0)],[new Complex(0), new Complex(Math.cos(Math.PI/4), Math.sin(Math.PI/4))]],
  Rz: (theta) => [[new Complex(Math.cos(theta/2),-Math.sin(theta/2)), new Complex(0)],[new Complex(0), new Complex(Math.cos(theta/2), Math.sin(theta/2))]]
};

class EntangledPair {
  constructor() {
    this.qubitA = new QubitState(1,0); this.qubitB = new QubitState(1,0);
    this.qubitA.applyGate(Gates.H);
    this._entangled = true; this._id = crypto.randomBytes(8).toString('hex'); this._correlation = 1;
  }
  measureA(caller = 'system') {
    if (!this._entangled) return this.qubitA.measure(caller);
    const resultA = this.qubitA.measure(caller);
    this.qubitB.alpha = resultA === 0 ? new Complex(1) : new Complex(0);
    this.qubitB.beta  = resultA === 0 ? new Complex(0) : new Complex(1);
    this.qubitB._collapsed = true; this.qubitB._collapseVal = resultA;
    this._entangled = false; return resultA;
  }
  measureB(caller = 'system') {
    if (!this._entangled) return this.qubitB.measure(caller);
    const resultB = this.qubitB.measure(caller);
    this.qubitA.alpha = resultB === 0 ? new Complex(1) : new Complex(0);
    this.qubitA.beta  = resultB === 0 ? new Complex(0) : new Complex(1);
    this.qubitA._collapsed = true; this.qubitA._collapseVal = resultB;
    this._entangled = false; return resultB;
  }
  detectTamper(authorizedCallers = ['system']) {
    const a = this.qubitA.detectTamper(authorizedCallers);
    const b = this.qubitB.detectTamper(authorizedCallers);
    return { tampered: a.tampered || b.tampered, qubitA: a, qubitB: b, score: Math.max(a.score, b.score) };
  }
  get id() { return this._id; }
  get entangled() { return this._entangled; }
}

class QubitRegister {
  constructor(n) {
    if (n < 1 || n > 4096) throw new Error('Register size must be 1-4096');
    this.n = n; this.qubits = []; this._id = crypto.randomBytes(8).toString('hex');
    for (let i = 0; i < n; i++) this.qubits.push(new QubitState(1,0));
  }
  superpose() { for (const q of this.qubits) if (!q.collapsed) q.applyGate(Gates.H); return this; }
  randomRotate() {
    for (const q of this.qubits) {
      if (!q.collapsed) {
        const theta = (crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF) * 2 * Math.PI;
        q.applyGate(Gates.Rz(theta));
      }
    }
    return this;
  }
  deriveKey(bits = 256, caller = 'system') {
    if (bits > this.n) throw new Error(`Register has only ${this.n} qubits`);
    this.superpose(); this.randomRotate();
    const measurements = [];
    for (let i = 0; i < bits; i++) measurements.push(this.qubits[i].measure(caller));
    const bytes = [];
    for (let i = 0; i < bits; i += 8) {
      let byte = 0;
      for (let b = 0; b < 8 && i+b < bits; b++) byte |= (measurements[i+b] << (7-b));
      bytes.push(byte);
    }
    return Buffer.from(bytes);
  }
  detectTamper(authorizedCallers = ['system']) {
    let totalScore = 0, tamperedCount = 0, events = [];
    for (const q of this.qubits) {
      const r = q.detectTamper(authorizedCallers);
      if (r.tampered) { tamperedCount++; totalScore += r.score; events.push(...r.events); }
    }
    return { tampered: tamperedCount > 0, tamperedQubits: tamperedCount, totalQubits: this.n, score: Math.min(1.0, totalScore / Math.max(1, this.n)), events };
  }
  get id() { return this._id; }
}

class QubitFactory {
  static zero()  { return new QubitState(1,0); }
  static one()   { return new QubitState(0,1); }
  static plus()  { const q = new QubitState(1,0); q.applyGate(Gates.H); return q; }
  static minus() { const q = new QubitState(1,0); q.applyGate(Gates.X); q.applyGate(Gates.H); return q; }
  static random() {
    const buf = crypto.randomBytes(8);
    const phi = (buf.readUInt32BE(0)/0xFFFFFFFF) * Math.PI;
    const theta = (buf.readUInt32BE(4)/0xFFFFFFFF) * 2 * Math.PI;
    return new QubitState(new Complex(Math.cos(phi/2),0), new Complex(Math.sin(phi/2)*Math.cos(theta), Math.sin(phi/2)*Math.sin(theta)));
  }
  static bellPair() { return new EntangledPair(); }
  static register(n) { return new QubitRegister(n); }
}

module.exports = { Complex, QubitState, EntangledPair, QubitRegister, QubitFactory, Gates };
