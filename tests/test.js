'use strict';

const { Complex, QubitState, EntangledPair, QubitRegister, QubitFactory, Gates } = require('../src/core/eigen-engine');
const { QuantumErrorCorrection } = require('../src/qec/steane-code');
const { QKDSession }             = require('../src/qkd/qkd-session');
const { EigenLock }            = require('../src/sdk/index');

let passed = 0, failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch(e) { console.log(`  ✗  ${name}\n     → ${e.message}`); failed++; }
}

function assert(condition, msg) { if (!condition) throw new Error(msg || 'Assertion failed'); }
function assertClose(a, b, tol=0.0001) { if (Math.abs(a-b)>tol) throw new Error(`Expected ${a} ≈ ${b}`); }

console.log('\n═══════════════════════════════════════════');
console.log('  QUBIT SHIELD — TEST SUITE');
console.log('  LUNARECLIPSE · v1.0.0');
console.log('═══════════════════════════════════════════\n');

console.log('▸ Layer 1 — Complex Numbers');
test('Complex addition',          () => { const c=new Complex(1,2).add(new Complex(3,4)); assert(c.re===4&&c.im===6); });
test('Complex multiplication',    () => { const c=new Complex(1,2).mul(new Complex(3,4)); assert(c.re===-5&&c.im===10); });
test('Complex modulus squared',   () => assertClose(new Complex(3,4).mod2(),25));

console.log('\n▸ Layer 2 — Qubit States');
test('Qubit |0⟩ initialization',  () => { const q=QubitFactory.zero(); assertClose(q.prob0(),1.0); assertClose(q.prob1(),0.0); });
test('Qubit |1⟩ initialization',  () => { const q=QubitFactory.one();  assertClose(q.prob0(),0.0); assertClose(q.prob1(),1.0); });
test('Qubit normalization',        () => { const q=new QubitState(3,4); assertClose(q.prob0()+q.prob1(),1.0); });
test('Hadamard gate superposition',() => { const q=QubitFactory.zero(); q.applyGate(Gates.H); assertClose(q.prob0(),0.5); assertClose(q.prob1(),0.5); });
test('Pauli-X flips |0⟩ to |1⟩', () => { const q=QubitFactory.zero(); q.applyGate(Gates.X); assertClose(q.prob1(),1.0); });
test('Measurement collapses qubit',() => { const q=QubitFactory.plus(); const r=q.measure(); assert(r===0||r===1); assert(q.collapsed===true); });
test('Collapsed qubit consistent', () => { const q=QubitFactory.zero(); assert(q.measure()===q.measure()); });
test('Observer effect detected',   () => { const q=QubitFactory.plus(); q.measure('attacker'); assert(q.detectTamper(['system']).tampered===true); });
test('Authorized access clean',    () => { const q=QubitFactory.plus(); q.measure('system');  assert(q.detectTamper(['system']).tampered===false); });

console.log('\n▸ Layer 3 — Quantum Gates');
test('Hadamard self-inverse',      () => { const q=QubitFactory.zero(); q.applyGate(Gates.H); q.applyGate(Gates.H); assertClose(q.prob0(),1.0); });
test('X gate self-inverse',        () => { const q=QubitFactory.zero(); q.applyGate(Gates.X); q.applyGate(Gates.X); assertClose(q.prob0(),1.0); });
test('Random qubit valid probs',   () => { const rq=QubitFactory.random(); assertClose(rq.prob0()+rq.prob1(),1.0,0.001); });

console.log('\n▸ Layer 4 — Entanglement');
test('Bell pair created',          () => assert(QubitFactory.bellPair().entangled===true));
test('Measuring A collapses B',    () => { const p=QubitFactory.bellPair(); p.measureA('system'); assert(p.entangled===false); });
test('Tamper on pair detected',    () => { const p=QubitFactory.bellPair(); p.qubitA.measure('hacker'); assert(p.detectTamper(['system']).tampered===true); });

console.log('\n▸ Layer 5 — Qubit Register');
test('Register creates N qubits',  () => { const r=QubitFactory.register(64); assert(r.n===64); });
test('Register derives 256-bit key',()=> { const k=QubitFactory.register(256).deriveKey(256); assert(k.length===32); });
test('Two keys are different',     () => { const k1=QubitFactory.register(256).deriveKey(256); const k2=QubitFactory.register(256).deriveKey(256); assert(k1.toString('hex')!==k2.toString('hex')); });

console.log('\n▸ Layer 6 — Quantum Error Correction');
test('Encode bit 0',               () => { const cw=QuantumErrorCorrection.encodeBit(0); assert(cw.length===7); });
test('Encode bit 1',               () => { const cw=QuantumErrorCorrection.encodeBit(1); assert(cw.length===7); });
test('Syndrome of valid codeword', () => assert(QuantumErrorCorrection.syndrome(QuantumErrorCorrection.encodeBit(0)).every(s=>s===0)));
test('Single error detected',      () => assert(QuantumErrorCorrection.syndrome(QuantumErrorCorrection.simulateError(QuantumErrorCorrection.encodeBit(1),2)).some(s=>s!==0)));
test('Single error corrected',     () => { const cw=QuantumErrorCorrection.encodeBit(1); const err=QuantumErrorCorrection.simulateError(cw,3); const {bit}=QuantumErrorCorrection.decodeBit(err); assert(bit===1); });
test('Buffer round-trip',          () => { const buf=Buffer.from('QUBIT SHIELD'); const b=QuantumErrorCorrection.encodeBuffer(buf); const {buffer}=QuantumErrorCorrection.decodeBuffer(b,buf.length); assert(buffer.toString()==='QUBIT SHIELD'); });
test('Tamper detection baseline',  () => { const buf=Buffer.from('secure'); const b=QuantumErrorCorrection.encodeBuffer(buf); const base=QuantumErrorCorrection.generateBaseline(b); const t=b.map(x=>[...x]); t[0][2]^=1; assert(QuantumErrorCorrection.verifyBaseline(t,base).valid===false); });

console.log('\n▸ Layer 7 — QKD');
test('QKD unique session IDs',     () => { const s1=QKDSession.create(),s2=QKDSession.create(); assert(s1.id!==s2.id); s1.destroy();s2.destroy(); });
test('QKD 256-bit key',            () => { const s=QKDSession.create(); assert(s.consumeKey().length===32); s.destroy(); });
test('QKD no-reuse',               () => { const s=QKDSession.create(); s.consumeKey(); let t=false; try{s.consumeKey();}catch{t=true;} assert(t); s.destroy(); });
test('Two QKD keys different',     () => { const s1=QKDSession.create(),s2=QKDSession.create(); assert(s1.consumeKey().toString('hex')!==s2.consumeKey().toString('hex')); s1.destroy();s2.destroy(); });

console.log('\n▸ Layer 8 — Public SDK');
const qs = new EigenLock({ apiKey:'qs_test_lunareclipse2026' });
test('SDK initializes',            () => assert(qs.status().ok===true));
test('SDK rejects bad key',        () => { let t=false; try{new EigenLock({apiKey:'bad'});}catch{t=true;} assert(t); });
test('Sign and verify',            () => { const {signature}=qs.sign('hello'); assert(qs.verify('hello',signature).valid===true); });
test('Verify rejects tamper',      () => { const {signature}=qs.sign('original'); assert(qs.verify('tampered',signature).valid===false); });
test('Raw quantum key',            () => { const {key,bits}=qs.qubit().generateKey(256); assert(key.length===64&&bits===256); });

Promise.resolve().then(async () => {
  console.log('\n▸ Async SDK Tests');
  const asyncTests = [
    ['Encrypt returns envelope',    async()=>{ const {ok,envelope}=await qs.encrypt('Hello QUBIT Shield'); assert(ok&&envelope.sessionId.startsWith('qs_sess_')); }],
    ['Encrypt → Decrypt',          async()=>{ const {envelope}=await qs.encrypt('LUNARECLIPSE'); const {text}=await qs.decrypt(envelope); assert(text==='LUNARECLIPSE'); }],
    ['Binary encrypt → decrypt',   async()=>{ const buf=Buffer.from([0xDE,0xAD,0xBE,0xEF]); const {envelope}=await qs.encrypt(buf); const {plaintext}=await qs.decrypt(envelope); assert(buf.equals(plaintext)); }],
    ['Detect clean envelope',      async()=>{ const {envelope}=await qs.encrypt('clean'); const {tampered}=await qs.detect(envelope); assert(tampered===false); }],
    ['Detect tampered envelope',   async()=>{ const {envelope}=await qs.encrypt('data'); envelope.ciphertext=Buffer.from('forged').toString('base64'); const {tampered}=await qs.detect(envelope); assert(tampered===true); }],
  ];
  for (const [name,fn] of asyncTests) {
    try { await fn(); console.log(`  ✓  ${name}`); passed++; }
    catch(e) { console.log(`  ✗  ${name}\n     → ${e.message}`); failed++; }
  }
  console.log('\n═══════════════════════════════════════════');
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log(failed===0 ? '  Status:  ALL TESTS PASSED ✓\n  Engine:  QUBIT SHIELD OPERATIONAL' : '  Status:  SOME TESTS FAILED ✗');
  console.log('═══════════════════════════════════════════\n');
});
