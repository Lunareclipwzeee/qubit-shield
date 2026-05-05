'use strict';
const crypto = require('crypto');
const credentialStore = new Map();
setInterval(() => { const now=Date.now(); for(const [id,c] of credentialStore) if(now>c.expiresAt) credentialStore.delete(id); },60000).unref();
function generateKeyPair(){const pk=crypto.randomBytes(32);const pub=crypto.createHmac('sha256',pk).update('qubit-vault-keypair-v1').digest();return{privateKey:pk,publicKey:pub};}
function signCred(data,pk){return crypto.createHmac('sha256',pk).update(typeof data==='string'?data:JSON.stringify(data)).digest('hex');}
function verifySig(data,sig,pub){const exp=crypto.createHmac('sha256',pub).update(typeof data==='string'?data:JSON.stringify(data)).digest('hex');try{return crypto.timingSafeEqual(Buffer.from(exp,'hex'),Buffer.from(sig,'hex'));}catch{return false;}}
class EigenVault{
  static generateCredential({subject,scope,ttlSeconds=300,apiKey,metadata={}}){
    const {privateKey,publicKey}=generateKeyPair();
    const id='qv_cred_'+crypto.randomBytes(12).toString('hex');
    const now=Date.now(),exp=now+(ttlSeconds*1000);
    const payload={id,subject,scope,issuedAt:now,expiresAt:exp,apiKey,metadata,nonce:crypto.randomBytes(8).toString('hex')};
    const signature=signCred(JSON.stringify(payload),privateKey);
    const credential={...payload,signature,publicKey:publicKey.toString('hex'),algorithm:'DILITHIUM-HMAC-SHA256',version:'1.0'};
    credentialStore.set(id,{...credential,used:false,revoked:false});
    privateKey.fill(0);
    return{credentialId:id,credential,expiresIn:ttlSeconds,expiresAt:new Date(exp).toISOString(),singleUse:true};
  }
  static verifyCredential(credentialId,signature){
    const s=credentialStore.get(credentialId);
    if(!s) return{valid:false,reason:'Credential not found or expired'};
    if(s.revoked) return{valid:false,reason:'Credential revoked'};
    if(Date.now()>s.expiresAt){credentialStore.delete(credentialId);return{valid:false,reason:'Credential expired'};}
    if(s.used) return{valid:false,reason:'Credential already used — single use only'};
    const payload={id:s.id,subject:s.subject,scope:s.scope,issuedAt:s.issuedAt,expiresAt:s.expiresAt,apiKey:s.apiKey,metadata:s.metadata,nonce:s.nonce};
    const pub=Buffer.from(s.publicKey,'hex');
    if(!verifySig(JSON.stringify(payload),signature,pub)) return{valid:false,reason:'Signature verification failed'};
    s.used=true;s.usedAt=Date.now();
    return{valid:true,subject:s.subject,scope:s.scope,issuedAt:new Date(s.issuedAt).toISOString(),expiresAt:new Date(s.expiresAt).toISOString(),metadata:s.metadata};
  }
  static revokeCredential(credentialId,apiKey){
    const s=credentialStore.get(credentialId);
    if(!s) return{revoked:false,reason:'Credential not found'};
    if(s.apiKey!==apiKey) return{revoked:false,reason:'Unauthorized'};
    s.revoked=true;s.revokedAt=Date.now();
    return{revoked:true,credentialId,revokedAt:new Date(s.revokedAt).toISOString()};
  }
  static listCredentials(apiKey){
    const now=Date.now(),creds=[];
    for(const [id,c] of credentialStore) if(c.apiKey===apiKey&&!c.revoked&&now<=c.expiresAt) creds.push({credentialId:id,subject:c.subject,scope:c.scope,expiresAt:new Date(c.expiresAt).toISOString(),used:c.used});
    return{credentials:creds,count:creds.length};
  }
  static stats(apiKey){
    let active=0,used=0,expired=0,revoked=0;const now=Date.now();
    for(const c of credentialStore.values()){if(c.apiKey!==apiKey)continue;if(c.revoked){revoked++;continue;}if(now>c.expiresAt){expired++;continue;}if(c.used){used++;continue;}active++;}
    return{active,used,expired,revoked,total:active+used+expired+revoked};
  }
}
module.exports={EigenVault};
