'use strict';
const crypto=require('crypto');
const monitoredObjects=new Map();
const alertStore=new Map();
setInterval(()=>{const now=Date.now();for(const[id,obj]of monitoredObjects)if(obj.expiresAt&&now>obj.expiresAt)monitoredObjects.delete(id);},5*60*1000).unref();
function computeSyndrome(data){const n=typeof data==='string'?data:JSON.stringify(data);return{sha256:crypto.createHash('sha256').update(n).digest('hex'),sha512:crypto.createHash('sha512').update(n).digest('hex'),length:n.length,checksum:n.split('').reduce((a,c)=>a+c.charCodeAt(0),0)%65536};}
function compareSyndromes(b,c){const m=[];if(b.sha256!==c.sha256)m.push('sha256_mismatch');if(b.sha512!==c.sha512)m.push('sha512_mismatch');if(b.length!==c.length)m.push('length_changed');if(b.checksum!==c.checksum)m.push('checksum_mismatch');const score=m.length/4;return{tampered:m.length>0,score:parseFloat(score.toFixed(4)),mismatches:m,confidence:m.length>=2?'high':m.length===1?'medium':'none'};}
class EigenSentinel{
  static monitor({objectId,data,label,apiKey,ttlSeconds=3600,alertThreshold=0.25}){
    if(!objectId)throw new Error('objectId is required');
    if(data===undefined)throw new Error('data is required');
    const syndrome=computeSyndrome(data);
    const now=Date.now(),expiresAt=now+(ttlSeconds*1000);
    const monitorId='qs_mon_'+crypto.randomBytes(8).toString('hex');
    const record={monitorId,objectId,label:label||objectId,apiKey,baseline:syndrome,alertThreshold,createdAt:now,expiresAt,lastScanned:now,scanCount:0,alertCount:0,status:'active'};
    monitoredObjects.set(objectId+':'+apiKey,record);
    return{monitorId,objectId,status:'monitoring',baseline:syndrome.sha256.substring(0,16)+'...',alertThreshold,expiresAt:new Date(expiresAt).toISOString(),message:`Sentinel is now watching "${label||objectId}"`};
  }
  static scan({objectId,currentData,apiKey}){
    if(!objectId)throw new Error('objectId is required');
    if(currentData===undefined)throw new Error('currentData is required');
    const key=objectId+':'+apiKey;
    const record=monitoredObjects.get(key);
    if(!record)return{scanned:false,reason:'Object not monitored',objectId};
    if(Date.now()>record.expiresAt){monitoredObjects.delete(key);return{scanned:false,reason:'Monitor expired',objectId};}
    const curr=computeSyndrome(currentData);
    const comp=compareSyndromes(record.baseline,curr);
    record.lastScanned=Date.now();record.scanCount++;
    let alert=null;
    if(comp.tampered&&comp.score>=record.alertThreshold){
      const alertId='qs_alert_'+crypto.randomBytes(8).toString('hex');
      alert={alertId,objectId,monitorId:record.monitorId,apiKey,score:comp.score,confidence:comp.confidence,mismatches:comp.mismatches,detectedAt:Date.now(),status:'open',label:record.label};
      alertStore.set(alertId,alert);record.alertCount++;
    }
    return{scanned:true,objectId,monitorId:record.monitorId,tampered:comp.tampered,score:comp.score,confidence:comp.confidence,mismatches:comp.mismatches,alert:alert?{alertId:alert.alertId,status:'ALERT_RAISED'}:null,scanCount:record.scanCount,scannedAt:new Date(record.lastScanned).toISOString(),reason:comp.tampered?`Tampering detected — ${comp.mismatches.join(', ')}`:'Data integrity verified'};
  }
  static getAlerts(apiKey,{status='all',limit=50}={}){
    const alerts=[];
    for(const a of alertStore.values()){if(a.apiKey!==apiKey)continue;if(status!=='all'&&a.status!==status)continue;alerts.push({alertId:a.alertId,objectId:a.objectId,label:a.label,score:a.score,confidence:a.confidence,mismatches:a.mismatches,status:a.status,detectedAt:new Date(a.detectedAt).toISOString()});}
    alerts.sort((a,b)=>new Date(b.detectedAt)-new Date(a.detectedAt));
    return{alerts:alerts.slice(0,limit),total:alerts.length,open:alerts.filter(a=>a.status==='open').length,resolved:alerts.filter(a=>a.status==='resolved').length};
  }
  static resolveAlert(alertId,apiKey,resolution='acknowledged'){
    const a=alertStore.get(alertId);
    if(!a)return{resolved:false,reason:'Alert not found'};
    if(a.apiKey!==apiKey)return{resolved:false,reason:'Unauthorized'};
    if(a.status==='resolved')return{resolved:false,reason:'Already resolved'};
    a.status='resolved';a.resolvedAt=Date.now();a.resolution=resolution;
    return{resolved:true,alertId,status:'resolved',resolution,resolvedAt:new Date(a.resolvedAt).toISOString()};
  }
  static listMonitored(apiKey){
    const objects=[];const now=Date.now();
    for(const r of monitoredObjects.values()){if(r.apiKey!==apiKey)continue;if(now>r.expiresAt)continue;objects.push({monitorId:r.monitorId,objectId:r.objectId,label:r.label,status:r.status,scanCount:r.scanCount,alertCount:r.alertCount,lastScanned:new Date(r.lastScanned).toISOString(),expiresAt:new Date(r.expiresAt).toISOString()});}
    return{monitored:objects,count:objects.length};
  }
  static stats(apiKey){
    let monitored=0,totalScans=0,openAlerts=0,resolvedAlerts=0;
    for(const r of monitoredObjects.values()){if(r.apiKey!==apiKey)continue;monitored++;totalScans+=r.scanCount;}
    for(const a of alertStore.values()){if(a.apiKey!==apiKey)continue;if(a.status==='open')openAlerts++;if(a.status==='resolved')resolvedAlerts++;}
    return{monitored,totalScans,openAlerts,resolvedAlerts,totalAlerts:openAlerts+resolvedAlerts};
  }
}
module.exports={EigenSentinel};
