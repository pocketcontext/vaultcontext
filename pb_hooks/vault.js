// All domain writes execute inside a single transaction. Action bodies never persist.
function action(e) {
 if(!e.auth || e.auth.collection().name!=='users' || e.auth.getBool('disabled')) throw new ForbiddenError('Ordinary active user required.');
 const actor=e.auth.id, op=e.record.getString('op');
 let p;try {p=JSON.parse(e.record.getString('payload'));} catch(_) {throw new BadRequestError('Invalid payload JSON.');}
 if(!p || typeof p!=='object' || Array.isArray(p)) throw new BadRequestError('Object payload required.');
 let result;const refusal={};
 // Lock refusals roll back the transaction, then return structured details that
 // PocketBase's generic ApiError data sanitizer would otherwise remove.
 try {e.app.runInTransaction(app=>{result=execute(app,actor,op,p,refusal);});}
 catch(err) {if(refusal.body)return e.json(refusal.status,refusal.body);throw err;}
 return e.json(200,{result});
}
const LOCK_ALPHABET='abcdefghijklmnopqrstuvwxyz0123456789';
function execute(app,actor,op,p,refusal) {
 if(app.findRecordById('users',actor).getBool('disabled')) throw new ForbiddenError('Account disabled.');
 const bad=message=>{throw new BadRequestError(message);};
 const denied=()=>{throw new ForbiddenError('Vault operation not permitted.');};
 const refuse=(status,code,message,data)=>{refusal.status=status;refusal.body={status,message,data:Object.assign({code},data||{})};throw new Error('Vault action refused.');};
 const conflict=()=>refuse(409,'revision_conflict','Revision conflict; refresh state.');
 const str=(name,max=65536)=>{const v=p[name];if(typeof v!=='string'||!v.length||v.length>max)bad('Invalid '+name);return v;};
 const validId=v=>typeof v==='string'&&/^[a-z0-9]{15}$/.test(v);
 const id=name=>{if(!validId(p[name]))bad('Invalid '+name);return p[name];};
 const rows=(table,filter,params)=>app.findRecordsByFilter(table,filter,'',0,0,params||{});
 const get=(table,key)=>{try{return app.findRecordById(table,key);}catch(_){throw new NotFoundError('Record unavailable.');}};
 const put=(table,data)=>{const r=new Record(app.findCollectionByNameOrId(table));Object.keys(data).forEach(k=>r.set(k,data[k]));app.save(r);return r;};
 const membership=(vault,account)=>rows('memberships','vault = {:v} && account = {:a}',{v:vault,a:account})[0];
 const audit=(vault,target,action)=>put('audit_log',{vault,actor,action:action||op,target:target||vault});
 const identity=()=>get('identities',actor);
 const vault=()=>{
  const v=get('vaults',id('vault')),m=membership(v.id,actor);
  if(!m||!m.getBool('active'))denied();
  return [v,m];
 };
 const owner=v=>{if(v.getString('owner')!==actor)denied();if(p.expected_revision!==v.getInt('revision'))conflict();};
 const writable=v=>{if(v.getBool('archived'))refuse(409,'vault_archived','Vault archived; unarchive before writing.');};
 // One lock row per vault. Its generation is monotonic and never reused.
 const lockRow=key=>rows('locks','vault = {:v}',{v:key})[0];
 const expiresMs=l=>Date.parse(l.getString('expires_at'));
 const live=l=>!!l&&l.getString('state')==='held'&&Date.now()<expiresMs(l);
 const lockInfo=l=>{let info={};try{info=JSON.parse(l.getString('info')||'{}');}catch(_){}return info;};
 const lockView=l=>({holder:l.getString('holder'),info:lockInfo(l),progress:l.getString('progress'),expires_at:l.getString('expires_at'),generation:l.getInt('generation'),state:l.getString('state')});
 const refuseHeld=l=>refuse(409,'lock_held','Vault is locked by another operation.',Object.assign(lockView(l),{retry_after:Math.max(1,Math.ceil((expiresMs(l)-Date.now())/1000))}));
 const unlocked=key=>{const l=lockRow(key);if(live(l))refuseHeld(l);};
 const intArg=(name,min,max,fallback)=>{const value=p[name]===undefined?fallback:p[name];if(!Number.isInteger(value)||value<min||value>max)bad('Invalid '+name);return value;};
 const iso=ms=>new Date(ms).toISOString();
 const retire=(l,reason)=>{
  l.set('state','broken');l.set('generation',l.getInt('generation')+1);l.set('broken_by',actor);l.set('break_reason',reason);l.set('released_at',iso(Date.now()));app.save(l);
 };
 const fenceMatches=(l,generation,lease)=>!!l&&l.getString('state')==='held'&&l.getString('holder')===actor&&l.getInt('generation')===generation&&l.getString('lease_id')===lease;
 const manifest=key=>rows('documents','vault = {:v}',{v:key}).map(doc=>{
  const version=doc.getString('current_version');
  const ver=rows('versions','id = {:id}',{id:version})[0];
  const chunks=app.findRecordsByFilter('version_chunks','version = {:v}','position',0,0,{v:version}).map(c=>({id:c.id,sha256:c.getString('sha256')}));
  return {id:doc.id,revision:doc.getInt('revision'),version,archived:doc.getBool('archived'),archive_revision:doc.getInt('archive_revision'),chunk_count:ver?ver.getInt('chunk_count'):0,chunks,metadata:doc.getString('metadata')};
 }).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
 const vaultView=v=>({id:v.id,revision:v.getInt('revision'),epoch:v.getInt('epoch'),frozen:v.getBool('frozen'),archived:v.getBool('archived'),archive_revision:v.getInt('archive_revision'),lock_policy:v.getString('lock_policy')||'none'});
 // The server compares IDs, revisions and versions only; plaintext hashes stay client-side.
 const classify=(local,documents)=>{
  const remote={},details={stale:[],missing_remote:[],extra_remote:[],diverged:[]},seen={};
  documents.forEach(d=>remote[d.id]=d);
  local.forEach(l=>{
   seen[l.id]=true;const r=remote[l.id];
   if(!r||r.archived)details.missing_remote.push(l.id);
   else if(l.revision>r.revision||(l.revision===r.revision&&l.version!==r.version))details.diverged.push(l.id);
   else if(l.revision<r.revision)details.stale.push(l.id);
  });
  documents.forEach(d=>{if(!d.archived&&!seen[d.id])details.extra_remote.push(d.id);});
  const active=documents.filter(d=>!d.archived).length;
  const status=!local.length&&!active?'empty_remote':details.diverged.length?'diverged':details.missing_remote.length?'missing_remote':details.extra_remote.length?'extra_remote':details.stale.length?'stale':'match';
  return {status,details};
 };
 const bump=v=>{v.set('revision',v.getInt('revision')+1);app.save(v);};
 const envelope=(v,a,epoch,value)=>{
  if(typeof value!=='string'||value.length<1||value.length>65536)bad('Invalid envelope');
  return put('key_envelopes',{vault:v,account:a,epoch,envelope:value});
 };
 if(op==='identity_init') {
  if(rows('identities','account = {:a}',{a:actor}).length)conflict();
  put('identities',{id:actor,account:actor,public_key:str('public_key',500),signing_key:str('signing_key',500),fingerprint:str('fingerprint',200)});
  put('identity_secrets',{id:actor,account:actor,key_bundle:str('key_bundle'),revision:1});
  return {id:actor,revision:1};
 }
 if(op==='identity_rewrap') {
  const r=get('identity_secrets',actor);if(p.expected_revision!==r.getInt('revision'))conflict();
  require(`${__hooks}/identity_signature.js`).verify(actor,identity(),p);
  r.set('key_bundle',str('key_bundle'));r.set('revision',r.getInt('revision')+1);app.save(r);audit('',actor);return {id:actor,revision:r.getInt('revision')};
 }
 identity();
 if(op==='vault_create') {
  const key=id('id');
  put('vaults',{id:key,owner:actor,metadata:str('metadata'),epoch:1,revision:1,frozen:false,archived:false,archive_revision:0,lock_policy:'none'});
  put('memberships',{vault:key,account:actor,role:'owner',active:true});envelope(key,actor,1,str('envelope'));audit(key);
  return {id:key,revision:1,epoch:1,archived:false,archive_revision:0};
 }
 if(op==='accept') {
  const inv=get('invitations',id('invitation'));
  if(inv.getString('account')!==actor || inv.getString('status')!=='pending')denied();
  const v=get('vaults',inv.getString('vault'));
  writable(v);if(v.getBool('frozen'))conflict();unlocked(v.id);
  const m=membership(v.id,actor);if(!m)bad('Missing membership');
  const keys=rows('key_envelopes','vault = {:v} && account = {:a}',{v:v.id,a:actor});
  if(keys.length!==v.getInt('epoch'))bad('Incomplete key history');
  m.set('active',true);m.set('role',inv.getString('role'));app.save(m);
  inv.set('status','accepted');app.save(inv);bump(v);audit(v.id,actor);
  return {id:v.id,revision:v.getInt('revision')};
 }
 const [v,m]=vault();
 if(op==='vault_archive'||op==='vault_unarchive') {
  owner(v);
  if(p.expected_archive_revision!==v.getInt('archive_revision'))conflict();
  unlocked(v.id);
  const archived=op==='vault_archive';
  if(v.getBool('archived')!==archived) {
   v.set('archived',archived);v.set('archive_revision',v.getInt('archive_revision')+1);bump(v);audit(v.id);
  }
  return {id:v.id,revision:v.getInt('revision'),archived:v.getBool('archived'),archive_revision:v.getInt('archive_revision')};
 }
 if(op==='archive'||op==='unarchive') {
  if(!['owner','editor'].includes(m.getString('role')))denied();
  writable(v);if(v.getBool('frozen'))conflict();unlocked(v.id);
  const doc=get('documents',id('document'));
  if(doc.getString('vault')!==v.id)denied();
  if(p.expected_revision!==doc.getInt('revision')||p.expected_archive_revision!==doc.getInt('archive_revision'))conflict();
  const archived=op==='archive';
  if(doc.getBool('archived')!==archived) {
   doc.set('archived',archived);doc.set('archive_revision',doc.getInt('archive_revision')+1);app.save(doc);audit(v.id,doc.id);
  }
  return {id:doc.id,revision:doc.getInt('revision'),archived:doc.getBool('archived'),archive_revision:doc.getInt('archive_revision')};
 }
 if(op==='save') {
  if(m.getString('role')==='reader')denied();
  writable(v);if(v.getBool('frozen')||p.epoch!==v.getInt('epoch'))conflict();
  // A protected vault accepts writes only from the current lock holder's fence.
  if(p.fence!==undefined||v.getString('lock_policy')==='required') {
   if(p.fence===undefined)refuse(409,'lock_required','Vault requires the current lock fence for writes.');
   const f=p.fence;
   if(!f||typeof f!=='object'||!Number.isInteger(f.generation)||!validId(f.lease_id))bad('Invalid fence');
   if(!fenceMatches(lockRow(v.id),f.generation,f.lease_id))refuse(409,'stale_fence','Lock fence is no longer current.');
  }
  // Reject uploads prepared before an archive/unarchive cycle, even when the vault is active again.
  if((p.expected_vault_archive_revision===undefined?0:p.expected_vault_archive_revision)!==v.getInt('archive_revision'))conflict();
  const d=id('document'),version=id('version');
  const found=rows('documents','id = {:id}',{id:d});let doc=found[0];
  if(doc&&doc.getString('vault')!==v.id)denied();
  const revision=doc?doc.getInt('revision'):0;
  if(p.expected_revision!==revision)conflict();
  // Legacy clients may save never-archived documents; stale state after any archive transition conflicts.
  const archiveRevision=doc?doc.getInt('archive_revision'):0;
  if((p.expected_archive_revision===undefined?0:p.expected_archive_revision)!==archiveRevision)conflict();
  if(doc&&doc.getBool('archived'))refuse(409,'document_archived','Document archived; unarchive before saving.');
  if(!Array.isArray(p.chunks)||p.chunks.length<1||p.chunks.length>64)bad('Invalid chunks');
  let total=0;p.chunks.forEach(c=>{if(typeof c!=='string'||!c.length||c.length>262144)bad('Invalid chunk');total+=c.length;});
  if(total>12000000)bad('File exceeds encoded size limit');
  const metadata=str('metadata');
  if(!doc)doc=put('documents',{id:d,vault:v.id,metadata,revision:revision+1,current_version:version});
  else {doc.set('metadata',metadata);doc.set('revision',revision+1);doc.set('current_version',version);app.save(doc);}
  put('versions',{id:version,vault:v.id,document:d,epoch:p.epoch,revision:revision+1,manifest:str('manifest'),signature:str('signature',1000),author:actor,chunk_count:p.chunks.length});
  p.chunks.forEach((c,i)=>put('version_chunks',{vault:v.id,version,position:i,ciphertext:$filesystem.fileFromBytes(c,'chunk.bin'),sha256:$security.sha256(c)}));audit(v.id,d);
  return {id:d,version,revision:revision+1};
 }
 if(op==='share') {
  owner(v);writable(v);if(v.getBool('frozen'))conflict();unlocked(v.id);
  const account=id('account');if(account===actor)bad('Owner already has access');
  const user=get('users',account);if(!require(`${__hooks}/user_directory.js`).eligible(user))throw new ForbiddenError('Recipient must sign in with their verified Workspace Google account.');get('identities',account);
  if(!['reader','editor'].includes(p.role))bad('Invalid role');
  const old=membership(v.id,account);
  if(old&&old.getBool('active')) {
   if(old.getString('role')!==p.role)bad('Member already has a different role; revoke and share again to change it');
   return {id:old.id,vault:v.id,account,role:p.role,status:'active',revision:v.getInt('revision')};
  }
  const pending=rows('invitations','vault = {:v} && account = {:a} && status = "pending"',{v:v.id,a:account})[0];
  if(pending) {
   if(pending.getString('role')!==p.role)bad('Invitation already has a different role; revoke and share again to change it');
   return {id:pending.id,vault:v.id,account,role:p.role,status:'pending',revision:v.getInt('revision')};
  }
  if(!Array.isArray(p.envelopes)||p.envelopes.length!==v.getInt('epoch'))bad('Full key history required');
  // Remove obsolete envelopes only for this inactive recipient before a fresh invitation.
  rows('key_envelopes','vault = {:v} && account = {:a}',{v:v.id,a:account}).forEach(r=>app.delete(r));
  const seen={};p.envelopes.forEach(k=>{if(!Number.isInteger(k.epoch)||k.epoch<1||k.epoch>v.getInt('epoch')||seen[k.epoch])bad('Invalid key history');seen[k.epoch]=true;envelope(v.id,account,k.epoch,k.envelope);});
  if(!old)put('memberships',{vault:v.id,account,role:p.role,active:false});
  else {old.set('role',p.role);app.save(old);}
  const invitation=put('invitations',{vault:v.id,account,role:p.role,status:'pending',invited_by:actor});bump(v);audit(v.id,account);
  return {id:invitation.id,vault:v.id,account,role:p.role,status:'pending',revision:v.getInt('revision')};
 }
 if(op==='revoke') {
  owner(v);const account=id('account');if(account===actor)bad('Cannot revoke owner');
  const target=membership(v.id,account);if(!target)bad('Unknown member');
  target.set('active',false);app.save(target);
  rows('key_envelopes','vault = {:v} && account = {:a}',{v:v.id,a:account}).forEach(r=>app.delete(r));
  // Every pending invitation is canceled because rotation changes the required key history.
  rows('invitations','vault = {:v} && status = "pending"',{v:v.id}).forEach(r=>{r.set('status','canceled');app.save(r);});
  v.set('frozen',true);bump(v);audit(v.id,account);return {id:v.id,revision:v.getInt('revision'),epoch:v.getInt('epoch'),frozen:true};
 }
 if(op==='rotate') {
  owner(v);if(!v.getBool('frozen')||p.epoch!==v.getInt('epoch')+1)conflict();
  const members=rows('memberships','vault = {:v} && active = true',{v:v.id});
  if(!Array.isArray(p.envelopes)||p.envelopes.length!==members.length)bad('Exact active recipients required');
  const expected={};members.forEach(r=>expected[r.getString('account')]=true);
  p.envelopes.forEach(k=>{if(!expected[k.account])bad('Invalid rotation recipient');delete expected[k.account];envelope(v.id,k.account,p.epoch,k.envelope);});
  v.set('epoch',p.epoch);v.set('frozen',false);bump(v);audit(v.id);
  // Rotation retires any outstanding lock: its holder must acquire again.
  const held=lockRow(v.id);if(held&&held.getString('state')==='held'){retire(held,'key_rotation');audit(v.id,v.id,'lock_break');}
  return {id:v.id,revision:v.getInt('revision'),epoch:p.epoch};
 }
 if(op==='lock_acquire') {
  if(!['owner','editor'].includes(m.getString('role')))denied();
  const ttl=intArg('ttl_seconds',30,3600,900);
  const onMismatch=p.on_mismatch===undefined?'fail':p.on_mismatch;
  if(!['fail','lock'].includes(onMismatch))bad('Invalid on_mismatch');
  const info=p.info===undefined?{}:p.info;
  if(!info||typeof info!=='object'||Array.isArray(info))bad('Invalid info');
  const infoText=JSON.stringify(info);if(infoText.length>2048)bad('Invalid info');
  const requestId=p.request_id===undefined?'':p.request_id;
  if(typeof requestId!=='string'||requestId.length>64||(requestId&&!/^[A-Za-z0-9_.:-]+$/.test(requestId)))bad('Invalid request_id');
  let local=null;
  if(p.local!==undefined) {
   if(!p.local||typeof p.local!=='object'||!Array.isArray(p.local.documents)||p.local.documents.length>1000)bad('Invalid local');
   const ids={};
   local=p.local.documents.map(d=>{
    if(!d||typeof d!=='object'||!validId(d.id)||ids[d.id]||!Number.isInteger(d.revision)||d.revision<1||!validId(d.version))bad('Invalid local');
    ids[d.id]=true;return {id:d.id,revision:d.revision,version:d.version};
   });
  }
  const force=p.force===true;
  if(p.force!==undefined&&typeof p.force!=='boolean')bad('Invalid force');
  let observed,reason;
  if(force) {
   if(!Number.isInteger(p.observed_generation)||p.observed_generation<0)bad('Force requires observed_generation');
   observed=p.observed_generation;reason=str('reason',500);
   if(v.getString('owner')!==actor)denied();
  }
  writable(v);
  if(v.getBool('frozen'))refuse(409,'vault_frozen','Vault is frozen until key rotation completes.');
  const now=Date.now();let row=lockRow(v.id),previous=null;
  const respond=(l,documents,status,details)=>({lease_id:l.getString('lease_id'),generation:l.getInt('generation'),expires_at:l.getString('expires_at'),server_time:iso(Date.now()),ttl_seconds:l.getInt('ttl_seconds'),local_status:status,local_details:details,vault:vaultView(v),documents,previous});
  // Replaying the same request for the same live or late holder returns its lease.
  if(requestId&&row&&row.getString('state')==='held'&&row.getString('holder')===actor&&row.getString('request_id')===requestId) {
   const documents=manifest(v.id);const c=local?classify(local,documents):{status:'unchecked',details:null};
   return respond(row,documents,c.status,c.details);
  }
  if(force) {
   if((row?row.getInt('generation'):0)!==observed)refuse(409,'generation_changed','Lock generation changed; inspect the lock again.',row?lockView(row):{generation:0});
   if(row&&row.getString('state')==='held') {
    previous=Object.assign(lockView(row),{clean:false,expired_at:row.getString('expires_at')});
    retire(row,reason);audit(v.id,v.id,'lock_break');
   }
  } else if(row&&row.getString('state')==='held') {
   if(live(row))refuseHeld(row);
   // Expiry takeover: the previous holder did not release cleanly.
   previous=Object.assign(lockView(row),{clean:false,expired_at:row.getString('expires_at')});
   row.set('state','broken');row.set('generation',row.getInt('generation')+1);row.set('break_reason','expired');row.set('broken_by','');app.save(row);
  } else if(row) {
   previous={state:row.getString('state'),clean:row.getBool('clean'),generation:row.getInt('generation'),holder:row.getString('holder'),expired_at:row.getString('released_at'),progress:row.getString('progress'),info:lockInfo(row)};
  }
  const documents=manifest(v.id);
  const c=local?classify(local,documents):{status:'unchecked',details:null};
  if(onMismatch==='fail'&&local&&!['match','empty_remote'].includes(c.status))
   refuse(409,'local_mismatch','Local recovery set differs from the vault; restore first.',{local_status:c.status,local_details:c.details,remote:{vault:vaultView(v),documents}});
  if(!row)row=new Record(app.findCollectionByNameOrId('locks'));
  const fields={vault:v.id,holder:actor,lease_id:$security.randomStringWithAlphabet(15,LOCK_ALPHABET),generation:(row.getInt('generation')||0)+1,state:'held',acquired_at:iso(now),renewed_at:iso(now),expires_at:iso(now+ttl*1000),released_at:'',ttl_seconds:ttl,clean:false,progress:'',info:infoText,request_id:requestId,broken_by:'',break_reason:''};
  Object.keys(fields).forEach(k=>row.set(k,fields[k]));app.save(row);
  audit(v.id,v.id,force?'lock_force_acquire':'lock_acquire');
  if(v.getString('lock_policy')!=='required'){v.set('lock_policy','required');bump(v);audit(v.id,v.id,'lock_policy_required');}
  return respond(row,documents,c.status,c.details);
 }
 if(op==='lock_renew'||op==='lock_release') {
  const generation=intArg('generation',1,Number.MAX_SAFE_INTEGER),lease=id('lease_id');
  let progress;
  if(p.progress!==undefined){if(typeof p.progress!=='string'||p.progress.length>200)bad('Invalid progress');progress=p.progress;}
  const row=lockRow(v.id);
  if(op==='lock_release') {
   if(typeof p.clean!=='boolean')bad('Invalid clean');
   const result=()=>({released:true,vault_revision:v.getInt('revision'),documents:rows('documents','vault = {:v}',{v:v.id}).map(d=>({id:d.id,revision:d.getInt('revision'),version:d.getString('current_version')}))});
   if(row&&row.getString('state')==='released'&&row.getString('holder')===actor&&row.getInt('generation')===generation&&row.getString('lease_id')===lease)return result();
   if(!fenceMatches(row,generation,lease))refuse(409,'lock_lost','Lock is no longer held by this lease.');
   row.set('state','released');row.set('clean',p.clean);row.set('released_at',iso(Date.now()));if(progress!==undefined)row.set('progress',progress);app.save(row);
   audit(v.id,v.id,'lock_release');return result();
  }
  if(!fenceMatches(row,generation,lease))refuse(409,'lock_lost','Lock is no longer held by this lease.');
  const ttl=intArg('ttl_seconds',30,3600,row.getInt('ttl_seconds')),now=Date.now(),late=now>=expiresMs(row);
  row.set('renewed_at',iso(now));row.set('expires_at',iso(now+ttl*1000));row.set('ttl_seconds',ttl);if(progress!==undefined)row.set('progress',progress);app.save(row);
  return {expires_at:row.getString('expires_at'),server_time:iso(now),late};
 }
 if(op==='lock_break') {
  if(v.getString('owner')!==actor)denied();
  if(!Number.isInteger(p.observed_generation)||p.observed_generation<0)bad('Invalid observed_generation');
  const reason=str('reason',500),row=lockRow(v.id);
  if(!row||row.getInt('generation')!==p.observed_generation)refuse(409,'generation_changed','Lock generation changed; inspect the lock again.',row?lockView(row):{generation:0});
  if(row.getString('state')!=='held')return {generation:row.getInt('generation'),state:row.getString('state'),broken:false};
  retire(row,reason);audit(v.id,v.id,'lock_break');
  return {generation:row.getInt('generation'),state:'broken',broken:true};
 }
 if(op==='lock_policy_clear') {
  owner(v);const row=lockRow(v.id);
  if(row&&row.getString('state')==='held')refuseHeld(row);
  if(v.getString('lock_policy')!=='none'){v.set('lock_policy','none');bump(v);audit(v.id);}
  return {id:v.id,revision:v.getInt('revision'),lock_policy:'none'};
 }
 bad('Unknown operation');
}
function file(e) {
 if(e.record.collection().name!=='version_chunks')return e.next();
 let auth;try {auth=e.app.findAuthRecordByToken(e.requestInfo().query.token,'file');}catch(_){throw new NotFoundError('File unavailable.');}
 if(!auth||auth.collection().name!=='users')throw new NotFoundError('File unavailable.');
 const user=e.app.findRecordById('users',auth.id);
 const members=e.app.findRecordsByFilter('memberships','vault = {:v} && account = {:a} && active = true','',1,0,{v:e.record.getString('vault'),a:auth.id});
 if(user.getBool('disabled')||!members.length)throw new NotFoundError('File unavailable.');
 return e.next();
}
module.exports={action,file};
