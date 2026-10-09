// All domain writes execute inside a single transaction. Action bodies never persist.
function action(e) {
 if(!e.auth || e.auth.collection().name!=='users' || e.auth.getBool('disabled')) throw new ForbiddenError('Ordinary active user required.');
 const actor=e.auth.id, op=e.record.getString('op');
 let p;try {p=JSON.parse(e.record.getString('payload'));} catch(_) {throw new BadRequestError('Invalid payload JSON.');}
 if(!p || typeof p!=='object' || Array.isArray(p)) throw new BadRequestError('Object payload required.');
 let result;
 e.app.runInTransaction(app=>{result=execute(app,actor,op,p);});
 return e.json(200,{result});
}
function execute(app,actor,op,p) {
 require(`${__hooks}/demo.js`).authorizeAction(app,actor,op,p);
 if(app.findRecordById('users',actor).getBool('disabled')) throw new ForbiddenError('Account disabled.');
 const bad=message=>{throw new BadRequestError(message);};
 const denied=()=>{throw new ForbiddenError('Vault operation not permitted.');};
 const conflict=()=>{throw new ApiError(409,'Revision conflict; refresh state.',{});};
 const str=(name,max=65536)=>{const v=p[name];if(typeof v!=='string'||!v.length||v.length>max)bad('Invalid '+name);return v;};
 const validId=v=>typeof v==='string'&&/^[a-z0-9]{15}$/.test(v);
 const id=name=>{if(!validId(p[name]))bad('Invalid '+name);return p[name];};
 const rows=(table,filter,params)=>app.findRecordsByFilter(table,filter,'',0,0,params||{});
 const get=(table,key)=>{try{return app.findRecordById(table,key);}catch(_){throw new NotFoundError('Record unavailable.');}};
 const put=(table,data)=>{const r=new Record(app.findCollectionByNameOrId(table));Object.keys(data).forEach(k=>r.set(k,data[k]));app.save(r);return r;};
 const membership=(vault,account)=>rows('memberships','vault = {:v} && account = {:a}',{v:vault,a:account})[0];
 const audit=(vault,target)=>put('audit_log',{vault,actor,action:op,target:target||vault});
 const identity=()=>get('identities',actor);
 const vault=()=>{
  const v=get('vaults',id('vault')),m=membership(v.id,actor);
  if(!m||!m.getBool('active'))denied();
  return [v,m];
 };
 const owner=v=>{if(v.getString('owner')!==actor)denied();if(p.expected_revision!==v.getInt('revision'))conflict();};
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
  put('vaults',{id:key,owner:actor,metadata:str('metadata'),epoch:1,revision:1,frozen:false});
  put('memberships',{vault:key,account:actor,role:'owner',active:true});envelope(key,actor,1,str('envelope'));audit(key);
  return {id:key,revision:1,epoch:1};
 }
 if(op==='accept') {
  const inv=get('invitations',id('invitation'));
  if(inv.getString('account')!==actor || inv.getString('status')!=='pending')denied();
  const v=get('vaults',inv.getString('vault'));
  if(v.getBool('frozen'))conflict();
  const m=membership(v.id,actor);if(!m)bad('Missing membership');
  const keys=rows('key_envelopes','vault = {:v} && account = {:a}',{v:v.id,a:actor});
  if(keys.length!==v.getInt('epoch'))bad('Incomplete key history');
  m.set('active',true);m.set('role',inv.getString('role'));app.save(m);
  inv.set('status','accepted');app.save(inv);bump(v);audit(v.id,actor);
  return {id:v.id,revision:v.getInt('revision')};
 }
 const [v,m]=vault();
 if(op==='archive'||op==='unarchive') {
  if(!['owner','editor'].includes(m.getString('role')))denied();
  if(v.getBool('frozen'))conflict();
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
  if(v.getBool('frozen')||p.epoch!==v.getInt('epoch'))conflict();
  const d=id('document'),version=id('version');
  const found=rows('documents','id = {:id}',{id:d});let doc=found[0];
  if(doc&&doc.getString('vault')!==v.id)denied();
  const revision=doc?doc.getInt('revision'):0;
  if(p.expected_revision!==revision)conflict();
  // Legacy clients may save never-archived documents; stale state after any archive transition conflicts.
  const archiveRevision=doc?doc.getInt('archive_revision'):0;
  if((p.expected_archive_revision===undefined?0:p.expected_archive_revision)!==archiveRevision)conflict();
  if(doc&&doc.getBool('archived'))throw new ApiError(409,'Document archived; unarchive before saving.',{});
  if(!Array.isArray(p.chunks)||p.chunks.length<1||p.chunks.length>64)bad('Invalid chunks');
  let total=0;p.chunks.forEach(c=>{if(typeof c!=='string'||!c.length||c.length>262144)bad('Invalid chunk');total+=c.length;});
  if(total>12000000)bad('File exceeds encoded size limit');
  require(`${__hooks}/demo.js`).reserveSave(app,actor,v.id,!!doc,total);
  const metadata=str('metadata');
  if(!doc)doc=put('documents',{id:d,vault:v.id,metadata,revision:revision+1,current_version:version});
  else {doc.set('metadata',metadata);doc.set('revision',revision+1);doc.set('current_version',version);app.save(doc);}
  put('versions',{id:version,vault:v.id,document:d,epoch:p.epoch,revision:revision+1,manifest:str('manifest'),signature:str('signature',1000),author:actor,chunk_count:p.chunks.length});
  p.chunks.forEach((c,i)=>put('version_chunks',{vault:v.id,version,position:i,ciphertext:$filesystem.fileFromBytes(c,'chunk.bin'),sha256:$security.sha256(c)}));audit(v.id,d);
  return {id:d,version,revision:revision+1};
 }
 if(op==='share') {
  owner(v);if(v.getBool('frozen'))conflict();
  const account=id('account');if(account===actor)bad('Owner already has access');
  const user=get('users',account);if(user.getBool('disabled'))denied();get('identities',account);
  if(!['reader','editor'].includes(p.role))bad('Invalid role');
  const old=membership(v.id,account);if(old&&old.getBool('active'))bad('Already a member');
  if(rows('invitations','vault = {:v} && account = {:a} && status = "pending"',{v:v.id,a:account}).length)bad('Invitation already pending');
  if(!Array.isArray(p.envelopes)||p.envelopes.length!==v.getInt('epoch'))bad('Full key history required');
  // Remove obsolete envelopes only for this inactive recipient before a fresh invitation.
  rows('key_envelopes','vault = {:v} && account = {:a}',{v:v.id,a:account}).forEach(r=>app.delete(r));
  const seen={};p.envelopes.forEach(k=>{if(!Number.isInteger(k.epoch)||k.epoch<1||k.epoch>v.getInt('epoch')||seen[k.epoch])bad('Invalid key history');seen[k.epoch]=true;envelope(v.id,account,k.epoch,k.envelope);});
  if(!old)put('memberships',{vault:v.id,account,role:p.role,active:false});
  else {old.set('role',p.role);app.save(old);}
  const invitation=put('invitations',{vault:v.id,account,role:p.role,status:'pending',invited_by:actor});bump(v);audit(v.id,account);
  return {id:invitation.id,revision:v.getInt('revision')};
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
  v.set('epoch',p.epoch);v.set('frozen',false);bump(v);audit(v.id);return {id:v.id,revision:v.getInt('revision'),epoch:p.epoch};
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
