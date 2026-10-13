function eligible(user) {
 const domain=require(`${__hooks}/google_auth.js`).domain();
 return !!domain && !user.getBool('disabled') &&
  user.getString('workspace_google_domain')===domain &&
  user.getString('workspace_google_email')===user.getString('email').toLowerCase() &&
  user.getString('email').toLowerCase().split('@')[1]===domain;
}
function refresh(app) {
 // Frozen startup is read-only even when operator environment settings changed.
 // PocketContext validates the marker before bootstrap; do not write its snapshot.
 if($os.readDir(app.dataDir()).some(entry=>entry.name()==='maintenance.json')) {
  const state=JSON.parse(toString($os.readFile(app.dataDir()+'/maintenance.json')));
  if(state.readOnly) return;
 }
 // Re-evaluate after operator changes to the configured Workspace domain.
 app.findAllRecords('users').forEach(user=>{
  const row=app.findRecordById('user_directory',user.id), value=eligible(user);
  if(row.getBool('sharing_eligible')!==value) {row.set('sharing_eligible',value);app.save(row);}
 });
}
function sync(e) {
 const original=e.app;
 original.runInTransaction(tx=>{
  e.app=tx;
  try {
   e.next();
   const rows=tx.findRecordsByFilter('user_directory','id = {:id}','',1,0,{id:e.record.id});
   const row=rows.length?rows[0]:new Record(tx.findCollectionByNameOrId('user_directory'));
   row.set('id',e.record.id);row.set('name',e.record.getString('name'));row.set('email',e.record.getString('email'));row.set('sharing_eligible',eligible(e.record));tx.save(row);
  } finally {e.app=original;}
 });
}
module.exports={sync,eligible,refresh};
