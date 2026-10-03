function sync(e) {
 const original=e.app;
 original.runInTransaction(tx=>{
  e.app=tx;
  try {
   e.next();
   const rows=tx.findRecordsByFilter('user_directory','id = {:id}','',1,0,{id:e.record.id});
   const row=rows.length?rows[0]:new Record(tx.findCollectionByNameOrId('user_directory'));
   row.set('id',e.record.id);row.set('name',e.record.getString('name'));row.set('email',e.record.getString('email'));tx.save(row);
  } finally {e.app=original;}
 });
}
module.exports={sync};
