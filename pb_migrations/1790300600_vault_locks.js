migrate((app) => {
  // One exclusive, lease-based write lock per vault. Lock metadata is plaintext
  // operational data (holder, label, progress, timestamps); never store secrets in it.
  const text=(name,max=2000)=>({name,type:'text',max});
  const num=name=>({name,type:'number',min:0,onlyInt:true});
  app.save(new Collection({name:'locks',type:'base',listRule:null,viewRule:null,createRule:null,updateRule:null,deleteRule:null,
    fields:[text('vault',15),text('holder',15),text('lease_id',15),num('generation'),text('state',20),
      text('acquired_at',40),text('renewed_at',40),text('expires_at',40),text('released_at',40),
      num('ttl_seconds'),{name:'clean',type:'bool'},text('progress',200),text('info',2048),text('request_id',64),
      text('broken_by',15),text('break_reason',500),{name:'created',type:'autodate',onCreate:true}],
    indexes:['CREATE UNIQUE INDEX locks_vault ON locks(vault)']}));
  const vaults=app.findCollectionByNameOrId('vaults');
  vaults.fields.add(new TextField({name:'lock_policy',max:20}));
  app.save(vaults);
  // Existing vaults keep unfenced writes until their first lock acquisition.
  app.db().newQuery("UPDATE vaults SET lock_policy = 'none' WHERE lock_policy = ''").execute();
},()=>{throw new Error('Restore a verified backup to roll back vault lock state.');});
