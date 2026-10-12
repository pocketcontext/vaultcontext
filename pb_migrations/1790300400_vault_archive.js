migrate((app) => {
  // Existing vaults start active. Lifecycle state is independent of key-rotation freeze.
  const vaults=app.findCollectionByNameOrId('vaults');
  vaults.fields.add(new BoolField({name:'archived'}));
  vaults.fields.add(new NumberField({name:'archive_revision',min:0,onlyInt:true}));
  app.save(vaults);
},()=>{throw new Error('Restore a verified backup to roll back vault archive state.');});
