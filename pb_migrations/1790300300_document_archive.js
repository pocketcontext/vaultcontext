migrate((app) => {
  // PocketBase initializes these fields to false/0 on existing documents.
  // Keep content revision unchanged: it is bound into each immutable signed manifest.
  const documents=app.findCollectionByNameOrId('documents');
  documents.fields.add(new BoolField({name:'archived'}));
  documents.fields.add(new NumberField({name:'archive_revision',min:0,onlyInt:true}));
  app.save(documents);
},()=>{throw new Error('Restore a verified backup to roll back document archive state.');});
