migrate((app) => {
  const audit = app.findCollectionByNameOrId('audit_log');
  audit.fields.add(new TextField({name:'reason', max:500}));
  audit.fields.add(new NumberField({name:'generation', min:0, onlyInt:true}));
  app.save(audit);
  const locks = app.findCollectionByNameOrId('locks');
  // Private replay state is excluded from filtered SQL and ordinary REST.
  locks.fields.add(new TextField({name:'request_hash', max:64}));
  locks.fields.add(new JSONField({name:'grant', maxSize:64*1024*1024}));
  app.save(locks);
  // Grants issued by the earlier schema had member-readable fence identifiers.
  const reason = $os.getenv('VAULTCONTEXT_RECOVERING_DATABASE') === '1' ? 'database_restore' : 'lock_schema_upgrade';
  for (const lock of app.findRecordsByFilter('locks', 'state = "held"', '', 0, 0)) {
    const generation = lock.getInt('generation');
    const event = new Record(audit);
    event.set('vault',lock.getString('vault')); event.set('target',lock.getString('vault'));
    event.set('action','lock_break'); event.set('reason',reason); event.set('generation',generation);
    app.save(event);
    lock.set('state','broken'); lock.set('generation',generation+1); lock.set('clean',false);
    lock.set('lease_id',''); lock.set('request_id',''); lock.set('break_reason',reason);
    lock.set('released_at',new Date().toISOString()); app.save(lock);
  }
}, () => {throw new Error('Restore a verified backup to roll back lock audit state.');});
