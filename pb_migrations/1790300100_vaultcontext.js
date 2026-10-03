migrate((app) => {
  const access="@request.auth.id != '' && @request.auth.collectionName = 'users' && @request.auth.disabled = false";
  const text=(name,max=2000)=>({name,type:'text',max});
  const num=name=>({name,type:'number',min:0,onlyInt:true});
  // Ordinary REST reads are deliberately closed; authenticated filtered SQL is the read interface.
  function table(name,fields,indexes=[]) {
    app.save(new Collection({name,type:'base',listRule:null,viewRule:null,createRule:null,updateRule:null,deleteRule:null,fields:fields.concat([{name:'created',type:'autodate',onCreate:true}]),indexes}));
  }
  table('user_directory',[text('name',200),text('email',320)]);
  table('identities',[text('account',15),text('public_key',500),text('signing_key',500),text('fingerprint',200)],['CREATE UNIQUE INDEX identities_account ON identities(account)']);
  table('identity_secrets',[text('account',15),text('key_bundle',65536),num('revision')],['CREATE UNIQUE INDEX identity_secrets_account ON identity_secrets(account)']);
  table('vaults',[text('owner',15),text('metadata',65536),num('epoch'),num('revision'),{name:'frozen',type:'bool'}]);
  table('memberships',[text('vault',15),text('account',15),text('role',20),{name:'active',type:'bool'}],['CREATE UNIQUE INDEX memberships_pair ON memberships(vault,account)']);
  table('key_envelopes',[text('vault',15),text('account',15),num('epoch'),text('envelope',65536)],['CREATE UNIQUE INDEX envelope_generation ON key_envelopes(vault,account,epoch)']);
  table('documents',[text('vault',15),text('metadata',65536),num('revision'),text('current_version',15)]);
  table('versions',[text('vault',15),text('document',15),num('epoch'),num('revision'),text('manifest',65536),text('signature',1000),text('author',15),num('chunk_count')],['CREATE UNIQUE INDEX document_revision ON versions(document,revision)']);
  table('version_chunks',[text('vault',15),text('version',15),num('position'),{name:'ciphertext',type:'file',maxSize:262144,maxSelect:1,required:true,protected:true},text('sha256',64)],['CREATE UNIQUE INDEX chunk_position ON version_chunks(version,position)']);
  const chunks=app.findCollectionByNameOrId('version_chunks');chunks.viewRule="@request.context = 'protectedFile' && ("+access+")";app.save(chunks);
  table('invitations',[text('vault',15),text('account',15),text('role',20),text('status',20),text('invited_by',15)]);
  table('audit_log',[text('vault',15),text('actor',15),text('action',40),text('target',15)]);
  app.save(new Collection({name:'vault_actions',type:'base',listRule:null,viewRule:null,createRule:access,updateRule:null,deleteRule:null,fields:[text('op',40),{name:'payload',type:'json',maxSize:13000000}]}));
  const settings=app.settings();settings.batch.enabled=false;app.save(settings);
},()=>{throw new Error('Restore a verified backup to roll back the initial schema.');});
