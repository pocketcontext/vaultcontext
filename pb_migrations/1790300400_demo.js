migrate((app) => {
  const closed = {type:'base',listRule:null,viewRule:null,createRule:null,updateRule:null,deleteRule:null};
  app.save(new Collection({...closed,name:'demo_policy',fields:[
    {name:'enabled',type:'bool'}, {name:'generation',type:'text',max:10}
  ]}));
  const policy = new Record(app.findCollectionByNameOrId('demo_policy'));
  policy.set('id','demopolicy00001');
  const demo=$os.getenv('VAULTCONTEXT_DEMO_MODE')==='true';
  if(demo && (app.countRecords('users') || app.countRecords('vaults')))throw new Error('Demo requires a fresh isolated database');
  policy.set('enabled',demo);policy.set('generation',demo?$os.getenv('VAULTCONTEXT_DEMO_GENERATION'):'');app.save(policy);
  app.save(new Collection({...closed,name:'demo_enrollments',fields:[
    {name:'account',type:'text',max:15,required:true},
    {name:'generation',type:'text',max:10,required:true},
    {name:'terms_version',type:'text',max:80,required:true},
    {name:'sales_consent',type:'bool'}, {name:'newsletter_consent',type:'bool'},
    {name:'contact_revision',type:'number',min:0,onlyInt:true},
    {name:'action_count',type:'number',min:0,onlyInt:true},
    {name:'encoded_bytes',type:'number',min:0,onlyInt:true},
    {name:'created',type:'autodate',onCreate:true},
    {name:'updated',type:'autodate',onCreate:true,onUpdate:true}
  ],indexes:['CREATE UNIQUE INDEX demo_enrollment_account ON demo_enrollments(account)']}));
}, () => {throw new Error('Demo policy rollback requires a deliberate backup restore.');});
