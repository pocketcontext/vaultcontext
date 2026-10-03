onRecordCreateRequest((e)=>require(`${__hooks}/vault.js`).action(e),'vault_actions');
onFileDownloadRequest((e)=>require(`${__hooks}/vault.js`).file(e));
