onRecordCreateExecute((e)=>require(`${__hooks}/user_directory.js`).sync(e),'users');
onRecordUpdateExecute((e)=>require(`${__hooks}/user_directory.js`).sync(e),'users');
