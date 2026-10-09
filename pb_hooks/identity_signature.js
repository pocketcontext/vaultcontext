// Verification only. The client signs canonical ASCII JSON with its immutable Ed25519 key.
function bytes(value, length) {
 if(typeof value!=='string'||value.length!==4*Math.ceil(length/3)||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))throw new Error('Invalid signature encoding');
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
 const result=new Uint8Array(length);let acc=0,bits=0,index=0;
 for(const char of value.replace(/=+$/,'')) {
  acc=(acc<<6)|alphabet.indexOf(char);bits+=6;
  if(bits>=8){bits-=8;if(index>=length)throw new Error('Invalid signature size');result[index++]=(acc>>bits)&255;}
 }
 if(index!==length||(acc&((1<<bits)-1))!==0)throw new Error('Invalid signature size');
 return result;
}
function verify(actor, identity, p) {
 try {
  if(typeof p.key_bundle!=='string'||p.key_bundle.length>65536||!/^[\x20-\x7e]+$/.test(p.key_bundle)||!Number.isSafeInteger(p.expected_revision)||p.expected_revision<1)throw new Error('Invalid replacement');
  const body={account:actor,expected_revision:p.expected_revision,key_bundle:p.key_bundle,purpose:'identity-rewrap'};
  const value='vaultcontext-manifest-v1\x00'+JSON.stringify(body);
  const message=new Uint8Array(value.length);
  for(let i=0;i<value.length;i++)message[i]=value.charCodeAt(i);
  const nacl=require(`${__hooks}/vendor/tweetnacl-1.0.3.js`);
  if(!nacl.sign.detached.verify(message,bytes(p.signature,64),bytes(identity.getString('signing_key'),32)))throw new Error('Invalid signature');
 } catch(_) {throw new ForbiddenError('Identity replacement requires a valid signature from the existing identity.');}
}
module.exports={verify};
