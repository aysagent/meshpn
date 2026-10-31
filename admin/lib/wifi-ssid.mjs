// SSIDs returned by wpa_supplicant use printf_encode(), not JSON escaping.
// Decode only at that boundary: a manually entered literal "\\x41" is valid.
export function validWifiSsid(value){
 return typeof value==='string'&&Buffer.byteLength(value)>0&&Buffer.byteLength(value)<=32&&
  !/[\x00-\x1f\x7f]/.test(value)&&Buffer.from(value).toString('utf8')===value;
}

export function decodeWifiSsid(encoded){
 if(typeof encoded!=='string'||encoded.length>128)return null;
 const bytes=[],escapes={'\\':92,'"':34,n:10,r:13,t:9,e:27};
 for(let i=0;i<encoded.length;i++){
  const c=encoded.charCodeAt(i);
  if(c===92){
   const escape=encoded[++i];
   if(Object.hasOwn(escapes,escape))bytes.push(escapes[escape]);
   else if(escape==='x'&&/^[a-fA-F0-9]{2}$/.test(encoded.slice(i+1,i+3))){bytes.push(parseInt(encoded.slice(i+1,i+3),16));i+=2;}
   else return null;
  }else if(c>=32&&c<=126)bytes.push(c);
  else return null;
 }
 // Binary/non-UTF-8 SSIDs are not supported by this text-based profile store.
 // Never replace invalid bytes and accidentally save a different network name.
 try{const value=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Uint8Array.from(bytes));return validWifiSsid(value)?value:null;}catch{return null;}
}
