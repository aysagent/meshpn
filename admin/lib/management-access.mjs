import net from 'node:net';
import os from 'node:os';
import {exact,need,ipv4Subnet} from './common.mjs';

export function managementAccess(value) {
 if(value===undefined)return null;
 exact(value,['interface','subnet','port','capturePort']);
 need(typeof value.interface==='string'&&/^[a-zA-Z0-9_]{1,15}$/.test(value.interface)&&!['lo','usb0'].includes(value.interface),'management_interface');
 const [base,bits,...rest]=String(value.subnet).split('/');
 need(!rest.length&&net.isIPv4(base)&&/^(?:[1-9]|[12][0-9]|3[0-2])$/.test(bits),'management_subnet');
 const prefix=Number(bits);
 need([['10.0.0.0/8',8],['172.16.0.0/12',12],['192.168.0.0/16',16]].some(([range,min])=>prefix>=min&&ipv4Subnet(base,range)),'management_private_subnet_required');
 const result={...value,port:value.port??8080,capturePort:value.capturePort??18443};
 for(const p of [result.port,result.capturePort])need(Number.isInteger(p)&&p>=1024&&p<=65535,'management_port');
 need(result.port!==result.capturePort,'management_port_collision');
 return result;
}
export function managementAddresses(access,interfaces=os.networkInterfaces()) {
 return access?(interfaces[access.interface]??[]).filter(a=>a.family==='IPv4'&&!a.internal&&ipv4Subnet(a.address,access.subnet)).map(a=>a.address):[];
}
export function managementPeer(access,socket,interfaces) {
 return !!access&&[access.port,access.capturePort].includes(socket.localPort)&&managementAddresses(access,interfaces).includes(socket.localAddress)&&ipv4Subnet(socket.remoteAddress,access.subnet);
}
// The original HTTP/capture servers handle these raw sockets directly: peer IP,
// authentication state and Origin checks are preserved, no proxy headers trusted.
export function startManagementListeners(access,{server,captureFront},{interfaces=os.networkInterfaces,interval=2000,report=()=>{},createServer=net.createServer}={}) {
 const listeners=new Map();let closed=false;
 function drop(key,entry){listeners.delete(key);for(const s of entry.clients)s.destroy();entry.listener.close(()=>{});}
 function reconcile(){
  if(closed)return;
  const addresses=managementAddresses(access,interfaces());
  const wanted=new Map(addresses.flatMap(address=>[[`${address}:${access.port}`,{address,port:access.port,target:server}],[`${address}:${access.capturePort}`,{address,port:access.capturePort,target:captureFront}]]));
  for(const [key,entry]of listeners)if(!wanted.has(key))drop(key,entry);
  for(const [key,{address,port,target}]of wanted){
   if(listeners.has(key))continue;
   const clients=new Set();const listener=createServer(socket=>{
    if(!managementPeer(access,socket,interfaces())){socket.destroy();return;}
    clients.add(socket);socket.on('close',()=>clients.delete(socket));target.emit('connection',socket);
   });
   const entry={listener,clients};listeners.set(key,entry);listener.maxConnections=target===captureFront?8:32;
   listener.on('error',()=>{if(listeners.get(key)===entry)drop(key,entry);report({state:'unavailable',interface:access.interface,address,port});});
   listener.listen(port,address,()=>report({state:'listening',interface:access.interface,address,port}));
  }
 }
 reconcile();const timer=setInterval(reconcile,interval);timer.unref();
 return{reconcile,close(){closed=true;clearInterval(timer);for(const [key,entry]of listeners)drop(key,entry);}};
}
