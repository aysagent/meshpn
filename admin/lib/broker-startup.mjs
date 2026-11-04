import {setTimeout as delay} from 'node:timers/promises';
import {performance} from 'node:perf_hooks';

// Only startup's read-only settings request may wait for the Unix socket.
// Authentication/configuration errors and mutations must never be retried here.
export async function brokerStartupSettings(request,{timeoutMs=10000,intervalMs=100}={}) {
 const deadline=performance.now()+timeoutMs;
 for(;;){
  try{return await request();}
  catch(error){
   if(!['ENOENT','ECONNREFUSED'].includes(error.code))throw error;
   const remaining=deadline-performance.now();
   if(remaining<=0)throw Error('broker_startup_unavailable',{cause:error});
   await delay(Math.min(intervalMs,remaining));
  }
 }
}
