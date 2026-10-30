// Host journal adapter; pure native event parsing is shared with controllers.
import {projectEngineDiagnostics} from '../../scripts/lib/native-engine-diagnostics.mjs';
export {projectEngineDiagnostics,publicEngineDiagnostics} from '../../scripts/lib/native-engine-diagnostics.mjs';
export function createJournalDiagnostics(run,{now=()=>Date.now()}={}){
 let cache=null,key='',cachedAt=0;
 return async(unit,state)=>{
  if(!/^[a-zA-Z0-9_-]+\.service$/.test(unit)||!/^\d+$/.test(state.MainPID??'')||state.MainPID==='0')return{status:'stopped'};
  if(!/^[a-f0-9]{32}$/.test(state.InvocationID??''))return{status:'unavailable',reason:'invocation-unavailable'};
  const identity=unit+':'+state.InvocationID+':'+state.MainPID;
  if(cache&&identity===key&&now()-cachedAt>=0&&now()-cachedAt<5000)return cache;
  let result={status:'unavailable',reason:'no-native-diagnostics'};
  try{
   const r=await run('/usr/bin/journalctl',['--no-pager','-u',unit,'_SYSTEMD_INVOCATION_ID='+state.InvocationID,'-n','64','-o','json'],{timeout:4000,limit:512*1024});
   for(const line of r.out.split('\n').filter(Boolean).reverse()){
    try{const entry=JSON.parse(line);if(entry._PID!==state.MainPID||entry._SYSTEMD_INVOCATION_ID!==state.InvocationID)continue;
     const event=JSON.parse(entry.MESSAGE),data=projectEngineDiagnostics(event);if(!data)continue;
     const at=Number(entry.__REALTIME_TIMESTAMP)/1000,age=now()-at;
     if(!Number.isFinite(at)||age<0||age>120000){result={status:'stale',reason:'native-sample-age'};break;}
     result={status:'sampled',ageMs:Math.round(age),...data};break;
    }catch{}
   }
  }catch{result={status:'unavailable',reason:'journal-unavailable'};}
  key=identity;cachedAt=now();cache=result;return result;
 };
}
