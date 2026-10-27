import {randomBytes,scrypt as scryptCallback,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {atomic,readJson,need} from './common.mjs';
const scrypt=promisify(scryptCallback);
const token=()=>randomBytes(32).toString('hex');
export class Auth{
 constructor(file){this.file=file;this.sessions=new Map();this.attempts=new Map();this.busy=0;}
 async init(){this.record=readJson(this.file,null);if(!this.record){this.record=await this.hash('admin');this.record.defaultPassword=true;atomic(this.file,this.record);}need(this.record.version===1&&/^[a-f0-9]{32}$/.test(this.record.salt)&&/^[a-f0-9]{64}$/.test(this.record.hash),'invalid_auth_state');}
 async hash(password){const salt=randomBytes(16).toString('hex');return{version:1,salt,hash:Buffer.from(await scrypt(password,salt,32)).toString('hex'),defaultPassword:false};}
 async matches(password){if(typeof password!=='string'||Buffer.byteLength(password)>128)return false;const actual=Buffer.from(await scrypt(password,this.record.salt,32));return timingSafeEqual(actual,Buffer.from(this.record.hash,'hex'));}
 async login(password,peer){const now=Date.now();for(const[k,v]of this.attempts)if(v.until<now)this.attempts.delete(k);need(this.busy<2,'login_busy',429);const a=this.attempts.get(peer)??{count:0,until:now+60000};need(a.count<5,'login_rate_limit',429);a.count++;this.attempts.set(peer,a);this.busy++;try{need(await this.matches(password),'invalid_password',401);}finally{this.busy--;}this.attempts.delete(peer);for(const[k,v]of this.sessions)if(v.expires<now)this.sessions.delete(k);need(this.sessions.size<16,'session_limit',429);const sid=token(),s={csrf:token(),peer,expires:now+8*3600000};this.sessions.set(sid,s);return{sid,...s,defaultPassword:this.record.defaultPassword};}
 session(req){const cookie=req.headers.cookie??'';const sid=/(?:^|;\s*)mpn_session=([a-f0-9]{64})(?:;|$)/.exec(cookie)?.[1];const s=this.sessions.get(sid);need(s&&s.peer===req.socket.remoteAddress&&s.expires>Date.now(),'login_required',401);return{sid,...s};}
 csrf(req,s){need(req.headers['x-csrf-token']===s.csrf,'csrf',403);}
 async change(oldPassword,newPassword){need(typeof newPassword==='string'&&Buffer.byteLength(newPassword)>=8&&Buffer.byteLength(newPassword)<=128&&newPassword!=='admin','password_length');need(await this.matches(oldPassword),'invalid_password',401);this.record=await this.hash(newPassword);atomic(this.file,this.record);this.sessions.clear();}
}
