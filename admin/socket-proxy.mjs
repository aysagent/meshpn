#!/usr/bin/env node
// Unprivileged systemd USB sockets -> loopback-only container. No HTTP headers
// are trusted as peer identity; USB ingress is enforced by BindToDevice.
import net from 'node:net';
import {need} from './lib/common.mjs';
need(Number(process.env.LISTEN_PID)===process.pid&&Number(process.env.LISTEN_FDS)===2,'socket_activation_required');
const sockets=new Set(),servers=[];
for(const[fd,port]of[[3,8080],[4,18443]]){const server=net.createServer(client=>{if(sockets.size>=32){client.destroy();return;}sockets.add(client);const up=net.connect(port,'127.0.0.1');const close=()=>{client.destroy();up.destroy();sockets.delete(client);};for(const s of[client,up]){s.setTimeout(30000,close);s.on('error',close);s.on('close',close);}client.pipe(up);up.pipe(client);});server.listen({fd});servers.push(server);}
for(const signal of['SIGTERM','SIGINT'])process.once(signal,()=>{for(const s of sockets)s.destroy();for(const s of servers)s.close();});
