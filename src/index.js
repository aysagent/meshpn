import { MeshNode } from './core/node.js';
import { Identity } from './crypto/index.js';
import fs from 'fs';
import path from 'path';

function loadConfig() {
  const configPaths = [
    './config/default.json',
    './config.json',
    path.join(process.env.HOME || '', '.mesh-vpn/config.json')
  ];
  
  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(content);
      }
    } catch (err) {
      console.warn(`Failed to load config from ${configPath}:`, err.message);
    }
  }
  
  return {};
}

function parseArgs() {
  const args = process.argv.slice(2);
  const parsed = {};
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--role' || arg === '-r') {
      parsed.role = args[++i];
    } else if (arg === '--signalling' || arg === '-s') {
      parsed.signallingServer = args[++i];
    } else if (arg === '--config' || arg === '-c') {
      parsed.configPath = args[++i];
    } else if (arg === '--key' || arg === '-k') {
      parsed.privateKey = args[++i];
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }
  
  return parsed;
}

function printHelp() {
  console.log(`
Mesh VPN Node

Usage: node src/index.js [options]

Options:
  --role, -r <role>          Node role: client, relay, or exit (default: client)
  --signalling, -s <url>     Signalling server WebSocket URL
  --config, -c <path>        Path to config file
  --key, -k <key>            Private key (base64)
  --help, -h                 Show this help

Examples:
  node src/index.js --role client --signalling ws://localhost:8080
  node src/index.js --role exit -s ws://signal.example.com
  node src/index.js -c ./myconfig.json
`);
}

async function main() {
  console.log('Mesh VPN Node starting...');
  
  const fileConfig = loadConfig();
  const argsConfig = parseArgs();
  
  const config = {
    ...fileConfig,
    ...argsConfig
  };
  
  if (!config.signallingServer) {
    config.signallingServer = process.env.SIGNALLING_SERVER || 'ws://localhost:8080';
  }
  
  if (!config.role) {
    config.role = process.env.NODE_ROLE || 'client';
  }
  
  let identity;
  if (config.privateKey) {
    identity = Identity.fromPrivateKey(config.privateKey);
    console.log(`Loaded identity: ${identity.nodeId}`);
  } else {
    const keyPath = path.join(process.env.HOME || '', '.mesh-vpn/identity.key');
    try {
      if (fs.existsSync(keyPath)) {
        const keyData = fs.readFileSync(keyPath, 'utf8').trim();
        identity = Identity.fromPrivateKey(keyData);
        console.log(`Loaded identity from ${keyPath}: ${identity.nodeId}`);
      }
    } catch {
      // Will generate new identity
    }
    
    if (!identity) {
      identity = new Identity();
      console.log(`Generated new identity: ${identity.nodeId}`);
      
      try {
        const keyDir = path.dirname(keyPath);
        if (!fs.existsSync(keyDir)) {
          fs.mkdirSync(keyDir, { recursive: true });
        }
        fs.writeFileSync(keyPath, identity.exportPrivateKey(), { mode: 0o600 });
        console.log(`Saved identity to ${keyPath}`);
      } catch (err) {
        console.warn(`Could not save identity: ${err.message}`);
      }
    }
  }
  
  const node = new MeshNode({
    ...config,
    identity
  });
  
  node.on('started', () => {
    console.log('Node is running');
    console.log(`Role: ${node.role}`);
    console.log(`Node ID: ${node.nodeId}`);
  });
  
  node.on('registered', (info) => {
    console.log(`Virtual IP: ${info.virtualIp}`);
  });
  
  node.on('peer-connected', (peerId) => {
    console.log(`Connected to peer: ${peerId}`);
    console.log(`Total peers: ${node.discovery.getConnectedPeers().length}`);
  });
  
  node.on('peer-disconnected', (peerId) => {
    console.log(`Disconnected from peer: ${peerId}`);
  });
  
  const shutdown = async () => {
    console.log('\nShutting down...');
    await node.stop();
    process.exit(0);
  };
  
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  
  try {
    await node.start();
  } catch (err) {
    console.error('Failed to start node:', err.message);
    process.exit(1);
  }
  
  setInterval(() => {
    const stats = node.getStats();
    console.log(`\n--- Stats ---`);
    console.log(`Peers: ${stats.connectedPeers.length}`);
    console.log(`Exit nodes: ${stats.exitNodes.length}`);
    console.log(`Routing: ${stats.routing.totalNodes} nodes`);
    
    if (stats.loopPrevention) {
      const lp = stats.loopPrevention;
      if (lp.totalProcessed > 0) {
        console.log(`Packets: ${lp.totalProcessed} processed, ${lp.totalForwarded} forwarded`);
        const dropped = lp.ttlDropped + lp.duplicateDropped + lp.loopDropped + lp.splitHorizonDropped;
        if (dropped > 0) {
          console.log(`Dropped: ${dropped} (TTL: ${lp.ttlDropped}, dup: ${lp.duplicateDropped}, loop: ${lp.loopDropped}, split: ${lp.splitHorizonDropped})`);
        }
      }
    }
    
    if (stats.packetCacheSize > 0) {
      console.log(`Packet cache: ${stats.packetCacheSize} entries`);
    }
  }, 30000);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
