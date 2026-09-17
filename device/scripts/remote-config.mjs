#!/usr/bin/env node
// Linux-side non-secret connection preferences, kept out of git.
import { writeFile } from 'node:fs/promises';
import { configFile, macRepo, macUser } from './remote-mac.mjs';

const [repoDir, user] = process.argv.slice(2);
try {
  if (!repoDir || !user) throw Error('Usage: npm run device:remote:config -- /absolute/path/to/Mac/meshpn macuser');
  macRepo(repoDir); macUser(user);
  await writeFile(configFile, JSON.stringify({repo_dir: repoDir, mac_user: user}, null, 2) + '\n', {mode: 0o600});
  console.log(`Saved Mac checkout settings: ${configFile}`);
} catch (error) {console.error(error.message); process.exitCode = 2;}
