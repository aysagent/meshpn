import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const text=fs.readFileSync(new URL('../components/meshvpn_web/web_ui.h',import.meta.url),'utf8');
for(const part of text.split('static const char ').slice(1)){
  const html=part.split('\n').filter(l=>l.startsWith('"')).map(l=>JSON.parse(l.endsWith(';')?l.slice(0,-1):l)).join('');
  const ids=[...html.matchAll(/\bid=["']([^"']+)["']/g)].map(m=>m[1]);
  assert.equal(new Set(ids).size,ids.length,'duplicate DOM id');
  for(const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)){
    new vm.Script(script[1]);
    for(const use of script[1].matchAll(/\$\(['"]([^'"]+)['"]\)/g))
      assert(ids.includes(use[1]),'missing DOM id: '+use[1]);
  }
}
console.log('Web UI JavaScript and DOM references passed');
