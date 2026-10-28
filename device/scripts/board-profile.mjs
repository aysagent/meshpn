import {readFileSync} from 'node:fs';
export const developmentBoards = JSON.parse(readFileSync(new URL('../boards/development.json', import.meta.url)));
export function boardProfile(value) {
  const entry = Object.entries(developmentBoards).find(([name, p]) => name === value || p.aliases.includes(value));
  if (!entry) throw Error('Unknown --board; use waveshare, stamp, xiao or a canonical board name');
  return {name: entry[0], ...entry[1]};
}
export function boardSelection(o) {
  const name = o.board || process.env.BOARD;
  if (!name) return {...o};
  const p = boardProfile(name);
  return {...o, board: p.name, adminURL: o.adminURL || `http://${o.paths === 'ap' ? p.ap : p.usb}/`};
}
