// The journal is private and uses only installer-selected paths. It is not a
// generic file-write API. One broker owns these files; concurrent administrators
// must not edit them during apply. Unexpected bytes are never overwritten.
import fs from 'node:fs';
import path from 'node:path';
import {atomic, need} from './common.mjs';

function read(file, optional = false) {
  try {
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const s = fs.fstatSync(fd);
      need(s.isFile() && s.uid === process.getuid() && !(s.mode & 0o077) &&
        s.size <= 128 * 1024, 'vpn_transaction_file_permissions');
      return fs.readFileSync(fd, 'utf8');
    } finally { fs.closeSync(fd); }
  } catch (e) { if (optional && e.code === 'ENOENT') return null; throw e; }
}
function remove(file) {
  fs.unlinkSync(file);
  const fd = fs.openSync(path.dirname(file), 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
const bytes = value => JSON.stringify(value, null, 2) + '\n';

export class VpnSettingsTransaction {
  constructor({state, config, settings, unit, managed}, service, {fault = () => {}} = {}) {
    this.file = path.join(state, 'vpn-settings-transaction.json');
    this.binding = {config, settings, unit, managed: managed === true};
    this.service = service;
    this.fault = fault;
  }
  load() {
    const raw = read(this.file, true);
    if (raw === null) return null;
    const j = JSON.parse(raw);
    need(j.version === 1 && ['prepared', 'committed', 'rollback'].includes(j.phase) &&
      JSON.stringify(j.binding) === JSON.stringify(this.binding) &&
      typeof j.running === 'boolean' && (this.binding.managed || !j.running) &&
      j.entries?.length === 2 && j.entries.every((e, i) =>
        (typeof e.before === 'string' || (i === 1 && e.before === null)) &&
        typeof e.after === 'string'), 'vpn_transaction_invalid');
    return j;
  }
  paths() { return [this.binding.config, this.binding.settings]; }
  verify(j, committed = false) {
    this.paths().forEach((file, i) => {
      const current = read(file, i === 1);
      const e = j.entries[i];
      need(current === e.after || (!committed && current === e.before),
        'vpn_transaction_external_change', 409);
    });
  }
  clear() { remove(this.file); }
  async recover() {
    const j = this.load();
    if (!j) return {status: 'none'};
    this.verify(j, j.phase === 'committed');
    if (j.phase === 'committed') {
      this.clear();
      return {status: 'committed'};
    }
    // Durably select rollback before stopping or replacing anything. A second
    // interruption repeats the same recovery, never activates the candidate.
    j.phase = 'rollback'; atomic(this.file, j);
    if (this.binding.managed) await this.service.stop();
    this.verify(j);
    this.paths().forEach((file, i) => {
      const before = j.entries[i].before;
      if (before === null) { if (read(file, true) !== null) remove(file); }
      else atomic(file, before);
      this.fault('restored-' + i);
    });
    if (j.running) {
      await this.service.guard();
      await this.service.start();
      await this.service.ready();
    }
    this.clear();
    return {status: 'rolled-back', restarted: j.running};
  }
  async apply(config, settings) {
    need(!this.load(), 'vpn_transaction_recovery_required', 409);
    const running = this.binding.managed ? await this.service.running() : false;
    if (running) await this.service.guard();
    const j = {version: 1, phase: 'prepared', binding: this.binding, running,
      entries: this.paths().map((file, i) => ({before: read(file, i === 1),
        after: bytes(i === 0 ? config : settings)}))};
    atomic(this.file, j);
    try {
      this.fault('prepared');
      this.paths().forEach((file, i) => {
        this.verify(j); atomic(file, j.entries[i].after); this.fault('written-' + i);
      });
      if (running) {
        await this.service.guard();
        await this.service.restart();
        await this.service.ready();
      }
      this.fault('activated');
      this.verify(j, true);
      j.phase = 'committed'; atomic(this.file, j); this.fault('committed');
    } catch (e) {
      // A committed journal is authoritative, including when its final cleanup
      // is interrupted. Do not report rollback if recovery itself failed.
      const result = await this.recover();
      if (result.status === 'committed') return {saved: true, restarted: running};
      throw Object.assign(Error('vpn_apply_failed_rolled_back'), {cause: e});
    }
    this.clear();
    return {saved: true, restarted: running};
  }
}
