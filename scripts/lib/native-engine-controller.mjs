import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { validAddressDiagnostic } from './native-address-diagnostic.mjs';

// Control plane only. There is intentionally no sendPacket/data/stream bridge.
// The caller owns provisioned TUN/routes/guard and must not release protection
// merely because this child exits. No automatic deployment or firewall changes.
export class NativeEngineController extends EventEmitter {
  #child; #pending = ''; #closed = false; #killTimer; #allowTrialCrash;
  constructor({ binary, config, spawnChild = spawn, allowTrialCrash = false }) {
    super();
    if (![binary, config].every(p => typeof p === 'string' && path.isAbsolute(p))) throw Error('absolute engine/config paths required');
    this.#allowTrialCrash = allowTrialCrash === true;
    this.#child = spawnChild(binary, ['--config', config], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.#child.stdout.setEncoding('utf8');
    this.#child.stdout.on('data', chunk => {
      this.#pending += chunk;
      if (this.#pending.length > 65536) return this.#protocolFailure();
      for (;;) {
        const end = this.#pending.indexOf('\n'); if (end < 0) break;
        const line = this.#pending.slice(0, end); this.#pending = this.#pending.slice(end + 1);
        try {
          const event = JSON.parse(line);
          if (validAddressDiagnostic(event)) { this.emit('diagnostic', event); continue; }
          const keys = ['version', 'event', 'state', 'generation', 'tx_packets', 'rx_packets', 'dropped_packets'];
          if (!event || Array.isArray(event) || Object.keys(event).length !== keys.length || keys.some(k => !(k in event)) ||
              event.version !== 1 || !['state', 'status'].includes(event.event) ||
              typeof event.state !== 'string' || !/^[a-z0-9_]{1,64}$/.test(event.state) ||
              keys.slice(3).some(k => !Number.isSafeInteger(event[k]) || event[k] < 0)) return this.#protocolFailure();
          this.emit('status', event);
        } catch { return this.#protocolFailure(); }
      }
    });
    // Do not forward arbitrary child stderr into UI/logs (future native errors
    // must not accidentally expose configuration). Keep only a bounded count.
    let stderrBytes = 0;
    this.#child.stderr.on('data', b => { stderrBytes += b.length; if (stderrBytes > 65536) this.#protocolFailure(); });
    this.#child.stdin.on('error', () => {});
    this.#child.on('error', () => this.emit('fault', { reason: 'engine_spawn_failed' }));
    this.#child.once('close', (code, signal) => {
      this.#closed = true; clearTimeout(this.#killTimer);
      this.emit('exit', { code, signal, incompleteStatus: this.#pending.length !== 0 });
    });
  }
  #protocolFailure() {
    this.#child.kill('SIGKILL'); this.emit('fault', { reason: 'engine_control_protocol' });
  }
  #command(command) {
    if (this.#closed || this.#child.stdin.destroyed) throw Error('engine closed');
    if (this.#child.stdin.writableLength > 4096) throw Error('control queue full');
    this.#child.stdin.write(JSON.stringify(command) + '\n');
  }
  status() { this.#command({ op: 'status' }); }
  crashForTrial() {
    if (!this.#allowTrialCrash || this.#closed || this.#killTimer) throw Error('trial_crash_not_allowed');
    // Signal the owned ChildProcess, never a PID found by name/pgrep.
    if (!this.#child.kill('SIGKILL')) throw Error('trial_crash_signal_failed');
  }
  uplink(ready) {
    if (typeof ready !== 'boolean') throw Error('uplink boolean required');
    this.#command({ op: 'uplink', ready });
  }
  stop() {
    if (this.#closed || this.#killTimer) return;
    try { this.#command({ op: 'stop' }); } catch { this.#child.kill('SIGTERM'); }
    this.#killTimer = setTimeout(() => this.#child.kill('SIGKILL'), 2000);
    this.#killTimer.unref?.();
  }
}
