import { execFileSync } from 'node:child_process';

// A terminal SIGINT targets the foreground process group, including synchronous
// helpers. Keep the lifetime-lock fds, but put helpers in a separate group so a
// second Ctrl+C cannot interrupt a journalled operation behind Node's handler.
export function runTunnelDnsCommand(file, args, { lockDescriptors = [], timeoutMs = 10000 } = {}) {
  try {
    return execFileSync(file, args, {
      encoding: 'utf8', detached: true, timeout: Math.max(1, Math.ceil(timeoutMs)),
      killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe', ...lockDescriptors],
    }).trim();
  } catch (error) {
    // Preserve status=1 for conntrack's checked "entry already expired" path.
    const detail = String(error.stderr ?? '').trim().slice(0, 2048);
    error.message = `DNS command ${file} failed (code=${error.code ?? '-'}, status=${error.status ?? '-'}, signal=${error.signal ?? '-'}, timeout=${Math.ceil(timeoutMs)}ms)${detail ? `: ${detail}` : ''}`;
    throw error;
  }
}
