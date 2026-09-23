/** Pure proposal, not a host DNS backend. Actions require acknowledgement. */
const states = new Set(['idle', 'preparing', 'selecting', 'active', 'blocked', 'conflict', 'restoring', 'releasing']);
export function dnsLifecycle(state, event, { optIn = false, owned = false } = {}) {
  if (!states.has(state)) throw new Error('unknown DNS lifecycle state');
  const next = (state, ...actions) => ({ state, actions });
  if (event === 'enable' && state === 'idle') {
    if (optIn !== true) throw new Error('explicit DNS opt-in required');
    return next('preparing', 'install-guard', 'snapshot', 'start-adapter', 'probe-protected-dns');
  }
  if (event === 'failure' && state !== 'idle') return next('blocked', 'retain-guard-and-snapshot');
  if (event === 'external-change' && state !== 'idle') return next('conflict', 'retain-guard-and-snapshot');
  if (event === 'recover' && ['blocked', 'active', 'conflict'].includes(state)) {
    if (owned !== true) return next('conflict', 'retain-guard-and-snapshot');
    return next('preparing', 'install-guard', 'start-adapter', 'probe-protected-dns');
  }
  if (event === 'ready' && state === 'preparing') {
    if (owned !== true) return next('conflict', 'retain-guard-and-snapshot');
    return next('selecting', 'select-managed-dns');
  }
  if (event === 'selected' && state === 'selecting') return next('active');
  if (event === 'disable' && state === 'idle') return next('idle');
  if (event === 'disable' && !['idle', 'releasing'].includes(state)) {
    if (owned !== true) return next('conflict', 'retain-guard-and-snapshot');
    return next('restoring', 'restore-snapshot');
  }
  if (event === 'restored' && state === 'restoring') return next('releasing', 'remove-guard');
  if (event === 'released' && state === 'releasing') return next('idle', 'stop-adapter', 'forget-snapshot');
  throw new Error(`invalid DNS lifecycle transition: ${state}/${event}`);
}

export const DNS_SCENARIOS = Object.freeze({
  normal: ['enable', 'ready', 'selected', 'disable', 'restored', 'released'],
  outage: ['enable', 'ready', 'selected', 'failure', 'recover', 'ready', 'selected', 'disable', 'restored', 'released'],
  'startup-failure': ['enable', 'failure', 'disable', 'restored', 'released'],
  conflict: ['enable', 'ready', 'selected', 'external-change', 'disable'],
  'restore-failure': ['enable', 'ready', 'selected', 'disable', 'failure'],
});

export function dnsLifecycleDryRun(scenario = 'outage') {
  if (!Object.hasOwn(DNS_SCENARIOS, scenario)) throw new Error('unknown DNS lifecycle scenario');
  let state = 'idle', owned = true;
  const steps = DNS_SCENARIOS[scenario].map((event) => {
    if (event === 'external-change') owned = false;
    const result = dnsLifecycle(state, event, { optIn: true, owned });
    const step = { from: state, event, ...result }; state = result.state; return step;
  });
  return { schema: 1, mode: 'dry-run', systemDnsChanged: false, backend: 'unselected',
    persistentRecoveryImplemented: false, scenario, steps };
}
