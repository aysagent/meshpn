/** Offline boot protocol proposal. No effects, host reads or automatic adoption of a previous boot. */
import assert from 'node:assert/strict';

const phases = new Set(['cold', 'guarding', 'review', 'preparing', 'starting', 'probing', 'selecting',
  'active', 'blocked', 'disable-preparing', 'restoring', 'releasing', 'disabled']);
const bootId = (id) => assert.match(id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
export function dnsBootInitial(id) {
  bootId(id); return { bootId: id, phase: 'cold', guardVerified: false, admitted: false, journal: 'unchecked' };
}
export function dnsBootStep(state, event, evidence = {}) {
  assert.ok(state && phases.has(state.phase)); bootId(state.bootId);
  assert.equal(typeof state.guardVerified, 'boolean'); assert.equal(typeof state.admitted, 'boolean');
  assert.ok(['unchecked', 'missing', 'stale', 'current', 'released', 'corrupt'].includes(state.journal));
  const next = (phase, actions, extra = {}) => ({ state: { ...state, phase, admitted: phase === 'active' || phase === 'disabled', ...extra }, actions });
  const yes = (...keys) => keys.every((key) => evidence[key] === true);
  if (event === 'new-boot') {
    bootId(evidence.bootId); assert.notEqual(evidence.bootId, state.bootId);
    return { state: dnsBootInitial(evidence.bootId), actions: ['hold-workload-start', 'discard-runtime-readiness'] };
  }
  if (event === 'start' && state.phase === 'cold') {
    assert.ok(yes('optIn'), 'boot DNS policy requires explicit opt-in');
    return next('guarding', ['hold-workload-start', 'install-boot-guard']);
  }
  if (event === 'guard-confirmed' && state.phase === 'guarding') {
    assert.ok(yes('guardVerified'), 'guard acknowledgement required');
    return next('review', ['read-durable-intent', 'inspect-current-owner'], { guardVerified: true, journal: 'unchecked' });
  }
  if (event === 'guard-lost' && !['cold', 'disabled'].includes(state.phase)) {
    return next('guarding', ['hold-workload-start', 'install-boot-guard'], { guardVerified: false });
  }
  if (event === 'failure' && !['cold', 'disabled'].includes(state.phase)) {
    if (!state.guardVerified) return next('guarding', ['hold-workload-start', 'preserve-journal', 'install-boot-guard']);
    return next('blocked', ['hold-workload-start', 'preserve-journal', 'retain-guard']);
  }
  assert.ok(state.guardVerified || state.phase === 'disabled', 'guard is not verified');
  if (event === 'journal-inspected' && state.phase === 'review') {
    assert.ok(['missing', 'valid', 'corrupt'].includes(evidence.status));
    if (evidence.status === 'corrupt') return next('blocked', ['preserve-journal', 'manual-review'], { journal: 'corrupt' });
    if (evidence.status === 'missing') return next('review', ['manual-review'], { journal: 'missing' });
    bootId(evidence.journalBootId);
    if (evidence.journalBootId !== state.bootId || !yes('contextMatches')) {
      return next('review', ['preserve-journal', 'manual-review'], { journal: 'stale' });
    }
    if (evidence.released === true) return next('review', ['preserve-journal', 'manual-review'], { journal: 'released' });
    assert.equal(evidence.released, false);
    // A durable restore intent must not be converted to a protected apply by startup.
    assert.ok(['apply', 'restore'].includes(evidence.direction));
    if (evidence.direction === 'restore') return next('restoring', ['resume-current-boot-restore'], { journal: 'current' });
    return next('starting', ['resume-current-boot-intent', 'start-adapter'], { journal: 'current' });
  }
  if (event === 'authorize-new-epoch' && state.phase === 'review') {
    assert.ok(['missing', 'stale', 'released'].includes(state.journal));
    assert.ok(yes('operatorApproved', 'ownedLink', 'baselineVerified'), 'fresh ownership and explicit approval required');
    assert.ok(state.journal === 'missing' || yes('oldJournalPreserved'), 'do not overwrite the old journal');
    return next('preparing', ['snapshot-current-boot-baseline', 'persist-new-epoch-intent']);
  }
  if (event === 'intent-committed' && state.phase === 'preparing') {
    assert.ok(yes('durable', 'contextMatches')); return next('starting', ['start-adapter'], { journal: 'current' });
  }
  if (event === 'adapter-bound' && state.phase === 'starting') return next('probing', ['probe-protected-udp', 'probe-protected-tcp']);
  if (event === 'ready' && state.phase === 'probing') {
    assert.ok(yes('udpReady', 'tcpReady', 'contextMatches'));
    return next('selecting', ['apply-managed-dns-with-journal']);
  }
  if (event === 'selected' && state.phase === 'selecting') {
    assert.ok(yes('readBackMatches', 'contextMatches', 'durable')); return next('active', ['admit-protected-workload']);
  }
  if (event === 'retry' && state.phase === 'blocked') return next('review', ['inspect-current-owner', 'read-durable-intent']);
  if (event === 'disable' && ['active', 'blocked'].includes(state.phase)) {
    assert.equal(state.journal, 'current'); assert.ok(yes('operatorApproved', 'contextMatches'));
    return next('disable-preparing', ['hold-workload-start', 'persist-disable-intent']);
  }
  if (event === 'disable-committed' && state.phase === 'disable-preparing') {
    assert.ok(yes('durable', 'contextMatches')); return next('restoring', ['restore-current-boot-baseline']);
  }
  if (event === 'restored' && state.phase === 'restoring') {
    assert.ok(yes('readBackMatches', 'contextMatches', 'durable')); return next('releasing', ['remove-guard']);
  }
  if (event === 'guard-removed' && state.phase === 'releasing') {
    assert.ok(yes('removalVerified')); return next('disabled', ['admit-explicit-baseline'], { guardVerified: false, journal: 'released' });
  }
  throw new Error(`invalid DNS boot transition: ${state.phase}/${event}`);
}

export const DNS_BOOT_SCENARIOS = Object.freeze(['fresh', 'previous-boot', 'same-boot', 'corrupt', 'adapter-down', 'disable', 'power-loss']);
export function dnsBootDryRun(scenario = 'previous-boot') {
  assert.ok(DNS_BOOT_SCENARIOS.includes(scenario), 'unknown boot scenario');
  const first = '11111111-1111-1111-1111-111111111111', second = '22222222-2222-2222-2222-222222222222';
  let state = dnsBootInitial(first); const steps = [];
  const step = (event, evidence) => { const result = dnsBootStep(state, event, evidence); steps.push({ event, ...result }); state = result.state; };
  const guard = () => { step('start', { optIn: true }); step('guard-confirmed', { guardVerified: true }); };
  guard();
  if (scenario === 'previous-boot' || scenario === 'corrupt') {
    step('journal-inspected', scenario === 'corrupt' ? { status: 'corrupt' } : { status: 'valid', journalBootId: second, contextMatches: true });
  } else {
    if (scenario === 'same-boot') step('journal-inspected', { status: 'valid', journalBootId: first, contextMatches: true, released: false, direction: 'apply' });
    else {
      step('journal-inspected', { status: 'missing' });
      step('authorize-new-epoch', { operatorApproved: true, ownedLink: true, baselineVerified: true });
      step('intent-committed', { durable: true, contextMatches: true });
    }
    step('adapter-bound');
    if (scenario === 'adapter-down') step('failure');
    else {
      step('ready', { udpReady: true, tcpReady: true, contextMatches: true });
      step('selected', { readBackMatches: true, contextMatches: true, durable: true });
      if (scenario === 'disable') {
        step('disable', { operatorApproved: true, contextMatches: true }); step('disable-committed', { durable: true, contextMatches: true });
        step('restored', { readBackMatches: true, contextMatches: true, durable: true }); step('guard-removed', { removalVerified: true });
      }
      if (scenario === 'power-loss') {
        step('new-boot', { bootId: second }); guard();
        step('journal-inspected', { status: 'valid', journalBootId: first, contextMatches: true });
      }
    }
  }
  return { schema: 1, kind: 'dns-boot-proposal', mode: 'offline', scenario, systemDnsChanged: false,
    vmStarted: false, rebootTested: false, powerLossTested: false, steps };
}
