import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

test('autostart unit template leaves all three rollback budgets and signals main process first', () => {
  const source = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const unit = source.split('cat > "$UNIT_PATH" <<EOF\n')[1]?.split('\nEOF')[0];
  assert.ok(unit, 'main service template exists');
  assert.match(unit, /^KillMode=mixed$/m);
  const timeout = /^TimeoutStopSec=(\d+)$/m.exec(unit);
  assert.ok(timeout); assert.ok(Number(timeout[1]) >= 120 + 120 + 120 + 60);
  assert.match(unit, /^Restart=always$/m);
  assert.match(unit, /^ExecStart=\$RUN_SH$/m);
  // This is a template contract, not an actual PID1/boot lifecycle test.
});
test('installer validates guard configuration before writes and passes management port', () => {
  const source = readFileSync(new URL('./autostart/install.sh', import.meta.url), 'utf8');
  const preflight = source.indexOf('bash "$KS_SRC" plan');
  assert.ok(preflight > 0 && preflight < source.indexOf('cat > "$RUN_SH"'));
  assert.match(source, /KS_SSH_PORT="\$\{KS_SSH_PORT:-22\}"/);
  assert.match(source, /KS_UP_ARGS="up .*--ssh-port=\$KS_SSH_PORT"/);
});
test('uninstaller retains recovery files when stop or guard removal fails', () => {
  const source = readFileSync(new URL('./autostart/uninstall.sh', import.meta.url), 'utf8');
  assert.match(source, /systemctl stop "\$SERVICE_NAME" \|\| die/);
  assert.match(source, /systemctl stop "\$KS_UNIT_NAME" \|\| die/);
  assert.match(source, /"\$KS_SH" down --tun=tun0 \|\| die/);
  assert.ok(source.indexOf('"$KS_SH" down') < source.indexOf('systemctl disable "$SERVICE_NAME"'));
  assert.ok(source.indexOf('"$KS_SH" down') < source.indexOf('rm -f "$f"'));
});
