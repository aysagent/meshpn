import assert from 'node:assert/strict';
export function tcpPort(value) {
  assert.match(String(value), /^[1-9][0-9]{0,4}$/, 'invalid_tcp_port');
  const port = Number(value);
  assert.ok(Number.isInteger(port) && port <= 65535, 'invalid_tcp_port');
  return port;
}
export function publishedExitPort(config, published) {
  assert.equal(config.role, 'exit', 'published_port_requires_exit');
  return `${tcpPort(published)}:${tcpPort(config.port)}/tcp`;
}
