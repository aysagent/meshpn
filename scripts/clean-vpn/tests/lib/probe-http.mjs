import http from 'node:http';

export const PROBE_MARKER = 'clean-vpn-test-ok';
export const PROBE_EXIT_HOST = '10.99.0.1';
export const PROBE_EXIT_PORT = 18080;
export const PROBE_CLIENT_HOST = '10.99.0.2';
export const PROBE_CLIENT_PORT = 18081;

/**
 * @param {string} host
 * @param {number} port
 */
export function startProbeHttpServer(host, port) {
  const srv = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(PROBE_MARKER);
  });
  return new Promise((resolve, reject) => {
    srv.once('error', reject);
    srv.listen(port, host, () => resolve(srv));
  });
}
