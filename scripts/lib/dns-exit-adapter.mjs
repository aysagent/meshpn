/** Explicit loopback DNS listener, public resolver identity, numeric exit only. */
import { createDnsExitTransport } from './dns-exit-transport.mjs';
import { startLabDohStub } from './lab-doh-stub.mjs';

export async function startDnsExitAdapter({ profile, exitAddress, exitPort, publicName, secret,
  port = 0, timeoutMs = 1500, maxInflight = 16, maxTcpConnections = 16, tcpLifetimeMs = 5000, domainPolicy } = {}) {
  const transport = createDnsExitTransport({ profile, exitAddress, exitPort, publicName, secret });
  let stub, closePromise;
  try { stub = await startLabDohStub({ exitTransport: transport, port, timeoutMs, maxInflight, maxTcpConnections, tcpLifetimeMs, domainPolicy }); }
  catch (error) { await transport.close(); throw error; }
  return { port: stub.port, stats: () => ({ stub: stub.stats(), transport: transport.stats() }),
    close() {
      closePromise ??= (async () => { try { await stub.close(); } finally { await transport.close(); } })();
      return closePromise;
    } };
}
