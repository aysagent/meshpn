import path from 'path';
import { fileURLToPath } from 'url';
import { defaultLoopbackExt } from './tun-detect.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesTls = path.join(__dirname, '../fixtures/tls-test');
const fixturesProfile = path.join(__dirname, '../fixtures/boring-tls-profile.json');
const configDirect = path.join(__dirname, '../config/test-ice-direct.json');

/** @typedef {{ id: string, tier: number, transport: string, topology?: string, variant?: string, port: number, exitArgs: string[], clientArgs: string[], readyPattern: RegExp, clientTimeoutMs?: number, nodeExperimentalQuic?: boolean, skipReason?: string, platforms?: ('linux'|'darwin')[] }} TransportCase */

/** @type {Record<string, { client?: string[], exit?: string[] }>} */
export const VARIANTS = {
  base: {},
  'keep-alive-5': { client: ['--keep-alive=5'] },
  'http-vers-1.1': { client: ['--http-vers=1.1'], exit: ['--http-vers=1.1'] },
  'boring-profile': {
    client: [`--boring-tls-clienthello-profile=${fixturesProfile}`],
  },
  'boring-profile-strict': {
    client: [
      `--boring-tls-clienthello-profile=${fixturesProfile}`,
      '--boring-tls-profile-ja3-strict',
    ],
  },
  'ice-relay': { client: ['--ice-mode=relay'] },
};

const extLo = defaultLoopbackExt();

/**
 * @param {number} port
 * @param {string[]} extraExit
 * @param {string[]} extraClient
 * @param {Partial<TransportCase>} base
 * @returns {TransportCase}
 */
function caseBase(port, extraExit, extraClient, base) {
  return {
    port,
    exitArgs: extraExit,
    clientArgs: extraClient,
    readyPattern: /connected|TCP|WebSocket|DataChannel|готов|TLS|QUIC/i,
    clientTimeoutMs: 45000,
    ...base,
  };
}

/**
 * @param {{ tlsDir?: string, tierMax?: number, topology?: string, variant?: string, suite?: string, turn?: string|null, skipTier3?: boolean, boringHelper?: boolean, platforms?: string[] }} opts
 * @returns {TransportCase[]}
 */
export function expandCases(opts = {}) {
  const tlsDir = opts.tlsDir || fixturesTls;
  const variantFilter = opts.variant || 'base';
  const topologyFilter = opts.topology || 'exit-listens';
  const suite = opts.suite || 'smoke';
  /** @type {TransportCase[]} */
  const raw = [];

  const push = (/** @type {TransportCase} */ c) => raw.push(c);

  push(
    caseBase(
      8765,
      ['--role=exit', '--type=socket', '--server=127.0.0.1:8765', `--ext=${extLo}`],
      ['--role=client', '--type=socket', '--server=127.0.0.1:8765'],
      { id: 'socket', tier: 1, transport: 'socket', readyPattern: /TCP connected|connected/i },
    ),
  );
  push(
    caseBase(
      8766,
      ['--role=exit', '--type=http', '--server=127.0.0.1:8766', `--ext=${extLo}`],
      ['--role=client', '--type=http', '--server=127.0.0.1:8766'],
      { id: 'http', tier: 1, transport: 'http' },
    ),
  );
  push(
    caseBase(
      8767,
      [
        '--role=exit',
        '--type=websocket',
        '--ws-server',
        '--server=127.0.0.1:8767',
        `--ext=${extLo}`,
      ],
      ['--role=client', '--type=websocket', '--server=127.0.0.1:8767'],
      {
        id: 'websocket-exit-listens',
        tier: 1,
        transport: 'websocket',
        topology: 'exit-listens',
        readyPattern: /WebSocket connected/i,
      },
    ),
  );
  push(
    caseBase(
      8768,
      ['--role=exit', '--type=websocket', '--server=127.0.0.1:8768', `--ext=${extLo}`],
      [
        '--role=client',
        '--type=websocket',
        '--ws-server',
        '--server=0.0.0.0:8768',
      ],
      {
        id: 'websocket-client-listens',
        tier: 3,
        transport: 'websocket',
        topology: 'client-listens',
        readyPattern: /WebSocket connected/i,
        clientTimeoutMs: 60000,
      },
    ),
  );

  push(
    caseBase(
      8771,
      ['--role=exit', '--type=udp', '--server=127.0.0.1:8771', `--ext=${extLo}`],
      ['--role=client', '--type=udp', '--server=127.0.0.1:8771'],
      { id: 'udp', tier: 2, transport: 'udp', readyPattern: /UDP|connected|TUN/i },
    ),
  );

  push(
    caseBase(
      8443,
      [
        '--role=exit',
        '--type=tls',
        '--server=127.0.0.1:8443',
        `--tls-cert-dir=${tlsDir}`,
        `--ext=${extLo}`,
      ],
      [
        '--role=client',
        '--type=tls',
        '--server=127.0.0.1:8443',
        `--tls-cert-dir=${tlsDir}`,
        '--tls-server-name=clean-vpn',
      ],
      { id: 'tls', tier: 2, transport: 'tls', clientTimeoutMs: 60000 },
    ),
  );

  if (opts.boringHelper) {
    push(
      caseBase(
        8443,
        [
          '--role=exit',
          '--type=tls',
          '--server=127.0.0.1:8443',
          `--tls-cert-dir=${tlsDir}`,
          `--ext=${extLo}`,
        ],
        [
          '--role=client',
          '--type=boring-tls',
          '--server=127.0.0.1:8443',
          `--tls-cert-dir=${tlsDir}`,
          '--tls-server-name=clean-vpn',
        ],
        { id: 'boring-tls', tier: 2, transport: 'boring-tls', clientTimeoutMs: 90000 },
      ),
    );
  } else {
    push({
      id: 'boring-tls',
      tier: 2,
      transport: 'boring-tls',
      port: 8443,
      exitArgs: [],
      clientArgs: [],
      readyPattern: /.*/,
      skipReason: 'boring-tls-helper not built',
    });
  }

  push(
    caseBase(
      8444,
      [
        '--role=exit',
        '--type=quic-ext',
        '--server=127.0.0.1:8444',
        `--quic-certs-dir=${tlsDir}`,
        `--ext=${extLo}`,
      ],
      [
        '--role=client',
        '--type=quic-ext',
        '--server=127.0.0.1:8444',
        `--quic-certs-dir=${tlsDir}`,
      ],
      { id: 'quic-ext', tier: 2, transport: 'quic-ext', clientTimeoutMs: 60000 },
    ),
  );

  const pubName = 'clean-vpn.test';
  push(
    caseBase(
      8450,
      [
        '--role=exit',
        '--type=transparent-tls',
        '--server=127.0.0.1:8450',
        `--tls-public-name=${pubName}`,
        `--tls-cert-dir=${tlsDir}`,
        `--ext=${extLo}`,
      ],
      [
        '--role=client',
        '--type=transparent-tls',
        '--server=127.0.0.1:8450',
        `--tls-public-name=${pubName}`,
        `--tls-cert-dir=${tlsDir}`,
        '--tunnel-peer=127.0.0.1:9',
      ],
      { id: 'transparent-tls', tier: 2, transport: 'transparent-tls', clientTimeoutMs: 60000 },
    ),
  );

  if (opts.boringHelper) {
    push(
      caseBase(
        8451,
        [
          '--role=exit',
          '--type=combo-tls',
          '--server=127.0.0.1:8451',
          `--tls-public-name=${pubName}`,
          `--tls-cert-dir=${tlsDir}`,
          `--ext=${extLo}`,
        ],
        [
          '--role=client',
          '--type=combo-tls',
          '--server=127.0.0.1:8451',
          `--tls-public-name=${pubName}`,
          `--tls-cert-dir=${tlsDir}`,
          '--tunnel-peer=127.0.0.1:9',
          '--tls-server-name=clean-vpn',
        ],
        { id: 'combo-tls', tier: 2, transport: 'combo-tls', clientTimeoutMs: 90000 },
      ),
    );
  }

    if (!opts.skipTier3) {
    push(
      caseBase(
        8772,
        [
          '--role=exit',
          '--type=udp',
          '--signaling',
          '--punch',
          '--server=127.0.0.1:8772',
          `--ext=${extLo}`,
          `--config=${configDirect}`,
        ],
        [
          '--role=client',
          '--type=udp',
          '--punch',
          '--server=127.0.0.1:8772',
          `--config=${configDirect}`,
        ],
        {
          id: 'udp-punch-exit-listens',
          tier: 3,
          transport: 'udp',
          topology: 'exit-listens',
          clientTimeoutMs: 120000,
        },
      ),
    );

    push(
      caseBase(
        9876,
        [
          '--role=exit',
          '--type=webrtc',
          '--signaling',
          '--server=127.0.0.1:9876',
          `--ext=${extLo}`,
          `--config=${configDirect}`,
        ],
        [
          '--role=client',
          '--type=webrtc',
          '--server=127.0.0.1:9876',
          `--config=${configDirect}`,
          '--ice-mode=direct',
          '--allow-host-candidates',
        ],
        {
          id: 'webrtc-exit-listens',
          tier: 3,
          transport: 'webrtc',
          topology: 'exit-listens',
          readyPattern: /DataChannel|готов|connected/i,
          clientTimeoutMs: 90000,
        },
      ),
    );
    push(
      caseBase(
        9877,
        [
          '--role=exit',
          '--type=webrtc',
          '--server=127.0.0.1:9877',
          `--ext=${extLo}`,
          `--config=${configDirect}`,
        ],
        [
          '--role=client',
          '--type=webrtc',
          '--signaling',
          '--server=0.0.0.0:9877',
          `--config=${configDirect}`,
          '--ice-mode=direct',
          '--allow-host-candidates',
        ],
        {
          id: 'webrtc-client-listens',
          tier: 3,
          transport: 'webrtc',
          topology: 'client-listens',
          clientTimeoutMs: 90000,
        },
      ),
    );

    if (opts.turn) {
      const relayCfg = path.join(__dirname, '../config/test-ice-relay.json');
      push(
        caseBase(
          9878,
          [
            '--role=exit',
            '--type=webrtc',
            '--signaling',
            '--server=127.0.0.1:9878',
            `--ext=${extLo}`,
            `--config=${relayCfg}`,
          ],
          [
            '--role=client',
            '--type=webrtc',
            '--server=127.0.0.1:9878',
            `--config=${relayCfg}`,
            '--ice-mode=relay',
          ],
          {
            id: 'webrtc-relay',
            tier: 3,
            transport: 'webrtc',
            variant: 'ice-relay',
            clientTimeoutMs: 120000,
          },
        ),
      );
    }
  }

  /** @type {TransportCase[]} */
  const out = [];
  for (const c of raw) {
    if (c.skipReason) {
      out.push(c);
      continue;
    }
    if (opts.tierMax != null && c.tier > opts.tierMax) continue;
    if (opts.transport && c.transport !== opts.transport && c.id !== opts.transport) continue;

    const top = c.topology || 'exit-listens';
    if (topologyFilter === 'exit-listens' && top === 'client-listens') continue;
    if (topologyFilter === 'client-listens' && top !== 'client-listens') continue;

    const variants =
      suite === 'keep-alive'
        ? ['keep-alive-5']
        : suite === 'boring-profile' && ['boring-tls', 'combo-tls'].includes(c.transport)
          ? ['boring-profile', 'boring-profile-strict']
          : variantFilter === 'all'
            ? ['base', 'keep-alive-5']
            : [variantFilter];

    for (const v of variants) {
      if (v === 'ice-relay' && !opts.turn) continue;
      if (v.startsWith('boring-profile') && !['boring-tls', 'combo-tls'].includes(c.transport))
        continue;
      if (v === 'http-vers-1.1' && !['tls', 'boring-tls', 'combo-tls'].includes(c.transport))
        continue;
      if (v === 'keep-alive-5' && ['udp', 'quic-ext', 'transparent-tls'].includes(c.transport))
        continue;

      const va = VARIANTS[v] || VARIANTS.base;
      out.push({
        ...c,
        id: `${c.id}${v === 'base' ? '' : `-${v}`}`,
        variant: v,
        exitArgs: [...c.exitArgs, ...(va.exit || [])],
        clientArgs: [...c.clientArgs, ...(va.client || [])],
      });
    }
  }
  return out;
}
