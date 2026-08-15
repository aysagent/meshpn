#!/usr/bin/env node
/**
 * Минимальный VPN поверх TCP/WebSocket/UDP/WebRTC/QUIC (node:quic / @infisical/quic) + Linux TUN (native N-API addon).
 * Без шифрования и авторизации.
 *
 * Требования: Linux, sudo, собранный addon `native/tun_linux` (`npm run build:tun-linux`; python3, make, g++).
 * После `npm install` addon собирается в postinstall (ошибка сборки не роняет install — тогда соберите вручную).
 * Основной mesh (`src/network/tun.js`) по-прежнему может использовать бинарь `helpers/tun-helper` из `cd helpers && make`.
 *
 * Exit (VPS): tun + NAT в интернет, без split-default.
 * Client: tun + split-default (опция, только IPv4 default), маршрут к --server через uplink.
 * Без --split-default на TUN всё равно может попадать трафик: к VPN-peer (point-to-point, напр. 10.99.0.1), IPv6 link-local/ND/RA
 * на интерфейсе tun при включённом IPv6 на хосте. Мостируем только валидный IPv4; cooldown по idle не заменяет этот фильтр.
 * USB gadget / клиент как роутер: с `--split-default` опционально `--client-lan-subnet=192.168.7.0/24` — ip_forward + iptables SNAT LAN→10.99.0.2 через tun и FORWARD; иначе в VPN доходят пакеты в основном с самого клиента (src уже туннельный).
 *
 * Протокол (socket / http после преамбулы): uint32 BE + сырой IPv4-пакет (как у прежнего tun-helper по транспорту).
 * WebSocket / UDP: одно binary-сообщение или одна датаграмма = один IPv4-пакет (без префикса длины).
 * WebRTC DataChannel через Puppeteer (--type=rtc-chrome): client — Chrome + RTCPeerConnection к exit `--type=webrtc`, сигналинг как у webrtc, TUN ↔ локальный WS; `npm install puppeteer`.
 * WebSocket через Puppeteer (--type=ws-chrome): на client Headless Chrome держит исходящий WS к exit; `npm install puppeteer`.
 *   По умолчанию данные идут через локальный ws://127.0.0.1 (без CDP на каждый пакет). Медленный путь: --ws-chrome-cdp-data или CLEAN_VPN_WS_CHROME_CDP_DATA=1.
 *   --ws-chrome-url=... (произвольная страница) — только CDP-путь. exit --type=ws-chrome --ws-server + GET /clean-vpn-chrome; Puppeteer с --ws-chrome-exit-page без CDP использует setContent (тот же быстрый мост).
 *   Chrome: --ws-chrome-executable=PATH или PUPPETEER_EXECUTABLE_PATH; в контейнере: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
 *   Linux ARM64/ARM (Radxa, Multipass на Apple Silicon): бандл Puppeteer часто x86_64 (…/chrome-linux64/…) — ставьте `chromium` из apt и `--ws-chrome-executable` / `--rtc-chrome-executable` или `PUPPETEER_EXECUTABLE_PATH`; без системного Chromium на ARM скрипт не использует кэш Puppeteer.
 *   Локальный 127.0.0.1 WS auth (Phase 1 / H-4): URL содержит `?t=<32hex random>` (16 байт), проверка constant-time. Чужие процессы на хосте без secret в connect-URL не могут подключиться к локальному мосту. Применяется и для ws-chrome (Dual bridge), и для rtc-chrome (локальный WS).
 * WebRTC: сигналинг по WebSocket; слушать только с --signaling на этой ноде, иначе исходящий WS к --server (exit и client). Алиас: --signalling. Один SCTP DataChannel — одно бинарное сообщение = один IPv4-пакет.
 *   ICE host-candidate filter (Phase 1 / M-5): по умолчанию `typ host` и `typ prflx` для RFC1918 / loopback / IPv6 ULA / link-local отбрасываются (в исходящих local-candidate'ах и во входящих remote). `srflx`/`relay` остаются. Защита от утечки внутренних IP. Opt-out: `--allow-host-candidates`.
 *   Signaling bind (Phase 2 / C-2): первое сообщение сигналинга `clean-vpn-bind` (webrtc/rtc-chrome) или `clean-vpn-udp-bind` (udp punch) подписано HMAC(clean-vpn-hmac.key, ts || nonce || dtls_fingerprint?), проверяется обеими сторонами; nonce защищает от replay, окно ts ±5 мин. Для webrtc дополнительно сверяется, что `a=fingerprint` в принятом SDP совпадает с подписанным — MITM сигналинга не может подсунуть свой DTLS-fingerprint. Без PSK (`clean-vpn-hmac.key`) запуск падает; для отладки: `--signaling-psk-required=false`.
 * ICE/STUN/TURN: из --config (по умолчанию config/default.json), см. --ice-mode; при --split-default client добавляет /32 bypass к IP STUN/TURN только для webrtc/rtc-chrome/ws-chrome и udp --punch (plain udp STUN не резолвит).
 * QUIC (Node 25+): нативный node:quic, ALPN clean-vpn, один bidi stream = тот же uint32+IPv4, что TCP.
 *   Нужен бинарь Node, собранный с QUIC (в рантайме: node -p "process.config.variables.node_use_quic" — должно быть истинно); одного флага --experimental-quic недостаточно, если модуль не вкомпилирован (часто apt/snap).
 *   Запуск: node --experimental-quic …  TLS: ca.pem / cert.pem / key.pem в certs/ (создаются через openssl при отсутствии).
 * QUIC-EXT (--type=quic-ext): пакет @infisical/quic (quiche), Node 18+, без node:quic и без --experimental-quic.
 *   Тот же UDP host:port и фрейминг uint32+IPv4 по одному bidi stream. ALPN: clean-vpn-ext (должен совпадать на обеих сторонах).
 *   TLS: те же ca.pem / cert.pem / key.pem (--quic-certs-dir). Дополнительно — общий HMAC-ключ (см. ниже «Общий HMAC PSK»); только на exit для stateless retry, на client+quic-ext не нужен.
 *
 * Общий HMAC PSK (clean-vpn-hmac.key, 32 байта в --tls-cert-dir / --quic-certs-dir):
 *   Используется одновременно для stateless retry в QUIC-EXT и Bearer-токена в --type=tls.
 *   На exit создаётся автоматически при отсутствии. На client + --type=tls должен лежать идентичный файл, скопированный с exit.
 *   Явный путь: --shared-hmac-key=PATH (обе стороны). Legacy alias: --quic-ext-crypto-key=PATH; legacy-имя файла quic-ext-hmac.key всё ещё читается, но новые файлы создаются как clean-vpn-hmac.key.
 *
 * Пример:
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=socket
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=socket --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=http
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=http --split-default
 *   HTTP (--type=http): тот же TCP, что socket; клиент — GET /clean-vpn, ответ 200, затем uint32+IPv4 (см. строку «Протокол» выше).
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=websocket --ws-server
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=websocket --split-default
 *   WebSocket «NAT»: client на VPS слушает (--ws-server), exit коннектится без флага к VPS:PORT; при --split-default bypass к пиру по remoteAddress или --tunnel-peer.
 *   sudo ... --role=client --server=0.0.0.0:8765 --type=websocket --ws-server --split-default
 *   sudo ... --role=exit --server=VPS:8765 --type=websocket --ext=eth0
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=ws-chrome --ws-server
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:8765 --type=ws-chrome --split-default [--ws-chrome-exit-page]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:51820 --type=udp
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:51820 --type=udp --split-default
 *   UDP hole punching: на exit в одном процессе UDP на PORT и сигналинг WebSocket на PORT+1 (`--signaling --punch`), STUN из `--config` (нужен stun: в iceServers). Клиент: `--type=udp --punch --server=VPS:PORT` — сигналинг к `ws://VPS:(PORT+1)/`. Relay нет; при жёстком NAT используйте webrtc или путь с белым IP.
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:9876 --type=webrtc --signaling [--config=config/exit-node.json]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:9876 --type=webrtc --split-default --ice-mode=relay
 *   Сигналинг на VPS: client --server=0.0.0.0:9876 --type=webrtc --signaling --split-default; exit --server=VPS:9876 --type=webrtc --ext=eth0 (без --signaling — исходящий WS к VPS)
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:9876 --type=rtc-chrome --split-default [--config=...] [--rtc-chrome-executable=...]
 *   sudo env PATH=$PATH node --experimental-quic scripts/clean-vpn.js --role=exit --server=0.0.0.0:4433 --type=quic
 *   sudo env PATH=$PATH node --experimental-quic scripts/clean-vpn.js --role=client --server=VPS:4433 --type=quic --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:4433 --type=quic-ext
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:4433 --type=quic-ext --split-default
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:443 --type=tls [--tls-cert-dir=...] [--tls-public-name=vpn.example.com] [--tls-probe-target=host:port] [--shared-hmac-key=PATH]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:443 --type=tls --split-default [--tls-server-name=...] [--shared-hmac-key=PATH]
 *   sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=VPS:443 --type=boring-tls --split-default [--tls-server-name=...] — TLS через native/boring_tls/boring-tls-helper (см. scripts/boring-tls-plan.md); exit по-прежнему `--type=tls`.
 *   combo-tls (`--type=combo-tls`): обе стороны **одним** `--server=…:443` — **exit** один TCP listen; поток начинающийся префиксом enc-SNI relay (`*.--tls-public-name`, raw TCP TLS) → HTTPS; иначе → VPN **TLS mux** как `--type=tls`. **BREAKING:** CVPTX удалён; `--tls-public-name` обязателен.
 * transparent-tls (`--type=transparent-tls`): TUN socket mux + enc-SNI v2 (base62) HTTPS intercept; exit: `0x16` → relay, иначе IPv4 в TUN. **BREAKING:** `--tls-public-name` обязателен; base32hex v1 enc-SNI не поддерживается.
 * TLS (--type=tls): TCP + TLS 1.3 only, ALPN в ClientHello по умолчанию [h2, http/1.1]; маркера VPN в открытой части нет.
 *   После рукопожатия: при согласованном `h2` — VPN поверх HTTP/2 (`POST /clean-vpn` + Bearer, двусторонний DATA на одном stream); при `http/1.1` — как раньше `GET /clean-vpn` с Bearer и hijack сокета после ответа 200.
 *   Флаг `--http-vers=1.1` (обе стороны): только HTTP/1.1 и только ALPN `http/1.1` — для отладки и регрессии GET-пути.
 *   Авторизация: `Authorization: Bearer <token>`; token = HMAC-SHA256 от общего HMAC PSK, **TLS exporter** (RFC 5705, label=EXPORTER-clean-vpn-bind, 32 байта) данной сессии и текущего 15-минутного окна — channel-binding (Phase 2 / H-1+H-2). Перехваченный Bearer вне той самой TLS-сессии не работает (exporter уникален per-session).
 *   Legacy v1 (без exporter) принимается с warning `bearer_legacy=1`; используйте только для миграции, удалите в следующем миноре. Совместимость fallback: старый Node без `exportKeyingMaterial` / старый boring-tls-helper без `exporter` в ok-frame → v1.
 *   Совпало → exit отвечает 200 (`:status` при h2 или HTTP/1.1) и поднимает прежний uint32+IPv4 туннель; иначе — отдаёт `It works!` как обычный HTTPS-сайт.
 *   Cover-page rate-limit (Phase 1 / M-1): per-IP лимит 10 cover-ответов за 60s; превышение — `socket.destroy()` без ответа. Tuning: CLEAN_VPN_TLS_COVER_RL_MAX / CLEAN_VPN_TLS_COVER_RL_WINDOW_MS. Успешный VPN-handshake счётчик не двигает.
 *   Peek-timeout / pending-peek limit (Phase 1 / M-4): combo-tls и transparent-tls exit-диспатч — ждут первые 8 байт ≤10s (CLEAN_VPN_EXIT_PEEK_TIMEOUT_MS), глобальный лимит одновременных pending peek 1000 (CLEAN_VPN_EXIT_PEEK_MAX); превышение → destroy без ответа. Защита от slow-loris по pending peek.
 *   Ключ — общий «clean-vpn-hmac.key», см. отдельный раздел выше; явный путь --shared-hmac-key=PATH (legacy --quic-ext-crypto-key).
 *   Exit: --tls-cert-dir, --tls-public-name (если задан, SNI в Hello должен совпасть с одним из перечисленных имён, через запятую; иначе passthrough), --tls-probe-target (куда passthrough при SNI mismatch / parse_fail). Passthrough и локальный TLS-сервер выбираются по разбору ClientHello и SNI/public-name, не по значению ALPN (настоящий активный пробинг не использует «магических» протоколов в ALPN). Флаг --tls-server-name на exit не читается (только client).
 *   Сертификаты: --tls-cert-dir с fullchain.pem+privkey.pem (Let's Encrypt) или, как у QUIC, ca.pem+cert.pem+key.pem.
 *   Рекомендация: для production используйте Let's Encrypt (fullchain.pem + privkey.pem в --tls-cert-dir). Self-signed (ensureQuicCerts) — fallback для отладки; с Phase 1 в auto-gen добавляется SAN из --server / --tls-public-name, поэтому Node-клиент проходит hostname-verification без `checkServerIdentity` workaround, но клиенту всё равно нужен ca.pem с exit'а в --tls-cert-dir.
 *   Внимание: passthrough на сторонний хост может нарушать ToS сервиса и законы юрисдикции — только на свой страх и риск.
 *   Client: --tls-server-name — имя для проверки сертификата (и SNI в ClientHello, если не задан --tls-client-sni).
 *   Не используйте `--tls-server-name=www.google.com` только ради маскировки SNI: это имя проверки CN/SAN, при сертификате exit с CN clean-vpn рукопожатие завершится ERR_TLS_CERT_ALTNAME_INVALID. При IP без имени проверки уже берётся clean-vpn и SNI по умолчанию www.google.com; свой SNI — `--tls-client-sni`.
 *   Если в --server указан IP, без --tls-server-name для проверки используется clean-vpn (как у ca/cert из репо); для LE на exit укажите --tls-server-name=ваш.домен.
 *   --tls-client-sni=HOST (опционально): явный ClientHello SNI; проверка cert через --tls-server-name / host / clean-vpn.
 *   Если не задан: при проверке имени clean-vpn (типично --server=IP без --tls-server-name) в ClientHello по умолчанию SNI www.google.com; иначе SNI совпадает с именем проверки.
 *   BREAKING: старые `--type=tls` пиры (с ALPN `clean-vpn-tls`) подключиться не смогут — нужно обновлять обе стороны и иметь общий clean-vpn-hmac.key.
 *   Split-default: маршруты 0.0.0.0/1 + 128.0.0.0/1 — только IPv4; плюс 10/8, 172.16/12, 192.168/16 через uplink (DNS/LAN не на exit). IPv6 default не трогается. Проверка внешнего IPv4: curl -4 https://ifconfig.me (без -4 curl может выбрать IPv6).
 *
 * --keep-alive=N (N > 0): простой N-секундный idle по трафику TUN↔транспорт на этой стороне; при разрыве
 * (idle или закрытие пира) client снова поднимает провод по первому валидному IPv4 с TUN (lazy), exit/inbound —
 * по новому входящему соединению. Флаг асимметричен: достаточно на client или exit. Без N на client исходящие
 * транспорты подключаются сразу, но переподключение после разрыва пира — по TUN/inbound как выше.
 * TCP (transport=tcp): idle на стороне TCP-сервера (inbound accept) — FIN (`socket.end`); TCP-клиент (outbound
 * connect, в т.ч. exit с исходящим WS) TUN снимает без FIN, ждёт FIN сервера и отвечает FIN. Таймаут:
 * CLEAN_VPN_TCP_GRACEFUL_CLOSE_MS (default 5000). Ошибки/framing/перезапуск пира — destroy (RST).
 * RST также при write/read ECONNRESET|EPIPE и при данных на idle-disarm сокете. WS/WebRTC/UDP — без изменений.
 * Честный FIN (.end()) — только для настоящего net.Socket (raw socket, native tls, exit); socket-like
 * поверх JSStream/h2/quic (boring-tls, combo-tls на client, QUIC) закрываются через destroy() —
 * иначе .end() пишет в закрытый JSStream и роняет процесс (ERR_INTERNAL_ASSERTION в JSStreamSocket.doWrite).
 * не-IPv4 (в т.ч. IPv6 с tun) не ставится в очередь и не уходит на wire — не поднимает сессию после idle.
 * --keep-alive-reconnect-cooldown=M: после разрыва по idle M с не поднимать lazy по TUN (IPv4 в этот интервал отбрасываются);
 * по истечении M с следующий IPv4 снова может подключить lazy — это ожидаемо, не «вечная» блокировка.
 * CLEAN_VPN_KEEPALIVE_DEBUG=1: лог ip-протокола/длины при lazy/cooldown и отбросе не-IPv4 (версия из старших 4 бит байта 0 + первые 8 байт hex).
 * CLEAN_VPN_TLS_MUX_DEBUG=1 (exit|client + tls|boring-tls|combo-tls): лог до разбора ClientHello на exit (таймаут/close/error, первый chunk hex); на client — TCP connect и гипотеза при таймауте handshake (`tls`; для `boring-tls`/`combo-tls` TUN — рукопожатие в helper — см. stderr helper).
 * JA3/JA4 (опционально): `CLEAN_VPN_TLS_LOG_JA3=1` и/или `--tls-log-ja3`; выводятся **JA3 wire**, **JA3 sorted** MD5, **JA4** (FoxIO JA4.md), **JA4 alt**, **JA4 raw_o**, **JA4 raw_r** (JA4.md — средний сегмент без 0000/0010), **JA4 raw_r_alt** (стиль ja3.zone: средний сегмент с SNI 0000, без ALPN 0010). `--ja3-verbose` дополняет компоненты JA4 и stderr helper. Цифры **1516** в середине `ja4_a` — счётчики шифров и **расширений без GREASE на проводе**; 17→16 значит с wire реально пропал один тип расширения (часто padding `0015`), а не ошибка формулы JA4. Exit + `--type=tls`: JA3/JA4 входящего ClientHello из mux; exit + `combo-tls` — то же для ветви tls, плюс лог enc-SNI relay как у `transparent-tls`. Client + `boring-tls` или `combo-tls` (мост TUN): stderr helper и строки `[clean-vpn] boring-tls …`. Для `--type=tls` в Node отпечаток в том же процессе не считается — смотрите лог exit или используйте на клиенте boring-tls либо combo-tls.
 * Шум IPv6 на tun при желании уменьняют вручную (отключение IPv6 на интерфейсе, sysctl) — скрипт это не автоматизирует.
 * QUIC/quic-ext в v1 без изменений (флаг на них не действует). Pong WS на idle не влияет.
 *
 * При SIGINT/SIGTERM и при uncaughtException/unhandledRejection: снимаются iptables/NAT (exit),
 * net.ipv4.ip_forward, маршруты и rp_filter (client) восстанавливаются по снимку `ip -json route`.
 *
 * Производительность (Linux, опционально, вручную):
 *   Высокий PPS / UDP / QUIC: увеличить лимиты сокетных буферов ядра, например:
 *   `sudo sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728`
 *   При узких TCP-окнах при необходимости смотреть `net.ipv4.tcp_rmem` / `tcp_wmem` (зависит от сценария).
 *   Аномалии фрагментации или латентности на физическом NIC: `ethtool -k <iface>` (иногда GRO/LRO влияют на кейс).
 */

import { execFileSync, spawn } from 'child_process';
import { EventEmitter, once } from 'events';
import { createRequire } from 'module';
import { createHmac, createPrivateKey, randomBytes, timingSafeEqual } from 'crypto';
import dgram from 'dgram';
import fs from 'fs';
import http from 'http';
import http2 from 'http2';
import net from 'net';
import tls from 'tls';
import path from 'path';
import process from 'process';
import { Duplex, Readable, Writable } from 'stream';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import WebSocket from 'ws';
import dns from 'dns/promises';
import {
  extractFirstClientHelloBody,
  ja3DebugFromTcpBuf,
  ja3FromTcpBuf,
  parseFirstTlsClientHelloFromTcpBuf,
} from './lib/tls-clienthello-ja3.mjs';
import { ja4FromTcpBuf } from './lib/tls-clienthello-ja4.mjs';
import {
  profileFileToHelperClientHelloBlock,
  readClienthelloProfileFileSync,
} from './lib/boring-tls-clienthello-profile.mjs';
import {
  attachTransparentTlsClientSession,
  classifyComboTlsExitPrefix,
  logComboTlsClientBranch,
  logComboTlsExitBranch,
  logNonTlsExitDispatch,
  peekPrefixDescribe,
  wireTransparentTlsEncSniSession,
} from './lib/transparent-tls-runtime.mjs';
// node-datachannel — native addon; только для --type=webrtc (не rtc-chrome). Lazy import в ensureNodeDatachannelLoaded().
// @matrixai/logger — CJS; в ESM класс лежит в .default, не в корне namespace.
import matrixAiLogger from '@matrixai/logger';
const LoggerClass = matrixAiLogger.default ?? matrixAiLogger;
const { LogLevel, StreamHandler } = matrixAiLogger;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const requireAddon = createRequire(import.meta.url);
const TUN_LINUX_ADDON = path.join(__dirname, '../native/tun_linux/build/Release/tun_linux.node');

/** @type {{ open: (name: string) => object }|null} */
let tunLinuxAddonCache = null;

function loadTunLinuxAddon() {
  if (tunLinuxAddonCache) return tunLinuxAddonCache;
  try {
    tunLinuxAddonCache = requireAddon(TUN_LINUX_ADDON);
  } catch (e) {
    throw new Error(
      `Не удалось загрузить native TUN (${TUN_LINUX_ADDON}). Соберите: npm run build:tun-linux (нужны python3, make, g++; только Linux).`,
      { cause: e },
    );
  }
  return tunLinuxAddonCache;
}

/**
 * Открывает TUN через N-API addon (без subprocess tun-helper).
 * @param {string} tunName — желаемое имя, например tun0
 * @returns {{ tun: { ifname: string, write: (b: Buffer) => void, startRead: (cb: (batch: ArrayBuffer[]) => void) => void, close: () => void }, name: string }}
 */
function openTunNative(tunName) {
  const addon = loadTunLinuxAddon();
  const tun = addon.open(tunName);
  return { tun, name: tun.ifname };
}

// =============================================================================
// === Константы: native TUN addon, адреса VPN, SCTP, пути конфигов, ALPN ===
// =============================================================================

const TUN_MTU = 1400;
const MAX_PKT = 65535;
const IP_EXIT = '10.99.0.1';
const IP_CLIENT = '10.99.0.2';

/** После iptables OUTPUT REDIRECT/tcp:443 здесь живёт локальный intercept transparent-tls. */
const TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT = 8443;
const TRANSPARENT_TLS_IPT_COMMENT = `clean-vpn-ttl:${process.pid}`;

/** Опции моста TUN для exit / client (`attachTunBridge`). */
const BRIDGE_OPTS_EXIT = { localTunIp: IP_EXIT };
const BRIDGE_OPTS_CLIENT = { localTunIp: IP_CLIENT };

/** Макс. IPv4-пакетов с TUN в очереди на время lazy-connect (keep-alive). */
const KEEPALIVE_TUN_QUEUE_MAX = 256;

/** Транспорты с единым мостом и reconnectWire (асимметричный keep-alive). */
const RECONNECT_BRIDGE_TRANSPORTS = new Set([
  'tcp',
  'websocket',
  'udp-client',
  'udp-server',
  'webrtc-dc',
]);

function safe(fn) {
  try {
    fn();
  } catch {
    /* ignore */
  }
}

/** @typedef {{ exitCode: number, reason: string, err?: unknown }} CleanVpnEmergencyOpts */

/** @type {((opts: CleanVpnEmergencyOpts) => void) | null} */
let cleanVpnEmergencyShutdown = null;
let cleanVpnFatalHandlersInstalled = false;
let cleanVpnFatalCleanupStarted = false;

/**
 * Регистрирует полный или минимальный shutdown (маршруты/NAT/tun) для аварийного выхода.
 * @param {(opts: CleanVpnEmergencyOpts) => void} fn
 */
function registerCleanVpnEmergencyShutdown(fn) {
  cleanVpnEmergencyShutdown = fn;
}

function clearCleanVpnEmergencyShutdown() {
  cleanVpnEmergencyShutdown = null;
}

/**
 * @param {string} reason
 * @param {unknown} [err]
 * @param {number} [exitCode=1]
 */
function invokeCleanVpnEmergencyShutdown(reason, err, exitCode = 1) {
  if (cleanVpnFatalCleanupStarted) {
    process.exit(exitCode);
    return;
  }
  cleanVpnFatalCleanupStarted = true;
  console.error(`[clean-vpn] аварийное завершение (${reason}): восстанавливаем маршруты/NAT…`);
  if (err != null) {
    const msg = err instanceof Error ? err.stack || err.message : String(err);
    console.error(msg);
  }
  if (cleanVpnEmergencyShutdown) {
    try {
      cleanVpnEmergencyShutdown({ exitCode, reason, err });
      return;
    } catch (cleanupErr) {
      console.error(
        '[clean-vpn] ошибка при аварийной очистке:',
        cleanupErr?.message || cleanupErr,
      );
    }
  }
  process.exit(exitCode);
}

function installCleanVpnFatalHandlers() {
  if (cleanVpnFatalHandlersInstalled) return;
  cleanVpnFatalHandlersInstalled = true;
  process.on('uncaughtException', (err) => {
    invokeCleanVpnEmergencyShutdown('uncaughtException', err, 1);
  });
  process.on('unhandledRejection', (reason) => {
    invokeCleanVpnEmergencyShutdown('unhandledRejection', reason, 1);
  });
}

/**
 * @param {import('ws').WebSocketServer} wss
 * @returns {Promise<void>}
 */
function awaitWebSocketServerListening(wss) {
  return new Promise((resolve, reject) => {
    wss.once('error', reject);
    wss.once('listening', resolve);
  });
}

/** Уже «x.x.x.x» — как есть; иначе A-запись IPv4 через DNS. */
async function resolveHostToIpv4(host) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return host;
  return (await dns.lookup(host, { family: 4 })).address;
}

const SCTP_DEFAULTS = {
  recvBufferSize: 16 * 1024 * 1024,
  sendBufferSize: 16 * 1024 * 1024,
  maxChunksOnQueue: 32768,
  initialCongestionWindow: 65535,
  delayedSackTime: 2,
};

const DEFAULT_ICE_SERVERS_JSON = [
  { urls: 'stun:stun.cloudflare.com:3478' },
  { urls: 'stun:global.stun.twilio.com:3478' },
  { urls: 'stun:stun.nextcloud.com:443' },
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

/** @type {typeof import('node-datachannel').PeerConnection | null} */
let ndcPeerConnectionClass = null;

/** Загрузить node-datachannel (native). rtc-chrome/ws-chrome не вызывают — избегаем segfault на ARM при битом prebuild. */
async function ensureNodeDatachannelLoaded() {
  if (ndcPeerConnectionClass) return;
  let mod;
  try {
    mod = await import('node-datachannel');
  } catch (e) {
    throw new Error(
      'node-datachannel не загружен (нужен для --type=webrtc на client/exit). npm install node-datachannel; на ARM при segfault пересоберите из исходников или используйте --type=rtc-chrome.',
      { cause: e },
    );
  }
  mod.setSctpSettings(SCTP_DEFAULTS);
  ndcPeerConnectionClass = mod.PeerConnection;
}

const DEFAULT_CONFIG_JSON = path.join(__dirname, '../config/default.json');
const DEFAULT_QUIC_CERTS_DIR = path.join(__dirname, '../certs');
const QUIC_ALPN = 'clean-vpn';
const QUIC_TLS_CA = 'ca.pem';
const QUIC_TLS_CERT = 'cert.pem';
const QUIC_TLS_KEY = 'key.pem';
/** ALPN для @infisical/quic (quiche); должен совпадать на exit и client. */
const QUIC_EXT_ALPN = 'clean-vpn-ext';
/** Общий 32-байтовый HMAC PSK: stateless retry для QUIC-EXT и Bearer для --type=tls. */
const SHARED_HMAC_FILE = 'clean-vpn-hmac.key';
/** Legacy-имя того же файла (создавался прежними версиями только под QUIC-EXT). */
const SHARED_HMAC_LEGACY_FILE = 'quic-ext-hmac.key';

/** ALPN по умолчанию для --type=tls: приоритет HTTP/2 (`h2` первым). */
const TLS_ALPN_PREFER_H2 = ['h2', 'http/1.1'];
/** Принудительный HTTP/1.1 (`--http-vers=1.1`): только http/1.1 в ALPN. */
const TLS_ALPN_HTTP1_ONLY = ['http/1.1'];
const TLS_LE_FULLCHAIN = 'fullchain.pem';
const TLS_LE_PRIVKEY = 'privkey.pem';
const TLS_HTTP_WORKS_BODY = 'It works!\n';
/** Rate-limit cover-page: окно 60s, лимит 10 cover-responses на IP. Vpn-успех счётчик не двигает. */
const TLS_COVER_RATELIMIT_WINDOW_MS_DEFAULT = 60 * 1000;
const TLS_COVER_RATELIMIT_MAX_DEFAULT = 10;
/** Peek timeout (combo-tls / transparent-tls exit dispatch): 10s; превышение — destroy. */
const EXIT_PEEK_TIMEOUT_MS_DEFAULT = 10 * 1000;
/** Глобальный лимит одновременно открытых peek-сокетов на exit; защита от slow-loris по pending peek. */
const EXIT_PEEK_MAX_PENDING_DEFAULT = 1000;
/** Окно ротации Bearer-токена (мс) — защита от долгого replay при утечке логов. */
const TLS_VPN_TOKEN_WINDOW_MS = 15 * 60 * 1000;
/** Контекст HMAC v1 (legacy, без channel binding). */
const TLS_VPN_TOKEN_CONTEXT_V1 = 'clean-vpn-tls-v1';
/** Контекст HMAC v2 — с привязкой к TLS exporter (RFC 5705) данной сессии. */
const TLS_VPN_TOKEN_CONTEXT_V2 = 'clean-vpn-tls-v2';
/** Алиас для обратной совместимости с внешним кодом, если кто-то ссылался. */
const TLS_VPN_TOKEN_CONTEXT = TLS_VPN_TOKEN_CONTEXT_V2;
/** Label для tls.TLSSocket#exportKeyingMaterial / SSL_export_keying_material (RFC 5705). */
const TLS_VPN_EXPORTER_LABEL = 'EXPORTER-clean-vpn-bind';
/** Длина exporter-секрета (байт). */
const TLS_VPN_EXPORTER_LEN = 32;

/** C-2 / Phase 2: HMAC-контекст для подписи DTLS fingerprint в сигналинге webrtc/rtc-chrome/udp-punch. */
const SIGNALING_BIND_CONTEXT = 'clean-vpn-signal-bind';
/** Тип сообщения для подписи (передача fingerprint + nonce + ts + MAC) перед offer/answer. */
const SIGNALING_BIND_MSG_TYPE = 'clean-vpn-bind';
/** Окно валидности `ts` подписи (±, мс) — защита от replay; 5 мин по плану. */
const SIGNALING_BIND_TS_WINDOW_MS = 5 * 60 * 1000;
/** Контекст подписи для udp-punch (без DTLS fingerprint — только bearer + nonce). */
const SIGNALING_UDPBIND_CONTEXT = 'clean-vpn-udp-bind';
const SIGNALING_UDPBIND_MSG_TYPE = 'clean-vpn-udp-bind';
/** Browser-like User-Agent — чтобы внутри TLS preamble выглядеть «как обычный HTTPS-клиент». */
const TLS_VPN_USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
/** TLS 1.3 cipher suite list, порядок близко к Chrome. */
const TLS_VPN_CIPHERS_1_3 =
  'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
/** ECDH-кривые на client/exit: X25519 первый — как в Chrome. */
const TLS_VPN_ECDH_CURVES = 'X25519:P-256:P-384';
const DEFAULT_TLS_PROBE_TARGET = 'www.google.com:443';
/**
 * Значения `--tls-server-name`, которые пользователи часто путают с decoy SNI.
 * При `--server=IP` и дефолтном ca.pem (CN clean-vpn) проверка должна быть по `clean-vpn`, не по этому хосту.
 */
const TLS_VERIFYNAME_DECOY_SNI_ALIASES = new Set(['www.google.com']);
const DEFAULT_TLS_PROBE_MAX_BYTES = 49152;
const DEFAULT_TLS_PROBE_MAX_SECONDS = 30;
const DEFAULT_TLS_PROBE_FULL_PROXY_PER_IP = 0;
/** Таймаут ожидания TLS-рукопожатия на client (до attachTunBridge). */
const TLS_CLIENT_HANDSHAKE_MS = 30000;
/** Env `CLEAN_VPN_TLS_MUX_DEBUG=1`: первый TCP chunk до разбора ClientHello на exit; этапы TCP/TLS на client до handshake. */
function tlsMuxDebugEnabled() {
  return process.env.CLEAN_VPN_TLS_MUX_DEBUG === '1';
}

/** Включается из `--tls-log-bearer` или env `CLEAN_VPN_TLS_LOG_BEARER=1` в main(). */
let cleanVpnTlsLogBearer = false;

/** `--tls-log-bearer` или env `CLEAN_VPN_TLS_LOG_BEARER=1`. */
function tlsLogBearerEnabled() {
  return cleanVpnTlsLogBearer || envCleanVpnTruthy01('CLEAN_VPN_TLS_LOG_BEARER');
}

/**
 * Печатать Bearer-токен и exporter_b64 для ручной проверки H-1/H-2 (только при tlsLogBearerEnabled()).
 * @param {string} side — метка стороны/этапа (client h1, exit http2 reject, …)
 * @param {string|null|undefined} token
 * @param {Buffer|null|undefined} exporterBuf
 * @param {boolean} [legacy=false]
 */
function tlsLogBearerDebug(side, token, exporterBuf, legacy = false) {
  if (!tlsLogBearerEnabled()) return;
  const exp =
    exporterBuf && Buffer.isBuffer(exporterBuf) && exporterBuf.length > 0
      ? exporterBuf.toString('base64')
      : '(none — Bearer v1 legacy)';
  console.log(
    `[clean-vpn] tls bearer debug (${side}): token=${token ?? '(null)'} exporter_b64=${exp} legacy=${legacy ? '1' : '0'}`,
  );
}

/** Для CLEAN_VPN_TLS_LOG_JA3 / CLEAN_VPN_JA3_VERBOSE — истина для 1/true/yes (без учёта регистра). */
function envCleanVpnTruthy01(key) {
  const v = process.env[key];
  if (v == null) return false;
  const s = String(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes';
}

/** RFC 7540: минимальный/максимальный SETTINGS_MAX_FRAME_SIZE. */
const HTTP2_SETTINGS_MAX_FRAME_MIN = 16384;
const HTTP2_SETTINGS_MAX_FRAME_MAX = 16777215;
/** Дефолтное SETTINGS_INITIAL_WINDOW_SIZE для VPN-потока h2 (можно переопределить env). */
const CLEAN_VPN_H2_INITIAL_WINDOW_DEFAULT = 16 * 1024 * 1024;
/** Дефолтное SETTINGS_MAX_FRAME_SIZE для VPN-потока h2 (байт). */
const CLEAN_VPN_H2_MAX_FRAME_DEFAULT = 1024 * 1024;

/**
 * @param {string} envName
 * @param {number} fallback
 */
function parsePositiveEnvInt(envName, fallback) {
  const raw = process.env[envName];
  if (raw == null || raw === '') return fallback;
  const n = Number.parseInt(String(raw), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Для env вида «0 выкл»: допускает 0 и положительные числа. */
function parseNonNegativeEnvInt(envName, fallback) {
  const raw = process.env[envName];
  if (raw == null || raw === '') return fallback;
  const n = Number.parseInt(String(raw), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/**
 * SETTINGS HTTP/2 для туннеля (--type=tls, ALPN h2): client (`http2.connect`) и exit (`createSecureServer`).
 * Переменные окружения: `CLEAN_VPN_H2_INITIAL_WINDOW`, `CLEAN_VPN_H2_MAX_FRAME` (байты).
 *
 * @returns {{ initialWindowSize: number, maxFrameSize: number }}
 */
function resolveCleanVpnHttp2Settings() {
  let initialWindowSize = parsePositiveEnvInt(
    'CLEAN_VPN_H2_INITIAL_WINDOW',
    CLEAN_VPN_H2_INITIAL_WINDOW_DEFAULT,
  );
  const iwCap = 0x7fffffff;
  if (initialWindowSize > iwCap) initialWindowSize = iwCap;

  let maxFrameSize = parsePositiveEnvInt(
    'CLEAN_VPN_H2_MAX_FRAME',
    CLEAN_VPN_H2_MAX_FRAME_DEFAULT,
  );
  maxFrameSize = Math.min(
    HTTP2_SETTINGS_MAX_FRAME_MAX,
    Math.max(HTTP2_SETTINGS_MAX_FRAME_MIN, maxFrameSize),
  );

  return { initialWindowSize, maxFrameSize };
}

/** Окно потока на соединении HTTP/2: `Http2Session.setLocalWindowSize` (Node ≥20.18 / ≥22.9). Env: `CLEAN_VPN_H2_CONN_WINDOW`. */
const CLEAN_VPN_H2_CONN_WINDOW_DEFAULT = 128 * 1024 * 1024;

/** SO_SNDBUF/SO_RCVBUF для сокета VPN после TLS. Env: `CLEAN_VPN_TCP_SNDBUF`, `CLEAN_VPN_TCP_RCVBUF`. */
const CLEAN_VPN_TCP_SNDBUF_DEFAULT = 4 * 1024 * 1024;
const CLEAN_VPN_TCP_RCVBUF_DEFAULT = 4 * 1024 * 1024;

/** @param {import('http2').Http2Session|null|undefined} session */
function applyCleanVpnHttp2ConnWindow(session) {
  if (!session || typeof session.setLocalWindowSize !== 'function') return;
  const w = parsePositiveEnvInt('CLEAN_VPN_H2_CONN_WINDOW', CLEAN_VPN_H2_CONN_WINDOW_DEFAULT);
  try {
    session.setLocalWindowSize(w);
  } catch {
    /* ignore */
  }
}

/**
 * Потоковое окно duplex-stream VPN (`Http2Stream.setWindowSize`, Node ≥20.18 / ≥22.9).
 * Уменьшает асимметрию iperf без `-R` и с `-R`. Env: `CLEAN_VPN_H2_STREAM_WINDOW`;
 * если не задан — те же байты, что и `CLEAN_VPN_H2_CONN_WINDOW`.
 *
 * @param {import('http2').Http2Stream|null|undefined} stream
 */
function applyCleanVpnHttp2StreamWindow(stream) {
  if (!stream || typeof stream.setWindowSize !== 'function') return;
  const raw = process.env.CLEAN_VPN_H2_STREAM_WINDOW;
  const w =
    raw != null && raw !== ''
      ? parsePositiveEnvInt('CLEAN_VPN_H2_STREAM_WINDOW', CLEAN_VPN_H2_CONN_WINDOW_DEFAULT)
      : parsePositiveEnvInt('CLEAN_VPN_H2_CONN_WINDOW', CLEAN_VPN_H2_CONN_WINDOW_DEFAULT);
  try {
    stream.setWindowSize(w);
  } catch {
    /* ignore */
  }
}

/** @param {import('net').Socket|null|undefined} sock */
function applyCleanVpnTlsTcpBuffers(sock) {
  if (!sock) return;
  const snd = parsePositiveEnvInt('CLEAN_VPN_TCP_SNDBUF', CLEAN_VPN_TCP_SNDBUF_DEFAULT);
  const rcv = parsePositiveEnvInt('CLEAN_VPN_TCP_RCVBUF', CLEAN_VPN_TCP_RCVBUF_DEFAULT);
  try {
    if (typeof sock.setSendBufferSize === 'function') sock.setSendBufferSize(snd);
    if (typeof sock.setRecvBufferSize === 'function') sock.setRecvBufferSize(rcv);
  } catch {
    /* ignore */
  }
}

/**
 * @param {null|'1.1'} tlsHttpVers — из `--http-vers=1.1` или null (авто / приоритет h2).
 * @returns {{ client: string[], server: string[] }}
 */
function resolveTlsAlpnProtocols(tlsHttpVers) {
  const list = tlsHttpVers === '1.1' ? TLS_ALPN_HTTP1_ONLY : TLS_ALPN_PREFER_H2;
  return { client: list, server: list };
}

/**
 * Выбор ALPN со стороны сервера (первый протокол из serverOffer, который клиент указал в ClientHello).
 * Совпадает с порядком OpenSSL/NODE для TLS 1.3 ALPN на сервере.
 *
 * @param {string[]} clientAlpn из разбора ClientHello (может быть пусто)
 * @param {string[]} serverOffer например ['h2','http/1.1']
 */
function pickNegotiatedAlpn(clientAlpn, serverOffer) {
  const client = new Set((clientAlpn || []).map((x) => String(x)));
  if (!client.size) return '';
  for (const p of serverOffer) {
    if (client.has(p)) return p;
  }
  return '';
}

/** Уникальный ключ пира для привязки HTTP/2 session/stream к TCP-сокету (IPv6-safe). */
function tlsPeerTuple(sock) {
  const fam = sock?.remoteFamily ?? '';
  const addr = sock?.remoteAddress ?? '';
  const port = sock?.remotePort ?? '';
  return `${fam}|${addr}|${port}`;
}

/** Человекочитаемый слой HTTP после handshake (для логов). */
function tlsAlpnToHttpLabel(alpn) {
  if (alpn === 'h2') return 'HTTP/2';
  if (alpn === 'http/1.1') return 'HTTP/1.1';
  return '—';
}

// =============================================================================
// === tun: маршруты split-default (RFC1918 через uplink) ===
// =============================================================================

/** RFC1918: при split-default идут через uplink (длиннее префикса /1), чтобы DNS/LAN не уезжали на exit. Peer 10.99.0.1 остаётся /32 на tun. */
const SPLIT_PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

/**
 * @param {string|null|undefined} gw
 * @param {string} dev
 */
function addSplitPrivateUplinkRoutes(gw, dev) {
  for (const dst of SPLIT_PRIVATE_V4) {
    if (gw) {
      ip(['route', 'replace', dst, 'via', gw, 'dev', dev]);
    } else {
      ip(['route', 'replace', dst, 'dev', dev]);
    }
  }
}

/**
 * @param {string|null|undefined} gw
 * @param {string} dev
 */
function delSplitPrivateUplinkRoutes(gw, dev) {
  for (const dst of SPLIT_PRIVATE_V4) {
    if (gw) {
      tryIpRoute(['route', 'del', dst, 'via', gw, 'dev', dev]);
    } else {
      tryIpRoute(['route', 'del', dst, 'dev', dev]);
    }
  }
}

// =============================================================================
// === --type=quic-ext: HMAC stateless retry, импорт @infisical/quic, логер ===
// =============================================================================

function createQuicExtLogger() {
  return new LoggerClass('clean-vpn-quic-ext', LogLevel.WARN, [new StreamHandler(process.stderr)]);
}

/** @param {Buffer} buf */
function bufferToArrayBuffer(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

/**
 * @param {ArrayBuffer} keyBuf
 * @param {ArrayBuffer} dataBuf
 */
async function quicExtSignHMAC(keyBuf, dataBuf) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return globalThis.crypto.subtle.sign('HMAC', key, dataBuf);
}

/**
 * @param {ArrayBuffer} keyBuf
 * @param {ArrayBuffer} dataBuf
 * @param {ArrayBuffer} sigBuf
 */
async function quicExtVerifyHMAC(keyBuf, dataBuf, sigBuf) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  return globalThis.crypto.subtle.verify('HMAC', key, sigBuf, dataBuf);
}

/** @param {ArrayBuffer} data */
async function quicExtRandomBytes(data) {
  const u8 = new Uint8Array(data);
  globalThis.crypto.getRandomValues(u8);
}

/**
 * Загружает (или auto-create на exit) общий 32-байтовый HMAC PSK.
 * Используется для:
 *   - stateless retry в QUIC-EXT (только exit);
 *   - Bearer-токена в `--type=tls` (обе стороны).
 *
 * Приоритет источников:
 *   1) `sharedExplicitPath` (флаг `--shared-hmac-key=PATH`);
 *   2) `legacyExplicitPath` (legacy флаг `--quic-ext-crypto-key=PATH`);
 *   3) `<certsDir>/clean-vpn-hmac.key`;
 *   4) `<certsDir>/quic-ext-hmac.key` (legacy-имя — читается, но не создаётся);
 *   5) при `opts.autoCreate === true` — генерируется новый `clean-vpn-hmac.key`;
 *      иначе — ошибка с подсказкой.
 *
 * @param {string} certsDir
 * @param {string|null} sharedExplicitPath
 * @param {string|null} legacyExplicitPath
 * @param {{ autoCreate: boolean, role: string }} opts
 * @returns {{ buffer: Buffer, path: string, source: 'flag'|'legacy-flag'|'file'|'legacy-file'|'created' }}
 */
function ensureSharedHmacKey(certsDir, sharedExplicitPath, legacyExplicitPath, opts) {
  /**
   * @param {string} p
   * @param {string} flagName
   */
  const readExact32 = (p, flagName) => {
    if (!fs.existsSync(p)) {
      throw new Error(`HMAC: нет файла ${flagName}=${p} (нужны ровно 32 байта).`);
    }
    const buf = fs.readFileSync(p);
    if (buf.length !== 32) {
      throw new Error(`HMAC: ${p} должен быть ровно 32 байта, сейчас ${buf.length}`);
    }
    return buf;
  };
  if (sharedExplicitPath) {
    const p = path.resolve(sharedExplicitPath);
    return { buffer: readExact32(p, '--shared-hmac-key'), path: p, source: 'flag' };
  }
  if (legacyExplicitPath) {
    const p = path.resolve(legacyExplicitPath);
    const buf = readExact32(p, '--quic-ext-crypto-key');
    console.log(
      '[clean-vpn] HMAC: legacy флаг --quic-ext-crypto-key (рекомендуется --shared-hmac-key=PATH)',
    );
    return { buffer: buf, path: p, source: 'legacy-flag' };
  }
  const newPath = path.join(certsDir, SHARED_HMAC_FILE);
  if (fs.existsSync(newPath)) {
    const buf = fs.readFileSync(newPath);
    if (buf.length !== 32) {
      throw new Error(`HMAC: ${newPath} должен быть ровно 32 байта, сейчас ${buf.length}`);
    }
    return { buffer: buf, path: newPath, source: 'file' };
  }
  const legacyPath = path.join(certsDir, SHARED_HMAC_LEGACY_FILE);
  if (fs.existsSync(legacyPath)) {
    const buf = fs.readFileSync(legacyPath);
    if (buf.length !== 32) {
      throw new Error(`HMAC: ${legacyPath} должен быть ровно 32 байта, сейчас ${buf.length}`);
    }
    console.log(
      `[clean-vpn] HMAC: использую legacy ${SHARED_HMAC_LEGACY_FILE} (рекомендуется переименовать в ${SHARED_HMAC_FILE})`,
    );
    return { buffer: buf, path: legacyPath, source: 'legacy-file' };
  }
  if (!opts.autoCreate) {
    throw new Error(
      `HMAC: не найден общий ключ (искал ${newPath} и legacy ${legacyPath}). На ${opts.role} нужен скопированный с exit файл; путь можно задать --shared-hmac-key=PATH.`,
    );
  }
  fs.mkdirSync(certsDir, { recursive: true });
  const rnd = randomBytes(32);
  fs.writeFileSync(newPath, rnd, { mode: 0o600 });
  console.log('[clean-vpn] HMAC: создан общий ключ', newPath);
  return { buffer: rnd, path: newPath, source: 'created' };
}

/**
 * Bearer-токен, сменяющийся каждое окно `TLS_VPN_TOKEN_WINDOW_MS`.
 *
 * v2 (Phase 2 / H-1+H-2): channel binding через TLS exporter (RFC 5705).
 *   `HMAC(secret, "clean-vpn-tls-v2:" || exporter32 || ":" || window)[:16]`
 *   Токен валиден только в **той самой** TLS-сессии, где получен exporter.
 *
 * v1 (legacy): без exporter, `HMAC(secret, "clean-vpn-tls-v1:" || window)[:16]`.
 *   Поддерживается для миграции; на exit фиксируется в логах как `bearer_legacy=1`.
 *   Используется, если `exporterBuf` отсутствует (старая Node-версия без `exportKeyingMaterial`,
 *   старый boring-tls helper без exporter в config-frame, или QUIC-стек без exporter API).
 *
 * @param {Buffer} secret
 * @param {Buffer|null|undefined} exporterBuf — 32 байта из TLS exporter (label=EXPORTER-clean-vpn-bind),
 *   null/undefined → v1 без channel binding.
 * @param {number} [windowOffset=0] — 0 = текущее окно; -1 / +1 — соседние (для clock skew).
 * @returns {string} hex-строка длиной 32 символа (16 байт)
 */
function computeTlsVpnBearerToken(secret, exporterBuf, windowOffset = 0) {
  const window = Math.floor(Date.now() / TLS_VPN_TOKEN_WINDOW_MS) + windowOffset;
  if (exporterBuf && Buffer.isBuffer(exporterBuf) && exporterBuf.length > 0) {
    const mac = createHmac('sha256', secret)
      .update(`${TLS_VPN_TOKEN_CONTEXT_V2}:`)
      .update(exporterBuf)
      .update(`:${window}`)
      .digest();
    return mac.subarray(0, 16).toString('hex');
  }
  const mac = createHmac('sha256', secret)
    .update(`${TLS_VPN_TOKEN_CONTEXT_V1}:${window}`)
    .digest();
  return mac.subarray(0, 16).toString('hex');
}

/**
 * Принять токен в текущем окне или соседних (±1) для compensation clock skew.
 * Если `exporterBuf` задан — сначала пробуем v2 (channel-bound); при mismatch fallback на v1
 * с пометкой `legacy: true` (для warning-лога и метрики переходного периода).
 *
 * @param {Buffer} secret
 * @param {string} token
 * @param {Buffer|null} [exporterBuf=null]
 * @returns {{ ok: boolean, windowOffset: number|null, legacy: boolean }}
 */
function verifyTlsVpnBearerToken(secret, token, exporterBuf = null) {
  if (typeof token !== 'string' || token.length !== 32) {
    return { ok: false, windowOffset: null, legacy: false };
  }
  let provided;
  try {
    provided = Buffer.from(token, 'hex');
  } catch {
    return { ok: false, windowOffset: null, legacy: false };
  }
  if (provided.length !== 16) return { ok: false, windowOffset: null, legacy: false };

  if (exporterBuf && Buffer.isBuffer(exporterBuf) && exporterBuf.length > 0) {
    for (const offset of [0, -1, 1]) {
      const expected = Buffer.from(
        computeTlsVpnBearerToken(secret, exporterBuf, offset),
        'hex',
      );
      if (expected.length === provided.length && timingSafeEqual(expected, provided)) {
        return { ok: true, windowOffset: offset, legacy: false };
      }
    }
  }
  for (const offset of [0, -1, 1]) {
    const expected = Buffer.from(computeTlsVpnBearerToken(secret, null, offset), 'hex');
    if (expected.length === provided.length && timingSafeEqual(expected, provided)) {
      return { ok: true, windowOffset: offset, legacy: true };
    }
  }
  return { ok: false, windowOffset: null, legacy: false };
}

/**
 * Извлечь 32-байтовый TLS exporter (RFC 5705) с label `EXPORTER-clean-vpn-bind`.
 * Возвращает null, если стек не поддерживает или вызов упал.
 * @param {import('tls').TLSSocket|null|undefined} tlsSock
 * @returns {Buffer|null}
 */
function tlsVpnExporterFromSocket(tlsSock) {
  if (!tlsSock || typeof tlsSock.exportKeyingMaterial !== 'function') return null;
  try {
    const buf = tlsSock.exportKeyingMaterial(TLS_VPN_EXPORTER_LEN, TLS_VPN_EXPORTER_LABEL);
    if (Buffer.isBuffer(buf) && buf.length === TLS_VPN_EXPORTER_LEN) return buf;
  } catch {
    /* noop */
  }
  return null;
}

/**
 * C-2 / Phase 2: подписать DTLS fingerprint для сигналинга webrtc/rtc-chrome.
 * MAC = HMAC-SHA256(PSK, "clean-vpn-signal-bind:" + ts + ":" + nonce + ":" + fingerprint)[:32hex]
 * Защита: ts окно ±5 мин, nonce 32hex (8 байт random), MAC не позволяет подделку без PSK.
 *
 * @param {Buffer} psk
 * @param {string} fingerprint — "sha-256 XX:XX:..."
 * @param {string} nonceHex
 * @param {number} ts
 * @returns {string} 32hex (16 bytes)
 */
function signSignalingBind(psk, fingerprint, nonceHex, ts) {
  const mac = createHmac('sha256', psk)
    .update(`${SIGNALING_BIND_CONTEXT}:${ts}:${nonceHex}:${fingerprint}`)
    .digest();
  return mac.subarray(0, 16).toString('hex');
}

/**
 * Проверка подписи (C-2). Возвращает причину отказа или null при успехе.
 * @param {Buffer} psk
 * @param {{ fingerprint?: string, nonce?: string, ts?: number, mac?: string }} msg
 * @returns {string|null}
 */
function verifySignalingBind(psk, msg) {
  if (!msg || typeof msg !== 'object') return 'no_obj';
  const { fingerprint, nonce, ts, mac } = msg;
  if (typeof fingerprint !== 'string' || !fingerprint) return 'no_fingerprint';
  if (typeof nonce !== 'string' || !/^[0-9a-f]{16,128}$/i.test(nonce)) return 'bad_nonce';
  if (typeof ts !== 'number' || !Number.isFinite(ts)) return 'bad_ts';
  if (typeof mac !== 'string' || !/^[0-9a-f]{32}$/i.test(mac)) return 'bad_mac';
  const now = Date.now();
  if (Math.abs(now - ts) > SIGNALING_BIND_TS_WINDOW_MS) return 'ts_window';
  const expected = Buffer.from(signSignalingBind(psk, fingerprint, nonce, ts), 'hex');
  const provided = Buffer.from(mac, 'hex');
  if (expected.length !== provided.length) return 'mac_len';
  if (!timingSafeEqual(expected, provided)) return 'mac_mismatch';
  return null;
}

/**
 * Аналог для udp-punch (без DTLS): просто bearer + replay-protected nonce + ts.
 * MAC = HMAC(PSK, "clean-vpn-udp-bind:" + ts + ":" + nonce)
 *
 * @param {Buffer} psk
 * @param {string} nonceHex
 * @param {number} ts
 */
function signUdpPunchBind(psk, nonceHex, ts) {
  const mac = createHmac('sha256', psk)
    .update(`${SIGNALING_UDPBIND_CONTEXT}:${ts}:${nonceHex}`)
    .digest();
  return mac.subarray(0, 16).toString('hex');
}

/**
 * Проверка подписи udp-punch (C-2).
 * @param {Buffer} psk
 * @param {{ nonce?: string, ts?: number, mac?: string }} msg
 */
function verifyUdpPunchBind(psk, msg) {
  if (!msg || typeof msg !== 'object') return 'no_obj';
  const { nonce, ts, mac } = msg;
  if (typeof nonce !== 'string' || !/^[0-9a-f]{16,128}$/i.test(nonce)) return 'bad_nonce';
  if (typeof ts !== 'number' || !Number.isFinite(ts)) return 'bad_ts';
  if (typeof mac !== 'string' || !/^[0-9a-f]{32}$/i.test(mac)) return 'bad_mac';
  const now = Date.now();
  if (Math.abs(now - ts) > SIGNALING_BIND_TS_WINDOW_MS) return 'ts_window';
  const expected = Buffer.from(signUdpPunchBind(psk, nonce, ts), 'hex');
  const provided = Buffer.from(mac, 'hex');
  if (expected.length !== provided.length) return 'mac_len';
  if (!timingSafeEqual(expected, provided)) return 'mac_mismatch';
  return null;
}

/**
 * Извлечь первый `a=fingerprint:` из SDP. Возвращает строку формата "sha-256 XX:XX:..."
 * или null, если не найдено.
 * @param {string} sdp
 */
function extractDtlsFingerprintFromSdp(sdp) {
  if (typeof sdp !== 'string') return null;
  const m = /^a=fingerprint:\s*([^\s]+)\s+([0-9A-Fa-f:]+)\s*$/m.exec(sdp);
  if (!m) return null;
  return `${m[1].toLowerCase()} ${m[2].toUpperCase()}`;
}

/**
 * Нормализованное сравнение fingerprint'ов (регистр и пробелы).
 * @param {string|null|undefined} a
 * @param {string|null|undefined} b
 */
function signalingFingerprintsEqual(a, b) {
  if (!a || !b) return false;
  const norm = (s) => String(s).trim().toLowerCase().replace(/\s+/g, ' ');
  return norm(a) === norm(b);
}

async function importQuicExt() {
  try {
    const m = await import('@infisical/quic');
    const root = m.default ?? m;
    const QUICServer = root.QUICServer ?? m.QUICServer;
    const QUICClient = root.QUICClient ?? m.QUICClient;
    const events = root.events ?? m.events;
    if (!QUICServer || !QUICClient || !events?.EventQUICServerConnection) {
      throw new Error('неполный экспорт пакета (QUICServer / QUICClient / events)');
    }
    return { QUICServer, QUICClient, events };
  } catch (e) {
    const arch = process.arch;
    const plat = process.platform;
    throw new Error(
      `Не удалось загрузить @infisical/quic (${plat}/${arch}): ${e.message}. ` +
        `Нужен prebuild под вашу платформу; см. optionalDependencies пакета и выполните npm install.`,
    );
  }
}

// =============================================================================
// === --type=quic (node:quic): версия Node, dynamic import ===
// =============================================================================

function assertQuicNodeVersion() {
  const major = parseInt(String(process.versions.node).split('.')[0], 10);
  if (Number.isNaN(major) || major < 25) {
    throw new Error(
      `--type=quic требует Node.js 25+ (сейчас ${process.versions.node}). Остальные --type работают на Node 18+.`,
    );
  }
}

async function importNodeQuic() {
  try {
    return await import('node:quic');
  } catch (e) {
    const hint =
      'Проверьте: node -p "process.config.variables.node_use_quic" — если не true/1, этот бинарь собран без QUIC; возьмите сборку с nodejs.org или nvm (не пакет apt без node_use_quic). ';
    throw new Error(
      `Не удалось загрузить node:quic: ${e.message}. ` +
        `Нужны Node 25+ и флаг --experimental-quic перед скриптом. ` +
        `Если версия уже 25+ и флаг есть, типичная причина — сборка без вкомпилированного QUIC. ` +
        hint,
    );
  }
}

// =============================================================================
// === Общее: OpenSSL, каталог сертификатов (quic / quic-ext / tls) ===
// =============================================================================

function opensslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Нормализует список host'ов (DNS/IPv4/IPv6) в строки `DNS:` / `IP:` для openssl SAN.
 * Отбрасывает 0.0.0.0, ::, пустые и unspecified — это listen-bind, не публичный адрес.
 * @param {string[]} hosts
 * @returns {string[]}
 */
function normalizeCertSanHosts(hosts) {
  const out = [];
  const seen = new Set();
  for (const raw of hosts || []) {
    if (!raw) continue;
    const h = String(raw).trim();
    if (!h) continue;
    if (h === '0.0.0.0' || h === '::' || h === '::0' || h === '0.0.0.0/0') continue;
    if (h.toLowerCase() === 'localhost') {
      if (!seen.has('DNS:localhost')) {
        out.push('DNS:localhost');
        seen.add('DNS:localhost');
      }
      continue;
    }
    const ipKind = net.isIP(h);
    const entry = ipKind ? `IP:${h}` : `DNS:${h}`;
    if (!seen.has(entry)) {
      out.push(entry);
      seen.add(entry);
    }
  }
  return out;
}

/**
 * Локальный CA + серверный cert (CN=clean-vpn). Клиент доверяет ca.pem; SNI на клиенте — clean-vpn.
 *
 * @param {string} dir
 * @param {{ sanHosts?: string[] }} [opts]  При первой генерации добавляет
 *   `subjectAltName` (IP/DNS) из `sanHosts`. Используется, чтобы Node.js TLS
 *   client мог пройти hostname-verification без `checkServerIdentity` workaround.
 *   Если cert уже существует — параметр игнорируется (старый файл не апгрейдится).
 */
function ensureQuicCerts(dir, opts = {}) {
  const caPath = path.join(dir, QUIC_TLS_CA);
  const certPath = path.join(dir, QUIC_TLS_CERT);
  const keyPath = path.join(dir, QUIC_TLS_KEY);
  if (fs.existsSync(caPath) && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { caPath, certPath, keyPath };
  }
  if (!opensslAvailable()) {
    throw new Error(
      `QUIC: нет ${caPath}, ${certPath}, ${keyPath} и не найден openssl в PATH. Установите openssl или создайте файлы вручную.`,
    );
  }
  fs.mkdirSync(dir, { recursive: true });
  const caKeyPath = path.join(dir, '.clean-vpn-ca.key');
  const csrPath = path.join(dir, '.clean-vpn-server.csr');
  const extPath = path.join(dir, '.clean-vpn-server.ext');
  const sanEntries = normalizeCertSanHosts(opts.sanHosts || []);
  const sslOpt = { stdio: 'inherit', cwd: dir };
  try {
    execFileSync('openssl', ['genrsa', '-out', caKeyPath, '4096'], sslOpt);
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-new',
        '-nodes',
        '-key',
        caKeyPath,
        '-sha256',
        '-days',
        '3650',
        '-subj',
        '/CN=clean-vpn-dev-ca',
        '-out',
        caPath,
      ],
      sslOpt,
    );
    execFileSync('openssl', ['genrsa', '-out', keyPath, '2048'], sslOpt);
    execFileSync(
      'openssl',
      ['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', '/CN=clean-vpn'],
      sslOpt,
    );
    const x509Args = [
      'x509',
      '-req',
      '-in',
      csrPath,
      '-CA',
      caPath,
      '-CAkey',
      caKeyPath,
      '-CAcreateserial',
      '-out',
      certPath,
      '-days',
      '825',
      '-sha256',
    ];
    if (sanEntries.length) {
      const extContent =
        `authorityKeyIdentifier=keyid,issuer\n` +
        `basicConstraints=CA:FALSE\n` +
        `keyUsage = digitalSignature, keyEncipherment\n` +
        `extendedKeyUsage = serverAuth\n` +
        `subjectAltName = ${sanEntries.join(',')}\n`;
      fs.writeFileSync(extPath, extContent);
      x509Args.push('-extfile', extPath);
    }
    execFileSync('openssl', x509Args, sslOpt);
  } finally {
    for (const p of [caKeyPath, csrPath, extPath]) {
      try {
        fs.unlinkSync(p);
      } catch {
        /* ignore */
      }
    }
    for (const srl of [
      path.join(dir, `${path.basename(caPath)}.srl`),
      path.join(dir, 'ca.srl'),
    ]) {
      try {
        fs.unlinkSync(srl);
      } catch {
        /* ignore */
      }
    }
  }
  const sanLabel = sanEntries.length ? ` SAN=${sanEntries.join(',')}` : '';
  console.log(`[clean-vpn] QUIC: созданы тестовые TLS-файлы в ${dir}${sanLabel}`);
  return { caPath, certPath, keyPath };
}

/**
 * @param {{ tlsCertDir?: string|null, quicCertsDir?: string|null }} args
 */
function resolveTlsCertsDir(args) {
  if (args.tlsCertDir) return path.resolve(args.tlsCertDir);
  if (args.quicCertsDir) return path.resolve(args.quicCertsDir);
  return DEFAULT_QUIC_CERTS_DIR;
}

/**
 * C-2 / Phase 2: загрузить общий HMAC PSK для подписи сигналинга webrtc/rtc-chrome/udp-punch.
 * Возвращает Buffer | null. При отсутствии файла и `required=true` бросает; при false — только warning.
 * Не создаёт ключ автоматически (на client'е exit'овский ключ должен быть скопирован).
 * @param {string} certsDir
 * @param {string|null|undefined} sharedExplicit — --shared-hmac-key
 * @param {string|null|undefined} legacyExplicit — --quic-ext-crypto-key
 * @param {boolean} required — если true и ключа нет — throw
 * @param {string} logPrefix
 */
function loadSignalingPskOrWarn(certsDir, sharedExplicit, legacyExplicit, required, logPrefix) {
  try {
    const r = ensureSharedHmacKey(certsDir, sharedExplicit || null, legacyExplicit || null, {
      autoCreate: false,
      role: logPrefix,
    });
    if (r.source === 'file' || r.source === 'flag') {
      console.log(`[clean-vpn] ${logPrefix}: PSK (${r.source}) ${r.path}`);
    }
    return r.buffer;
  } catch (e) {
    if (required) {
      throw new Error(
        `[clean-vpn] ${logPrefix}: для C-2 сигналинг-подписи нужен clean-vpn-hmac.key (--shared-hmac-key или файл в --tls-cert-dir/--quic-certs-dir). ` +
          `Отключите проверку флагом --signaling-psk-required=false (только для отладки). Исходная ошибка: ${e?.message || e}`,
      );
    }
    console.warn(
      `[clean-vpn] ${logPrefix}: PSK для сигналинга не найден (${e?.message || e}); работаем без C-2 fingerprint binding (--signaling-psk-required=false)`,
    );
    return null;
  }
}

/**
 * Серверные PEM для TLS exit: приоритет Let's Encrypt (fullchain+privkey), иначе ensureQuicCerts.
 * @param {string} dir
 * @param {{ sanHosts?: string[] }} [opts]  Прокидывается в `ensureQuicCerts`
 *   только при первой генерации self-signed; для Let's Encrypt игнорируется.
 * @returns {{ cert: string, key: string, caPath: string }}
 */
function loadTlsServerCredentials(dir, opts = {}) {
  const fullchainPath = path.join(dir, TLS_LE_FULLCHAIN);
  const privkeyPath = path.join(dir, TLS_LE_PRIVKEY);
  if (fs.existsSync(fullchainPath) && fs.existsSync(privkeyPath)) {
    return {
      cert: fs.readFileSync(fullchainPath, 'utf8'),
      key: fs.readFileSync(privkeyPath, 'utf8'),
      caPath: fullchainPath,
    };
  }
  const t = ensureQuicCerts(dir, { sanHosts: opts.sanHosts || [] });
  return {
    cert: fs.readFileSync(t.certPath, 'utf8'),
    key: fs.readFileSync(t.keyPath, 'utf8'),
    caPath: t.caPath,
  };
}

/** CA для tls.connect на клиенте: при LE — fullchain; иначе ca.pem. */
function loadTlsClientCaPem(dir) {
  const fullchainPath = path.join(dir, TLS_LE_FULLCHAIN);
  if (fs.existsSync(fullchainPath)) return fs.readFileSync(fullchainPath, 'utf8');
  const t = ensureQuicCerts(dir);
  return fs.readFileSync(t.caPath, 'utf8');
}

/** Клиент доверяет exit по LE fullchain (а не только dev ca.pem). */
function tlsClientTrustUsesLeFullchain(certsDir) {
  return fs.existsSync(path.join(certsDir, TLS_LE_FULLCHAIN));
}

/**
 * Hostname для проверки сертификата exit на TLS-клиенте (не wire SNI / ClientHello).
 * `--tls-public-name` нужен enc-SNI/combo; для self-signed ca.pem без fullchain проверяем clean-vpn.
 * @param {{ tlsServerName?: string|null, tlsPublicName?: string|null, host: string, certsDir: string }} opts
 */
function resolveTlsClientCertVerifyName({ tlsServerName, tlsPublicName, host, certsDir }) {
  const hostIsIp = net.isIP(host) !== 0;
  let explicit = tlsServerName != null ? String(tlsServerName).trim() : '';
  if (
    explicit &&
    hostIsIp &&
    TLS_VERIFYNAME_DECOY_SNI_ALIASES.has(explicit.toLowerCase())
  ) {
    console.warn(
      '[clean-vpn] TLS: `--tls-server-name` задаёт проверку сертификата, не decoy SNI. При IP-сервере значение www.google.com трактуем как запрос проверки CN/SAN clean-vpn (как без этого флага). Явный ClientHello SNI: `--tls-client-sni=HOST`. Имя под ваш LE-сертификат: `--tls-server-name=ваш.домен`.',
    );
    return 'clean-vpn';
  }
  if (explicit) return explicit;

  const pub = tlsPublicNamePrimary(tlsPublicName);
  const usesLeTrust = tlsClientTrustUsesLeFullchain(certsDir);
  if (pub && usesLeTrust) return pub;

  if (!pub) {
    if (hostIsIp) {
      console.warn(
        '[clean-vpn] TLS: в --server указан IP — для проверки сертификата используется clean-vpn (как у ca/cert из репо); для LE на exit задайте --tls-server-name=ваш.домен.',
      );
      return 'clean-vpn';
    }
    return host;
  }

  if (hostIsIp && !usesLeTrust) {
    console.warn(
      `[clean-vpn] TLS: --tls-public-name=${pub} — для enc-SNI/combo; проверка VPN-сертификата по clean-vpn (ca.pem, без fullchain.pem в --tls-cert-dir). LE на exit: fullchain.pem + --tls-server-name=${pub}.`,
    );
    return 'clean-vpn';
  }
  return pub;
}

/**
 * ClientHello SNI и имя проверки сертификата для `--type=tls|boring-tls|combo-tls` client.
 * @param {{ tlsClientSni?: string|null, verifyName: string }} opts
 */
function resolveTlsClientHelloSni({ tlsClientSni, verifyName }) {
  const sniRaw = tlsClientSni != null ? String(tlsClientSni).trim() : '';
  let clientHelloSni = sniRaw || verifyName;
  if (!sniRaw && verifyName === 'clean-vpn') {
    clientHelloSni = 'www.google.com';
    console.warn(
      '[clean-vpn] TLS: ClientHello SNI по умолчанию www.google.com (проверка сертификата clean-vpn). Свой SNI: --tls-client-sni=…; LE: --tls-server-name=ваш.домен.',
    );
  }
  if (sniRaw && sniRaw !== verifyName) {
    console.warn(
      '[clean-vpn] TLS: ClientHello SNI отличается от имени проверки сертификата; маршрутизация VPN — по Bearer-токену внутри TLS.',
    );
  }
  return clientHelloSni;
}

/**
 * После TLS с ALPN `h2`: HTTP/2 POST /clean-vpn, ждём `:status 200`, тело запроса не завершаем (duplex).
 *
 * @param {import('tls').TLSSocket} tlsSock
 * @param {string} checkHost — :authority / Host
 * @param {Buffer} vpnSecret
 * @returns {Promise<any>} socket-like для `attachTunBridge`
 */
function establishCleanVpnOverH2(tlsSock, checkHost, vpnSecret, exporter = null) {
  const ek = exporter ?? tlsVpnExporterFromSocket(tlsSock);
  if (!ek) {
    console.warn(
      '[clean-vpn] TLS exporter недоступен (Node без exportKeyingMaterial или helper без поддержки) — Bearer v1 legacy, без channel-binding (H-2)',
    );
  }
  const token = computeTlsVpnBearerToken(vpnSecret, ek);
  tlsLogBearerDebug('client h2', token, ek, !ek);
  const clientSession = http2.connect(`https://${checkHost}`, {
    createConnection: () => tlsSock,
    settings: resolveCleanVpnHttp2Settings(),
  });
  clientSession.once('connect', () => {
    applyCleanVpnHttp2ConnWindow(clientSession);
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    let respTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);
    const cleanupTimers = () => {
      if (respTimer) clearTimeout(respTimer);
      respTimer = null;
    };
    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanupTimers();
      try {
        clientSession.destroy();
      } catch {
        /* ignore */
      }
      try {
        tlsSock.destroy();
      } catch {
        /* ignore */
      }
      reject(err);
    };
    respTimer = setTimeout(() => {
      fail(
        new Error(
          `TLS client: таймаут ${TLS_CLIENT_HANDSHAKE_MS} мс ожидания HTTP/2 :status от ${checkHost}`,
        ),
      );
    }, TLS_CLIENT_HANDSHAKE_MS);
    respTimer.unref?.();

    clientSession.on('error', fail);
    tlsSock.once('error', fail);

    /** @type {import('http2').ClientHttp2Stream} */
    let req;
    try {
      req = clientSession.request(
        {
          ':method': 'POST',
          ':path': '/clean-vpn',
          ':scheme': 'https',
          ':authority': checkHost,
          authorization: `Bearer ${token}`,
          'user-agent': TLS_VPN_USER_AGENT,
          accept: '*/*',
        },
        { endStream: false },
      );
    } catch (e) {
      fail(/** @type {Error} */ (e));
      return;
    }

    req.on('error', fail);
    req.on('response', (headers) => {
      cleanupTimers();
      const rawStatus = headers[':status'];
      const statusStr = rawStatus != null ? String(rawStatus) : '';
      if (statusStr !== '200') {
        fail(
          new Error(
            `TLS client: HTTP/2 ответ :status=${rawStatus ?? '—'} — bearer не принят / не VPN-сервер`,
          ),
        );
        return;
      }
      if (settled) return;
      settled = true;
      applyCleanVpnHttp2StreamWindow(req);
      resolve(http2StreamToSocketLike(req, clientSession, tlsSock));
    });
  });
}

/** Дефолтный путь к артефакту сборки (рядом с репо). */
const DEFAULT_BORING_TLS_HELPER = path.join(
  __dirname,
  '..',
  'native',
  'boring_tls',
  'build',
  'boring-tls-helper',
);

/** Exit принимает тот же протокол, что `--type=tls`. */
function isTlsLikeType(t) {
  return t === 'tls' || t === 'boring-tls';
}

/**
 * @param {string|null|undefined} cliPath из `--boring-tls-helper`
 */
function resolveBoringTlsHelperExecutable(cliPath) {
  const env = process.env.CLEAN_VPN_BORING_TLS_HELPER;
  if (env != null && String(env).trim() !== '') return path.resolve(String(env).trim());
  if (cliPath != null && String(cliPath).trim() !== '')
    return path.resolve(String(cliPath).trim());
  return path.resolve(DEFAULT_BORING_TLS_HELPER);
}

/**
 * Читает ровно n байт из paused Readable.
 * @param {import('stream').Readable} readable
 */
async function readExactFromReadable(readable, n) {
  /** @type {Buffer[]} */
  const chunks = [];
  let have = 0;
  while (have < n) {
    const chunk = readable.read();
    if (chunk) {
      chunks.push(chunk);
      have += chunk.length;
      continue;
    }
    await once(readable, 'readable');
  }
  const all = Buffer.concat(chunks);
  const head = all.subarray(0, n);
  if (all.length > n) readable.unshift(all.subarray(n));
  return head;
}

/**
 * Один кадр протокола boring-tls-helper (BE uint32 + UTF-8 JSON).
 * @param {import('stream').Writable} writable
 */
function writeBoringTlsConfigFrame(writable, jsonObj) {
  const body = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(body.length, 0);
  writable.write(hdr);
  writable.write(body);
}

/**
 * Duplex поверх stdin/stdout helper после ответа READY.
 * @param {import('child_process').ChildProcessWithoutNullStreams} child
 */
function boringTlsHelperToDuplex(child) {
  const d = new Duplex({
    allowHalfOpen: false,
    read() {
      child.stdout.resume();
    },
    write(chunk, encoding, callback) {
      const cb =
        typeof encoding === 'function'
          ? encoding
          : typeof callback === 'function'
            ? callback
            : () => {};
      const enc = typeof encoding === 'string' ? encoding : undefined;
      if (child.stdin.destroyed) {
        cb(new Error('boring-tls-helper stdin closed'));
        return;
      }
      const ok = child.stdin.write(chunk, enc);
      if (ok) process.nextTick(cb);
      else child.stdin.once('drain', cb);
    },
    destroy(err, callback) {
      const killer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }, 2000);
      killer.unref?.();
      try {
        child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      child.once('close', () => {
        clearTimeout(killer);
        callback(err);
      });
    },
  });
  child.stdout.on('data', (chunk) => {
    if (!d.push(chunk)) child.stdout.pause();
  });
  child.stdout.on('end', () => d.push(null));
  child.stdout.on('error', (e) => {
    d.destroy(e);
  });
  child.stdin.on('error', (e) => {
    d.destroy(e);
  });
  child.on('error', (e) => {
    d.destroy(e);
  });
  d.setTimeout = () => d;
  return d;
}

/**
 * После TLS рукопожатия: HTTP/2 или HTTP/1.1 преамбула VPN.
 * @param {import('tls').TLSSocket | import('stream').Duplex} sock
 * @param {{
 *   checkHost: string,
 *   vpnSecret: Buffer,
 *   tlsHttpVers: null|'1.1',
 *   negotiatedAlpn?: string,
 * }} opts
 */
async function completeCleanVpnTlsSession(sock, opts) {
  const { checkHost, vpnSecret, tlsHttpVers, negotiatedAlpn } = opts;
  const exporter =
    opts.exporter ||
    tlsVpnExporterFromSocket(
      /** @type {import('tls').TLSSocket|null} */ (
        /** @type {unknown} */ (sock)
      ),
    );
  const ap =
    negotiatedAlpn !== undefined
      ? negotiatedAlpn
      : sock.alpnProtocol === false
        ? ''
        : String(sock.alpnProtocol ?? '');
  const httpLabel = tlsAlpnToHttpLabel(ap);
  console.log(
    `[clean-vpn] TLS client: рукопожатие OK http=${httpLabel} negotiated ALPN=${ap || '—'}`,
  );
  if (exporter && opts.exporter == null) {
    console.log(
      `[clean-vpn] tls: TLS channel-binding OK alpn=${ap || '(empty)'} exporter_len=${exporter.length} (Bearer v2; полный token/exporter — --tls-log-bearer)`,
    );
  }
  if (
    'setSendBufferSize' in sock &&
    typeof /** @type {{ setSendBufferSize?: unknown }} */ (sock).setSendBufferSize === 'function'
  ) {
    applyCleanVpnTlsTcpBuffers(/** @type {import('net').Socket} */ (sock));
  }
  if (tlsHttpVers === '1.1') {
    if (ap !== 'http/1.1') {
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      throw new Error(
        `TLS client: ожидался ALPN http/1.1 (--http-vers=1.1), получено «${ap || '—'}»`,
      );
    }
  } else if (ap !== 'h2' && ap !== 'http/1.1') {
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
    throw new Error(
      `TLS client: неожиданный ALPN «${ap || '—'}» (ожидались h2 или http/1.1)`,
    );
  }

  if (ap === 'h2') {
    sock.setTimeout?.(0);
    const wrapped = await establishCleanVpnOverH2(
      /** @type {import('tls').TLSSocket} */ (sock),
      checkHost,
      vpnSecret,
      exporter,
    );
    const cbLabel = exporter ? ' bearer=v2 channel-bound' : ' bearer=v1 legacy';
    console.log(`[clean-vpn] TLS (VPN) соединение установлено http=HTTP/2${cbLabel}`);
    return wrapped;
  }

  if (!exporter) {
    console.warn(
      '[clean-vpn] TLS exporter недоступен (HTTP/1.1) — Bearer v1 legacy, без channel-binding (H-2)',
    );
  }
  const token = computeTlsVpnBearerToken(vpnSecret, exporter);
  tlsLogBearerDebug('client http1', token, exporter, !exporter);
  const req =
    `GET /clean-vpn HTTP/1.1\r\n` +
    `Host: ${checkHost}\r\n` +
    `User-Agent: ${TLS_VPN_USER_AGENT}\r\n` +
    `Accept: */*\r\n` +
    `Authorization: Bearer ${token}\r\n` +
    `Connection: keep-alive\r\n\r\n`;
  /** @type {Buffer} */
  let respBuf = Buffer.alloc(0);
  await new Promise((resolve, reject) => {
    const onResp = (chunk) => {
      respBuf =
        respBuf.length === 0 ? Buffer.from(chunk) : Buffer.concat([respBuf, chunk]);
      const idx = respBuf.indexOf('\r\n\r\n');
      if (idx === -1) {
        if (respBuf.length > 16384) {
          sock.off('data', onResp);
          try {
            sock.destroy();
          } catch {
            /* ignore */
          }
          reject(new Error('TLS client: HTTP-ответ exit > 16 KiB без \\r\\n\\r\\n'));
        }
        return;
      }
      sock.off('data', onResp);
      const head = respBuf.subarray(0, idx).toString('latin1');
      const status = /^HTTP\/1\.1 (\d{3})/.exec(head);
      if (!status || status[1] !== '200') {
        try {
          sock.destroy();
        } catch {
          /* ignore */
        }
        reject(
          new Error(
            `TLS client: exit ответил «${head.split('\r\n')[0] || '?'}» — bearer не принят / не VPN-сервер`,
          ),
        );
        return;
      }
      const rest = respBuf.subarray(idx + 4);
      if (rest.length) setImmediate(() => sock.emit('data', rest));
      resolve(undefined);
    };
    sock.on('data', onResp);
    sock.write(req);
  });
  const cbLabel = exporter ? ' bearer=v2 channel-bound' : ' bearer=v1 legacy';
  console.log(`[clean-vpn] TLS (VPN) соединение установлено http=HTTP/1.1${cbLabel}`);
  return sock;
}

/**
 * TLS через boring-tls-helper (BoringSSL в отдельном процессе). См. scripts/boring-tls-plan.md
 * @param {{
 *   host: string,
 *   port: number,
 *   ca: string,
 *   servername: string,
 *   verifyServername?: string,
 *   vpnSecret: Buffer,
 *   tlsHttpVers?: null|'1.1',
 *   boringTlsHelperPath?: string|null,
 *   boringTlsProfile?: string|null,
 *   boringTlsClienthelloProfilePath?: string|null,
 *   boringTlsJa3Strict?: boolean,
 *   tlsLogJa3?: boolean,
 *   ja3Verbose?: boolean,
 * }} opts
 */
async function connectCleanVpnBoringTlsClient(opts) {
  const {
    host,
    port,
    ca,
    servername,
    verifyServername,
    vpnSecret,
    tlsHttpVers,
    boringTlsHelperPath,
    boringTlsProfile,
    boringTlsClienthelloProfilePath,
    boringTlsJa3Strict,
    tlsLogJa3,
    ja3Verbose,
  } = opts;
  const checkHost = verifyServername ?? servername;
  const connectHost = await resolveHostToIpv4(host);
  const exe = resolveBoringTlsHelperExecutable(boringTlsHelperPath ?? null);
  if (!fs.existsSync(exe)) {
    throw new Error(
      `boring-tls-helper не найден (${exe}). Соберите: npm run build:boring-tls-helper (на VPS при OOM/cc1plus Killed: npm run build:boring-tls-helper-lowmem; см. scripts/boring-tls-plan.md). Переменная CLEAN_VPN_BORING_TLS_HELPER или --boring-tls-helper=PATH.`,
    );
  }
  if (boringTlsClienthelloProfilePath) {
    console.log(
      `[clean-vpn] boring-tls: профиль ClientHello из файла ${boringTlsClienthelloProfilePath}${boringTlsJa3Strict ? ' (ja3_strict)' : ''}`,
    );
  }
  console.log(
    `[clean-vpn] boring-tls: helper=${exe} → ${connectHost}:${port}, ClientHello SNI=${servername}, verify cert host=${checkHost}`,
  );
  if (tlsLogBearerEnabled()) {
    console.log('[clean-vpn] tls-log-bearer: boring-tls connect…');
  }

  const child = spawn(exe, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  /** @type {Buffer[]} */
  const boringTlsStderrChunks = [];
  child.stderr?.on('data', (buf) => {
    boringTlsStderrChunks.push(Buffer.from(buf));
    try {
      process.stderr.write(buf);
    } catch {
      /* ignore */
    }
  });

  let handshakeTimer = /** @type {ReturnType<typeof setTimeout>|null} */ (null);
  const clearHsTimer = () => {
    if (handshakeTimer) clearTimeout(handshakeTimer);
    handshakeTimer = null;
  };

  try {
    handshakeTimer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, TLS_CLIENT_HANDSHAKE_MS);

    await once(child, 'spawn');
    child.stdout.pause();
    /** @type {Record<string, unknown>} */
    const cfgFrame = {
      host: connectHost,
      port,
      ca_pem: ca,
      servername,
      verify_host: checkHost,
      alpn: resolveTlsAlpnProtocols(tlsHttpVers ?? null).client,
      handshake_timeout_ms: TLS_CLIENT_HANDSHAKE_MS,
      profile: boringTlsProfile ?? 'default',
    };
    if (tlsLogJa3 || ja3Verbose) {
      cfgFrame.log_ja3 = true;
      if (ja3Verbose) cfgFrame.ja3_verbose = true;
    }
    if (boringTlsClienthelloProfilePath) {
      const prof = readClienthelloProfileFileSync(boringTlsClienthelloProfilePath);
      cfgFrame.client_hello_profile = profileFileToHelperClientHelloBlock(prof, {
        ja3Strict: Boolean(boringTlsJa3Strict),
      });
    }
    writeBoringTlsConfigFrame(child.stdin, cfgFrame);

    const hdr = await readExactFromReadable(child.stdout, 4);
    const bodyLen = hdr.readUInt32BE(0);
    if (bodyLen > 512 * 1024) {
      throw new Error('boring-tls: слишком большой ответ helper');
    }
    const body = await readExactFromReadable(child.stdout, bodyLen);
    clearHsTimer();
    let resp;
    try {
      resp = JSON.parse(body.toString('utf8'));
    } catch {
      throw new Error('boring-tls: невалидный JSON ответ helper');
    }
    if (!resp || resp.ok !== true) {
      const errText = Buffer.concat(boringTlsStderrChunks).toString('utf8');
      const baseErr =
        resp && typeof resp.error === 'string'
          ? resp.error
          : 'boring-tls-helper отказ (см. stderr)';
      if (baseErr.includes('certificate host verification failed')) {
        const peerCert = errText.match(/peer_cert="([^"]+)"/);
        const peerBit = peerCert ? `; peer ${peerCert[1]}` : '';
        throw new Error(
          `${baseErr} (verify_host=${checkHost}${peerBit}; LE: fullchain.pem + --tls-server-name=…; self-signed: --tls-server-name=clean-vpn)`,
        );
      }
      throw new Error(baseErr);
    }
    if (tlsLogJa3 || ja3Verbose) {
      const errText = Buffer.concat(boringTlsStderrChunks).toString('utf8');
      const jw = errText.match(/ja3_md5=([0-9a-f]{32})/);
      const js = errText.match(/ja3_sorted_md5=([0-9a-f]{32})/);
      const jf = errText.match(/ja4=([^\s]+)/);
      if (jw) {
        console.log(`[clean-vpn] boring-tls JA3 wire md5=${jw[1]} (Salesforce JA3 по проводу, сверка с JA3 DB для этого ClientHello)`);
      }
      if (js) {
        console.log(`[clean-vpn] boring-tls JA3 sorted md5=${js[1]} (те же компоненты, списки отсортированы; стабильнее при permute_extensions)`);
      }
      if (jf) {
        console.log(`[clean-vpn] boring-tls JA4 ${jf[1]} (FoxIO JA4 по JA4.md — канонический fingerprint)`);
      }
      const jfAlt = errText.match(/^boring-tls-helper: ja4_alt_sni_alpn_in_j4c=(.+)$/m);
      if (jfAlt) {
        console.log(
          `[clean-vpn] boring-tls JA4 alt ${jfAlt[1]} (ja4_a/b как канон; JA4_c как у ja3.zone: sorted ext с 0000, без 0010 — не FoxIO JA4.md)`,
        );
      }
      const jrawo = errText.match(/^boring-tls-helper: ja4_raw_o=(.+)$/m);
      const jrawr = errText.match(/^boring-tls-helper: ja4_raw_r=(.+)$/m);
      const jrawrAlt = errText.match(/^boring-tls-helper: ja4_raw_r_alt_sni_alpn=(.+)$/m);
      if (jrawo) {
        console.log(
          `[clean-vpn] boring-tls JA4 raw_o=${jrawo[1]} (FoxIO JA4_ro — порядок на проводе, в списке расширений есть SNI 0000 и ALPN 0010 при наличии на wire)`,
        );
      }
      if (jrawr) {
        console.log(
          `[clean-vpn] boring-tls JA4 raw_r=${jrawr[1]} (FoxIO JA4.md JA4_r: средний сегмент без SNI 0000 и ALPN 0010 — они учтены в префиксе ja4_a, см. JA4.md)`,
        );
      }
      if (jrawrAlt) {
        console.log(
          `[clean-vpn] boring-tls JA4 raw_r_alt=${jrawrAlt[1]} (как ja3.zone raw: средний сегмент — sorted ext с SNI 0000, без ALPN 0010; полное совпадение с сайтом только при том же числе расширений на wire, напр. при наличии 0029)`,
        );
      }
    }
    const negotiatedAlpn = resp.alpn != null ? String(resp.alpn) : '';
    /** H-1+H-2: helper кладёт TLS exporter (base64, label=EXPORTER-clean-vpn-bind) в ok-frame.
     *  Старый helper без поля — exporter останется null, Bearer уйдёт как legacy v1. */
    let exporter = null;
    if (typeof resp.exporter === 'string' && resp.exporter.length > 0) {
      try {
        const dec = Buffer.from(resp.exporter, 'base64');
        if (dec.length === TLS_VPN_EXPORTER_LEN) exporter = dec;
      } catch {
        /* ignore — Bearer уедет legacy */
      }
    }
    if (!exporter) {
      console.warn(
        '[clean-vpn] boring-tls: helper не вернул `exporter` в ok-frame (старая сборка?) — Bearer v1 legacy, без channel-binding (H-2)',
      );
    } else {
      console.log(
        `[clean-vpn] boring-tls: TLS channel-binding OK alpn=${negotiatedAlpn || '(empty)'} exporter_len=${exporter.length} (Bearer v2; полный token/exporter — --tls-log-bearer)`,
      );
    }
    if (tlsLogBearerEnabled()) {
      console.log(
        `[clean-vpn] boring-tls: helper ok-frame (length-prefixed JSON на stdout, не stderr) alpn=${negotiatedAlpn || '(empty)'} exporter=${typeof resp.exporter === 'string' ? resp.exporter : '(missing)'}`,
      );
    }

    // Нельзя resume stdout до подписки на 'data': в flowing mode без слушателя
    // первые байты TLS application data теряются → HTTP/2 и IPv4 framing ломаются.
    const duplex = boringTlsHelperToDuplex(child);
    child.stdout.resume();
    return await completeCleanVpnTlsSession(duplex, {
      checkHost,
      vpnSecret,
      tlsHttpVers: tlsHttpVers ?? null,
      negotiatedAlpn,
      exporter,
    });
  } catch (e) {
    clearHsTimer();
    try {
      child.kill('SIGKILL');
    } catch {
      /* ignore */
    }
    throw e;
  }
}

/**
 * Исходящее TLS к exit (ALPN по `resolveTlsAlpnProtocols`, TLS 1.3 only).
 * После рукопожатия: `http/1.1` — GET + 200; `h2` — POST duplex на одном stream + :status 200.
 * @param {{
 *   host: string,
 *   port: number,
 *   ca: string,
 *   servername: string,
 *   verifyServername?: string,
 *   vpnSecret: Buffer,
 *   tlsHttpVers?: null|'1.1',
 * }} opts
 */
async function connectCleanVpnTlsClient(opts) {
  const { host, port, ca, servername, verifyServername, vpnSecret, tlsHttpVers } = opts;
  const alpnList = resolveTlsAlpnProtocols(tlsHttpVers ?? null).client;
  const checkHost = verifyServername ?? servername;
  const hostIsIp = net.isIP(host) !== 0;
  let connectHost = host;
  if (!hostIsIp) {
    connectHost = (await dns.lookup(host, { family: 4 })).address;
  }
  const sniNote =
    checkHost !== servername ? `, проверка сертификата для host=${checkHost}` : '';
  console.log(
    `[clean-vpn] TLS client: соединение к ${connectHost}:${port}, ClientHello SNI=${servername}${sniNote}`,
  );
  return new Promise((resolve, reject) => {
    let settled = false;
    /** @type {import('tls').TLSSocket} */
    let sock;
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      try {
        sock.setTimeout(0);
      } catch {
        /* ignore */
      }
      fn();
    };
    sock = tls.connect(
      port,
      connectHost,
      {
        ALPNProtocols: alpnList,
        ca,
        servername,
        minVersion: 'TLSv1.3',
        ciphers: TLS_VPN_CIPHERS_1_3,
        ecdhCurve: TLS_VPN_ECDH_CURVES,
        rejectUnauthorized: true,
        ...(checkHost !== servername
          ? {
              checkServerIdentity: (/** @type {string} */ _host, cert) =>
                tls.checkServerIdentity(checkHost, cert),
            }
          : {}),
      },
      () => {
        void (async () => {
          try {
            if (sock.authorizationError) {
              console.error(
                '[clean-vpn] TLS client: проверка сертификата:',
                sock.authorizationError,
              );
            }
            const wrapped = await completeCleanVpnTlsSession(sock, {
              checkHost,
              vpnSecret,
              tlsHttpVers: tlsHttpVers ?? null,
            });
            finish(() => resolve(wrapped));
          } catch (e) {
            finish(() => reject(e));
          }
        })();
      },
    );
    if (tlsMuxDebugEnabled()) {
      sock.once('connect', () => {
        console.log(
          `[clean-vpn] TLS mux debug client: TCP установлен к ${connectHost}:${port}, идёт TLS handshake…`,
        );
      });
    }
    sock.setTimeout(TLS_CLIENT_HANDSHAKE_MS);
    sock.on('timeout', () => {
      if (tlsMuxDebugEnabled()) {
        console.error(
          `[clean-vpn] TLS mux debug client: таймаут ${TLS_CLIENT_HANDSHAKE_MS} мс — возможно фильтр режет TLS-record или сервер не отвечает (${connectHost}:${port})`,
        );
      }
      finish(() =>
        reject(
          new Error(
            `TLS client: таймаут ${TLS_CLIENT_HANDSHAKE_MS} мс рукопожатия к ${connectHost}:${port}`,
          ),
        ),
      );
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
    });
    sock.on('error', (err) => {
      console.error(
        '[clean-vpn] TLS client: ошибка сокета до завершения рукопожатия:',
        err?.message || err,
      );
      if (sock.authorizationError) {
        console.error(
          '[clean-vpn] TLS client: authorizationError:',
          sock.authorizationError,
        );
      }
      finish(() => reject(err));
    });
  });
}

// =============================================================================
// === --type=tls: парсинг ClientHello, SNI/ALPN, passthrough, inbound exit ===
// =============================================================================

/** Макс. буфер при сборке ClientHello из нескольких TLS records (защита от DOS). */
const TLS_MUX_MAX_CLIENT_BUF = 512 * 1024;

/**
 * SNI / ALPN / supported_versions (расширение 43) из тела ClientHello.
 * @returns {{ ok: true, sni: string[], alpn: string[], supportedVersions: number[] } | { ok: false, reason: string }}
 */
function parseTlsClientHelloExtensions(ch) {
  let o = 0;
  if (ch.length < 34) return { ok: false, reason: 'short_ch' };
  o += 34;
  const sidLen = ch[o];
  o += 1;
  if (ch.length < o + sidLen + 2) return { ok: false, reason: 'short_ch2' };
  o += sidLen;
  const csLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + csLen + 1) return { ok: false, reason: 'short_ch3' };
  o += csLen;
  const compLen = ch[o];
  o += 1;
  if (ch.length < o + compLen + 2) return { ok: false, reason: 'short_ch4' };
  o += compLen;
  const extLen = ch.readUInt16BE(o);
  o += 2;
  if (ch.length < o + extLen) return { ok: false, reason: 'short_ext' };
  const extBlock = ch.subarray(o, o + extLen);
  /** @type {string[]} */
  const sni = [];
  /** @type {string[]} */
  const alpn = [];
  /** @type {number[]} */
  const supportedVersions = [];
  let eo = 0;
  while (eo + 4 <= extBlock.length) {
    const et = extBlock.readUInt16BE(eo);
    const el = extBlock.readUInt16BE(eo + 2);
    eo += 4;
    if (eo + el > extBlock.length) break;
    const ed = extBlock.subarray(eo, eo + el);
    if (et === 0 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let so = 2;
      while (so + 3 <= ed.length && listLen >= 3) {
        const nt = ed[so];
        const nl = ed.readUInt16BE(so + 1);
        so += 3;
        if (so + nl > ed.length) break;
        if (nt === 0) sni.push(ed.subarray(so, so + nl).toString('utf8'));
        so += nl;
        listLen -= 3 + nl;
      }
    } else if (et === 16 && ed.length >= 2) {
      let listLen = ed.readUInt16BE(0);
      let ao = 2;
      while (ao + 1 <= ed.length && listLen > 0) {
        const pl = ed[ao];
        ao += 1;
        if (ao + pl > ed.length) break;
        alpn.push(ed.subarray(ao, ao + pl).toString('utf8'));
        ao += pl;
        listLen -= 1 + pl;
      }
    } else if (et === 43 && ed.length >= 1) {
      const slen = ed[0];
      const end = Math.min(ed.length, 1 + slen);
      for (let pos = 1; pos + 1 < end; pos += 2) {
        supportedVersions.push(ed.readUInt16BE(pos));
      }
    }
    eo += el;
  }
  return { ok: true, sni, alpn, supportedVersions };
}

/**
 * ClientHello может занимать несколько подряд TLS records (0x16) — типично при крупном hello (OpenSSL 3 / PQ).
 * @returns {{ needMore: true, minTotal: number } | { ok: false, reason: string } | { ok: true, sni: string[], alpn: string[], supportedVersions: number[], bytesConsumed: number }}
 */
function parseFirstTlsClientHello(buf) {
  if (buf.length > TLS_MUX_MAX_CLIENT_BUF) {
    return { ok: false, reason: 'buffer_max' };
  }
  if (buf.length < 5) return { needMore: true, minTotal: 5 };
  if (buf[0] !== 0x16) return { ok: false, reason: 'not_tls_handshake' };

  /** @type {Buffer[]} */
  const payloads = [];
  let offset = 0;
  for (;;) {
    if (buf.length - offset < 5) {
      return { needMore: true, minTotal: offset + 5 };
    }
    if (buf[offset] !== 0x16) {
      return offset === 0
        ? { ok: false, reason: 'not_tls_handshake' }
        : { ok: false, reason: 'non_handshake_record' };
    }
    const recLen = buf.readUInt16BE(offset + 3);
    const recordEnd = offset + 5 + recLen;
    if (recLen < 1 || recordEnd > TLS_MUX_MAX_CLIENT_BUF) {
      return { ok: false, reason: 'record_oversize' };
    }
    if (recordEnd > buf.length) {
      return { needMore: true, minTotal: recordEnd };
    }
    payloads.push(buf.subarray(offset + 5, recordEnd));
    offset = recordEnd;
    const combined = Buffer.concat(payloads);
    if (combined.length < 4) continue;
    if (combined[0] !== 1) return { ok: false, reason: 'not_client_hello' };
    const hsLen = combined.readUIntBE(1, 3);
    const totalHs = 4 + hsLen;
    if (combined.length < totalHs) continue;
    const ch = combined.subarray(4, totalHs);
    const ext = parseTlsClientHelloExtensions(ch);
    if (!ext.ok) return ext;
    return {
      ok: true,
      sni: ext.sni,
      alpn: ext.alpn,
      supportedVersions: ext.supportedVersions,
      bytesConsumed: offset,
    };
  }
}

/**
 * Несколько имён из `--tls-public-name=a,b` (пробелы обрезаются).
 * @param {string|null|undefined} publicName
 * @returns {string[]}
 */
function tlsPublicNameList(publicName) {
  if (publicName == null || String(publicName).trim() === '') return [];
  return String(publicName)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((w) => w.toLowerCase().replace(/\.$/, ''));
}

/**
 * Первый hostname из списка public-name (для проверки сертификата на client).
 * @param {string|null|undefined} publicName
 */
function tlsPublicNamePrimary(publicName) {
  const a = tlsPublicNameList(publicName);
  return a[0] ?? null;
}

/**
 * @param {string[]} sniList
 * @param {string} publicName — одно имя или несколько через запятую
 */
function sniMatchesTlsPublicName(sniList, publicName) {
  const wants = tlsPublicNameList(publicName);
  if (!wants.length) return false;
  for (const raw of sniList) {
    const h = String(raw).toLowerCase().replace(/\.$/, '');
    if (wants.includes(h)) return true;
  }
  return false;
}

function tlsClientIp(socket) {
  const a = socket.remoteAddress || '';
  return a.replace(/^\:\:ffff\:/, '');
}

function tlsUtcDayBucket() {
  return Math.floor(Date.now() / 86400000);
}

/**
 * Sliding-window rate-limit для TLS cover-page (M-1).
 * Считает только cover-ответы (`outcome !== 'vpn'`): успешный VPN-handshake счётчик не двигает.
 * @type {Map<string, { count: number, windowStart: number }>}
 */
const tlsCoverRateState = new Map();
let tlsCoverRateCleanupTimer = null;
function tlsCoverRateWindowMs() {
  return parsePositiveEnvInt(
    'CLEAN_VPN_TLS_COVER_RL_WINDOW_MS',
    TLS_COVER_RATELIMIT_WINDOW_MS_DEFAULT,
  );
}
function tlsCoverRateLimit() {
  return parsePositiveEnvInt('CLEAN_VPN_TLS_COVER_RL_MAX', TLS_COVER_RATELIMIT_MAX_DEFAULT);
}
function tlsCoverEnsureCleanupTimer() {
  if (tlsCoverRateCleanupTimer) return;
  const windowMs = tlsCoverRateWindowMs();
  tlsCoverRateCleanupTimer = setInterval(() => {
    const cutoff = Date.now() - 2 * windowMs;
    for (const [ip, entry] of tlsCoverRateState) {
      if (entry.windowStart < cutoff) tlsCoverRateState.delete(ip);
    }
  }, windowMs);
  tlsCoverRateCleanupTimer.unref?.();
}
/**
 * Проверить лимит и инкрементировать счётчик. Возвращает true если IP надо throttle.
 * Вызывать ТОЛЬКО когда `outcome !== 'vpn'`, иначе легитимные клиенты будут резаться при reconnect.
 * @param {string} ip
 * @returns {boolean}
 */
function tlsCoverShouldThrottle(ip) {
  tlsCoverEnsureCleanupTimer();
  const now = Date.now();
  const windowMs = tlsCoverRateWindowMs();
  const limit = tlsCoverRateLimit();
  let entry = tlsCoverRateState.get(ip);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 1, windowStart: now };
    tlsCoverRateState.set(ip, entry);
  } else {
    entry.count += 1;
  }
  return entry.count > limit;
}

/**
 * Глобальный семафор pending peek-сокетов на exit (M-4): защита от slow-loris,
 * который удерживает много TCP-соединений, не отдавая первые байты.
 * Acquire возвращает release-функцию или null, если лимит исчерпан.
 * Caller обязан вызывать release ровно один раз (в cleanup peek-handler'а).
 */
let exitPeekActive = 0;
function exitPeekMaxPending() {
  return parsePositiveEnvInt('CLEAN_VPN_EXIT_PEEK_MAX', EXIT_PEEK_MAX_PENDING_DEFAULT);
}
function exitPeekTimeoutMs() {
  return parsePositiveEnvInt('CLEAN_VPN_EXIT_PEEK_TIMEOUT_MS', EXIT_PEEK_TIMEOUT_MS_DEFAULT);
}
function exitPeekAcquire() {
  const max = exitPeekMaxPending();
  if (exitPeekActive >= max) return null;
  exitPeekActive += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (exitPeekActive > 0) exitPeekActive -= 1;
  };
}

/** После того как байты уже шли через pipe, такие errno — типичный разрыв пира, не сбой прокси. */
const TCP_BENIGN_AFTER_DATA_CODES = new Set(['ECONNRESET', 'EPIPE', 'ECONNABORTED']);

/**
 * @param {import('net').Socket} socket
 * @param {string} reason
 * @param {Buffer} fullBuf
 */
function logTlsPassthrough(socket, reason, fullBuf) {
  const ip = tlsClientIp(socket);
  const port = socket.remotePort ?? '?';
  const hex = fullBuf.subarray(0, Math.min(16, fullBuf.length)).toString('hex');
  console.log(
    `[clean-vpn] tls passthrough: start ip=${ip} port=${port} reason=${reason} prefix=${hex}…`,
  );
}

/**
 * Двунаправленный pipe с лимитом байт и времени.
 * @param {import('net').Socket} a
 * @param {import('net').Socket} b
 * @param {{ maxBytes: number, maxMs: number, treatCommonResetAsClose?: boolean }} opts
 * @param {(meta: { totalBytes: number, cause: 'timeout'|'byte_limit'|'error'|'close', socketError: boolean }) => void} onEnd
 */
function pipeTcpWithLimits(a, b, opts, onEnd) {
  let total = 0;
  const deadline = Date.now() + opts.maxMs;
  let ended = false;
  /** @type {'timeout'|'byte_limit'|'error'|'close'|null} */
  let endCause = null;
  let socketError = false;
  function finish(cause, fromError = false) {
    if (ended) return;
    ended = true;
    endCause = cause;
    if (fromError) socketError = true;
    clearInterval(tick);
    try {
      a.destroy();
    } catch {
      /* ignore */
    }
    try {
      b.destroy();
    } catch {
      /* ignore */
    }
    try {
      onEnd({
        totalBytes: total,
        cause: /** @type {'timeout'|'byte_limit'|'error'|'close'} */ (endCause || 'close'),
        socketError,
      });
    } catch {
      /* ignore */
    }
  }
  const tick = setInterval(() => {
    if (Date.now() > deadline) finish('timeout', false);
  }, 1000);
  tick.unref?.();
  const count = (n) => {
    total += n;
    if (total >= opts.maxBytes) finish('byte_limit', false);
  };
  const pipeDir = (src, dst) => {
    src.on('data', (chunk) => {
      if (ended) return;
      count(chunk.length);
      if (ended) return;
      const ok = dst.write(chunk);
      if (!ok) src.pause();
    });
    dst.on('drain', () => src.resume());
  };
  pipeDir(a, b);
  pipeDir(b, a);
  const onSockError = (err) => {
    const code = err && /** @type {NodeJS.ErrnoException} */ (err).code;
    if (
      opts.treatCommonResetAsClose &&
      total > 0 &&
      code &&
      TCP_BENIGN_AFTER_DATA_CODES.has(code)
    ) {
      finish('close', false);
      return;
    }
    finish('error', true);
  };
  a.on('error', onSockError);
  b.on('error', onSockError);
  a.on('close', () => finish('close', false));
  b.on('close', () => finish('close', false));
}

// =============================================================================
// === --type=quic (node:quic): QuicStream bidi → socket-like для attachTunBridge ===
// =============================================================================

/** @param {any} qs — quic.QuicStream (bidi) */
function quicBidiToSocketLike(qs) {
  if (!qs?.readable) {
    throw new Error('QUIC: у потока нет readable');
  }
  if (!qs.writable) {
    throw new Error('QUIC: у потока нет writable (нужен bidirectional stream)');
  }
  const r = Readable.fromWeb(qs.readable, { highWaterMark: 4 * 1024 * 1024 });
  const w = Writable.fromWeb(qs.writable, { highWaterMark: 4 * 1024 * 1024 });
  const sock = /** @type {any} */ (r);
  sock.destroyed = false;
  sock.write = (chunk, enc, cb) => w.write(chunk, enc, cb);
  sock.destroy = (err) => {
    if (sock.destroyed) return;
    sock.destroyed = true;
    try {
      qs.destroy(err);
    } catch {
      /* ignore */
    }
    try {
      w.destroy(err);
    } catch {
      /* ignore */
    }
    try {
      r.destroy(err);
    } catch {
      /* ignore */
    }
  };
  // QUIC-поток: нет реального TCP FIN, у socket-like нет writable-end() (только write/destroy).
  // graceful FIN небезопасен — закрываем через destroy().
  sock.__cleanVpnGracefulFinUnsafe = true;
  return sock;
}

/**
 * HTTP/2 stream (Duplex) → объект с жизненным циклом как у TCP-сокета для `attachTunBridge`.
 * При `destroy` закрываются stream, Http2Session и нижележащий TLS-сокет.
 *
 * @param {import('stream').Duplex} stream
 * @param {import('http2').Http2Session} session
 * @param {import('tls').TLSSocket} tlsSocket
 */
function http2StreamToSocketLike(stream, session, tlsSocket) {
  // Нельзя требовать stream.readable: у ClientHttp2Stream при событии 'response'
  // readable может быть false до прихода первого DATA (особенно с произвольным Duplex-сокетом).
  if (!stream || stream.destroyed) {
    throw new Error('HTTP/2: stream отсутствует или уже уничтожен');
  }
  if (typeof stream.write !== 'function') {
    throw new Error('HTTP/2: stream без writable-стороны');
  }
  const sock = /** @type {any} */ (stream);
  sock.destroyed = Boolean(sock.destroyed);
  const innerDestroy =
    typeof stream.destroy === 'function' ? stream.destroy.bind(stream) : null;
  sock.destroy = (err) => {
    if (sock.destroyed) return;
    sock.destroyed = true;
    try {
      innerDestroy?.(err);
    } catch {
      /* ignore */
    }
    try {
      session.destroy(err);
    } catch {
      /* ignore */
    }
    try {
      tlsSocket.destroy();
    } catch {
      /* ignore */
    }
  };
  // Если под h2 не настоящий net.Socket (boring-tls helper Duplex → Node оборачивает в
  // JSStreamSocket), то `.end()` при graceful FIN пишет END_STREAM в уже закрывшийся
  // JSStream → ERR_INTERNAL_ASSERTION в JSStreamSocket.doWrite (краш процесса).
  // Для таких обёрток закрываемся через destroy(). Настоящий TLSSocket (exit, native tls) — FIN ок.
  sock.__cleanVpnGracefulFinUnsafe = !(tlsSocket instanceof net.Socket);
  return sock;
}

// =============================================================================
// === --type=webrtc: ICE/STUN/TURN из JSON (node-datachannel) ===
// =============================================================================

/** Как в src/transport/webrtc.js: объекты конфига → строки для node-datachannel. */
function convertIceServers(servers, iceMode) {
  const result = [];
  for (const s of servers) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    for (const url of urls) {
      if (!url) continue;
      const isStun = url.startsWith('stun:');
      const isTurn = url.startsWith('turn:') || url.startsWith('turns:');

      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;

      if (isTurn && (s.username || s.credential)) {
        const proto = url.startsWith('turns:') ? 'turns' : 'turn';
        const addr = url.replace(/^turns?:/, '');
        result.push(`${proto}:${s.username}:${s.credential}@${addr}`);
      } else {
        result.push(url);
      }
    }
  }
  return result;
}

/**
 * @param {string|null|undefined} configPath — путь к JSON или null → default.json рядом с репо
 * @param {string|null|undefined} cliIceMode — перекрывает iceMode из файла
 */
function loadWebrtcIceFromConfig(configPath, cliIceMode) {
  const resolved = configPath
    ? path.resolve(configPath)
    : DEFAULT_CONFIG_JSON;
  if (!fs.existsSync(resolved)) {
    throw new Error(`Нет файла конфигурации ICE: ${resolved}`);
  }
  const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const iceFromFile = json.iceMode || 'auto';
  const iceMode =
    cliIceMode && ['auto', 'relay', 'direct'].includes(cliIceMode)
      ? cliIceMode
      : iceFromFile;
  const raw = [...(json.iceServers || []), ...(json.turnServers || [])];
  const merged = raw.length ? raw : DEFAULT_ICE_SERVERS_JSON;
  const ndcIceServers = convertIceServers(merged, iceMode);
  if (!ndcIceServers.length) {
    throw new Error('После convertIceServers список ICE пуст; проверьте iceMode и turnServers');
  }
  return { ndcIceServers, iceMode, configPath: resolved };
}

/**
 * ICE для --type=udp --punch: только stun: из iceServers.
 * turnServers / coturn намеренно не используются (hole punch ≠ relay).
 * @param {string|null|undefined} configPath
 * @param {string|null|undefined} cliIceMode — игнорируется для списка STUN (всегда stun-only)
 */
function loadUdpPunchIceFromConfig(configPath, cliIceMode) {
  const resolved = configPath ? path.resolve(configPath) : DEFAULT_CONFIG_JSON;
  if (!fs.existsSync(resolved)) {
    throw new Error(`Нет файла конфигурации ICE: ${resolved}`);
  }
  const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const iceFromFile = json.iceMode || 'auto';
  const iceMode =
    cliIceMode && ['auto', 'relay', 'direct'].includes(cliIceMode)
      ? cliIceMode
      : iceFromFile;
  const raw = json.iceServers?.length ? json.iceServers : DEFAULT_ICE_SERVERS_JSON;
  const ndcIceServers = convertIceServers(raw, 'direct').filter((u) => String(u).startsWith('stun:'));
  if (!ndcIceServers.length) {
    throw new Error(
      '[clean-vpn] UDP punch: в --config iceServers нужен хотя бы один stun: (turn/coturn не используется)',
    );
  }
  return { ndcIceServers, iceMode, configPath: resolved };
}

const ICE_INFRA_IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Hostname из stun:/turn:/turns: URL (как src/network/tun.js).
 * @param {string} url
 * @returns {string|null}
 */
function hostnameFromIceUrl(url) {
  const u = String(url).trim();
  const m = u.match(/^(?:stun|stuns|turn|turns):([^:[\s]+)(?::\d+)?/i);
  return m ? m[1].trim() : null;
}

/**
 * @param {Array<{ urls?: string|string[] }>} merged
 * @param {string} iceMode
 * @returns {string[]}
 */
function collectIceInfraHostnames(merged, iceMode) {
  const hosts = new Set();
  for (const s of merged) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    for (const url of urls) {
      if (!url) continue;
      const u = String(url);
      const isStun = u.startsWith('stun:') || u.startsWith('stuns:');
      const isTurn = u.startsWith('turn:') || u.startsWith('turns:');
      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;
      const h = hostnameFromIceUrl(u);
      if (h) hosts.add(h);
    }
  }
  return [...hosts];
}

/**
 * IPv4 STUN/TURN из --config для bypass при --split-default (все A-записи пула STUN).
 * @param {string|null|undefined} configPath
 * @param {string|null|undefined} cliIceMode
 * @returns {Promise<string[]>}
 */
async function resolveIceInfraIpv4FromConfig(configPath, cliIceMode) {
  const resolved = configPath ? path.resolve(configPath) : DEFAULT_CONFIG_JSON;
  if (!fs.existsSync(resolved)) return [];
  const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const iceFromFile = json.iceMode || 'auto';
  const iceMode =
    cliIceMode && ['auto', 'relay', 'direct'].includes(cliIceMode)
      ? cliIceMode
      : iceFromFile;
  const raw = [...(json.iceServers || []), ...(json.turnServers || [])];
  const merged = raw.length ? raw : DEFAULT_ICE_SERVERS_JSON;
  const hostnames = collectIceInfraHostnames(merged, iceMode);
  /** @type {Set<string>} */
  const ips = new Set();
  for (const h of hostnames) {
    if (ICE_INFRA_IPV4_RE.test(h)) {
      ips.add(h);
      continue;
    }
    if (h === 'localhost') {
      ips.add('127.0.0.1');
      continue;
    }
    try {
      const addrs = await dns.resolve4(h);
      for (const a of addrs) {
        if (ICE_INFRA_IPV4_RE.test(a)) ips.add(a);
      }
    } catch {
      try {
        const { address } = await dns.lookup(h, { family: 4 });
        if (ICE_INFRA_IPV4_RE.test(address)) ips.add(address);
      } catch (err) {
        console.warn(
          `[clean-vpn] infra bypass: не удалось резолвить ${h}: ${err?.message || err}`,
        );
      }
    }
  }
  return [...ips];
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isIpv4InfraBypassSafe(ip) {
  if (!ip || !ICE_INFRA_IPV4_RE.test(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 127) return false;
  if (a === 169 && b === 254 && ip !== '169.254.169.254') return false;
  return true;
}

/** Нужен ли /32 bypass к STUN/TURN при --split-default (plain udp/socket/tcp — нет). */
function clientNeedsIceInfraBypass(type, punch) {
  return (
    type === 'webrtc' ||
    type === 'rtc-chrome' ||
    type === 'ws-chrome' ||
    (type === 'udp' && punch)
  );
}

/**
 * UDP exit: первый пир или смена порта/IP (client переподключился с новым ephemeral port).
 * @param {{ peer?: import('dgram').RemoteInfo }} ep
 * @param {import('dgram').RemoteInfo} rinfo
 */
function bindOrMigrateUdpServerPeer(ep, rinfo) {
  if (!ep.peer) {
    ep.peer = rinfo;
    console.log(`[clean-vpn] udp peer ${rinfo.address}:${rinfo.port}`);
    return;
  }
  if (ep.peer.address === rinfo.address && ep.peer.port === rinfo.port) return;
  console.log(
    `[clean-vpn] udp peer ${ep.peer.address}:${ep.peer.port} → ${rinfo.address}:${rinfo.port} (переподключение)`,
  );
  ep.peer = rinfo;
}

/**
 * ICE в формате для RTCPeerConnection (Chrome): те же правила фильтрации, что у convertIceServers.
 * @returns {{ iceServers: Array<{ urls: string|string[], username?: string, credential?: string }>, iceMode: string, configPath: string }}
 */
function convertIceServersToBrowserObjects(servers, iceMode) {
  /** @type {Array<{ urls: string|string[], username?: string, credential?: string }>} */
  const result = [];
  for (const s of servers) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    const kept = [];
    for (const url of urls) {
      if (!url) continue;
      const u = String(url);
      const isStun = u.startsWith('stun:');
      const isTurn = u.startsWith('turn:') || u.startsWith('turns:');
      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;
      kept.push(u);
    }
    if (!kept.length) continue;
    const entry =
      kept.length === 1
        ? { urls: kept[0] }
        : { urls: kept };
    if (s.username != null && s.username !== '') entry.username = s.username;
    if (s.credential != null && s.credential !== '') entry.credential = s.credential;
    result.push(entry);
  }
  return result;
}

/**
 * @param {string|null|undefined} configPath
 * @param {string|null|undefined} cliIceMode
 */
function loadWebrtcBrowserIceFromConfig(configPath, cliIceMode) {
  const resolved = configPath
    ? path.resolve(configPath)
    : DEFAULT_CONFIG_JSON;
  if (!fs.existsSync(resolved)) {
    throw new Error(`Нет файла конфигурации ICE: ${resolved}`);
  }
  const json = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const iceFromFile = json.iceMode || 'auto';
  const iceMode =
    cliIceMode && ['auto', 'relay', 'direct'].includes(cliIceMode)
      ? cliIceMode
      : iceFromFile;
  const raw = [...(json.iceServers || []), ...(json.turnServers || [])];
  const merged = raw.length ? raw : DEFAULT_ICE_SERVERS_JSON;
  const iceServers = convertIceServersToBrowserObjects(merged, iceMode);
  if (!iceServers.length) {
    throw new Error(
      'rtc-chrome: после фильтрации iceMode список ICE пуст; проверьте turnServers',
    );
  }
  return { iceServers, iceMode, configPath: resolved };
}

/** WebRTC: WSS сигналинга на этой ноде только с --signaling; иначе исходящий WS. */
function webrtcSignalingListens(signaling) {
  return signaling === true;
}

/** WebSocket данных: WSS только с --ws-server; иначе исходящий WS. */
function websocketVpnListens(wsServer) {
  return wsServer === true;
}

/**
 * Два текстовых пира на одном WSS (rtc-chrome + --signaling): Chrome и exit webrtc.
 * Пока второй не подключён — буферизуем JSON до 200 сообщений на направление.
 * @param {import('ws').WebSocketServer} wss
 * @param {(exitSide: import('ws').WebSocket) => void} [onPaired] — после пары сокетов: не-127.0.0.1 считается стороной exit (bypass).
 */
/** @param {string} remoteAddress */
function isWsRemoteLoopback(remoteAddress) {
  const a = String(remoteAddress || '');
  return (
    a === '127.0.0.1' ||
    a === '::1' ||
    a.endsWith('127.0.0.1') ||
    a === '::ffff:127.0.0.1'
  );
}

function attachRtcChromeSignalingRelay(wss, onPaired) {
  /** @type {[import('ws').WebSocket|null, import('ws').WebSocket|null]} */
  const pair = [null, null];
  /** @type {Buffer[]} */
  const bufTo1 = [];
  /** @type {Buffer[]} */
  const bufTo0 = [];
  const MAXQ = 200;
  const flush = () => {
    const a = pair[0];
    const b = pair[1];
    if (!a || !b || a.readyState !== WebSocket.OPEN || b.readyState !== WebSocket.OPEN) return;
    while (bufTo1.length) {
      const d = bufTo1.shift();
      try {
        b.send(d);
      } catch {
        /* ignore */
      }
    }
    while (bufTo0.length) {
      const d = bufTo0.shift();
      try {
        a.send(d);
      } catch {
        /* ignore */
      }
    }
  };
  const wire = (idx) => {
    const ws = pair[idx];
    if (!ws) return;
    const otherIdx = 1 - idx;
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
        try {
          const j = JSON.parse(data.toString());
          if (j?.type) {
            console.warn(`[clean-vpn] relay slot${idx}→slot${otherIdx}: ${String(j.type)}`);
          }
        } catch {
          /* ignore */
        }
      }
      const o = pair[otherIdx];
      const buf = idx === 0 ? bufTo1 : bufTo0;
      if (o && o.readyState === WebSocket.OPEN) {
        try {
          o.send(data);
        } catch {
          /* ignore */
        }
      } else if (buf.length < MAXQ) {
        buf.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
      }
    });
  };
  const cleanupSlot = (idx) => {
    const w = pair[idx];
    pair[idx] = null;
    try {
      w?.close();
    } catch {
      /* ignore */
    }
    try {
      pair[1 - idx]?.close();
    } catch {
      /* ignore */
    }
    pair[1 - idx] = null;
    bufTo0.length = 0;
    bufTo1.length = 0;
  };
  wss.on('connection', (ws) => {
    if (pair[0] && pair[1]) {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
      return;
    }
    const idx = pair[0] ? 1 : 0;
    pair[idx] = ws;
    wire(idx);
    if (pair[0] && pair[1]) {
      flush();
      if (typeof onPaired === 'function') {
        const ra = (w) => String(w?._socket?.remoteAddress || '');
        const isLoc = (a) =>
          a === '127.0.0.1' ||
          a === '::1' ||
          a.endsWith('127.0.0.1') ||
          a === '::ffff:127.0.0.1';
        const w0 = pair[0];
        const w1 = pair[1];
        const r0 = ra(w0);
        const r1 = ra(w1);
        const exitSide = !isLoc(r0) ? w0 : !isLoc(r1) ? w1 : w1;
        try {
          onPaired(exitSide);
        } catch {
          /* ignore */
        }
      }
    }
    ws.on('close', () => {
      if (pair[idx] === ws) cleanupSlot(idx);
    });
    ws.on('error', () => {
      if (pair[idx] === ws) cleanupSlot(idx);
    });
  });
}

// =============================================================================
// === --type=udp + --punch: STUN (RFC 5389) + сигналинг WS на PORT+1 ===
// =============================================================================

const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const STUN_ATTR_MAPPED_ADDRESS = 0x0001;
const STUN_MAGIC = Buffer.from([0x21, 0x12, 0xa4, 0x42]);
const UDP_PUNCH_MAGIC = Buffer.from([0x43, 0x56, 0x50, 0x4e]); // CVPN — маркер punch-пакета
const CLEAN_VPN_UDP_REFLEXIVE = 'clean-vpn-udp-reflexive';

/**
 * @param {string} host
 * @returns {Promise<string[]>}
 */
async function resolveStunTargetIpv4s(host) {
  if (net.isIP(host) !== 0) return [host];
  /** @type {string[]} */
  const ips = [];
  try {
    for (const a of await dns.resolve4(host)) {
      if (ICE_INFRA_IPV4_RE.test(a)) ips.push(a);
    }
  } catch {
    /* ignore */
  }
  if (!ips.length) {
    try {
      const { address } = await dns.lookup(host, { family: 4 });
      if (ICE_INFRA_IPV4_RE.test(address)) ips.push(address);
    } catch {
      /* ignore */
    }
  }
  return ips;
}

/** @param {string} dstIp */
function logStunRouteDiag(dstIp) {
  if (!dstIp) return;
  try {
    const out = execFileSync('ip', ['route', 'get', dstIp], { encoding: 'utf8' });
    console.warn(`[clean-vpn] STUN ip route get ${dstIp}: ${out.trim()}`);
  } catch (e) {
    console.warn(`[clean-vpn] STUN ip route get ${dstIp}: ${e?.message || e}`);
  }
}

/** UDP punch: reuseAddr + recv buffer (multihomed / ARM). */
function createUdpPunchSocket() {
  return dgram.createSocket({
    type: 'udp4',
    reuseAddr: true,
    recvBufferSize: 256 * 1024,
  });
}

/**
 * @param {import('dgram').Socket} sock
 * @param {number} port
 * @param {string} host
 */
function bindUdp4Async(sock, port, host) {
  return new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.bind(port, host, () => {
      sock.off('error', reject);
      resolve(undefined);
    });
  });
}

/** Client punch: bind на uplink src (не 0.0.0.0 — иначе на multihomed ARM часто нет STUN-ответа). */
async function bindUdpPunchClientAsync(sock) {
  const forced = process.env.CLEAN_VPN_UDP_PUNCH_BIND?.trim();
  const uplink = forced || resolveUplinkBindIpv4();
  if (uplink) {
    try {
      await bindUdp4Async(sock, 0, uplink);
      const a = sock.address();
      console.log(`[clean-vpn] UDP punch: сокет привязан ${a.address}:${a.port} (uplink)`);
      return;
    } catch (e) {
      if (forced) throw e;
      console.warn(
        `[clean-vpn] UDP punch: bind ${uplink} не удался (${e?.message || e}), пробуем 0.0.0.0`,
      );
    }
  }
  await bindUdp4Async(sock, 0, '0.0.0.0');
  const a = sock.address();
  console.log(`[clean-vpn] UDP punch: сокет привязан ${a.address}:${a.port}`);
}

/**
 * @param {string[]} ndcIceServers — строки из convertIceServers
 * @returns {Array<{ host: string, port: number }>}
 */
function parseStunUdpServersFromIce(ndcIceServers) {
  /** @type {Array<{ host: string, port: number }>} */
  const out = [];
  for (const s of ndcIceServers) {
    const u = String(s);
    if (!u.startsWith('stun:') || u.includes('@')) continue;
    const rest = u.slice('stun:'.length);
    const lastColon = rest.lastIndexOf(':');
    if (lastColon <= 0) continue;
    const host = rest.slice(0, lastColon);
    const port = parseInt(rest.slice(lastColon + 1), 10);
    if (!host || !Number.isFinite(port) || port <= 0 || port > 65535) continue;
    out.push({ host, port });
  }
  return out;
}

/**
 * @param {Buffer} msg
 * @param {Buffer} tid
 * @returns {{ address: string, port: number } | null}
 */
function parseStunMappedFromResponse(msg, tid) {
  const xor = parseStunXorMappedAddress(msg, tid);
  if (xor) return xor;
  if (msg.length < 20) return null;
  if (msg.readUInt16BE(0) !== STUN_BINDING_RESPONSE) return null;
  if (!msg.subarray(4, 8).equals(STUN_MAGIC)) return null;
  if (!msg.subarray(8, 20).equals(tid)) return null;
  let o = 20;
  while (o + 4 <= msg.length) {
    const attrType = msg.readUInt16BE(o);
    const attrLen = msg.readUInt16BE(o + 2);
    o += 4;
    if (o + attrLen > msg.length) break;
    if (attrType === STUN_ATTR_MAPPED_ADDRESS && attrLen >= 8) {
      const v = msg.subarray(o, o + attrLen);
      if (v[1] !== 0x01) return null;
      const port = v.readUInt16BE(2);
      const a = `${v[4]}.${v[5]}.${v[6]}.${v[7]}`;
      return { address: a, port };
    }
    const pad = (4 - (attrLen % 4)) % 4;
    o += attrLen + pad;
  }
  return null;
}

/**
 * @param {Buffer} msg
 * @param {Buffer} tid
 * @returns {{ address: string, port: number } | null}
 */
function parseStunXorMappedAddress(msg, tid) {
  if (msg.length < 20) return null;
  if (msg.readUInt16BE(0) !== STUN_BINDING_RESPONSE) return null;
  if (!msg.subarray(4, 8).equals(STUN_MAGIC)) return null;
  if (!msg.subarray(8, 20).equals(tid)) return null;
  let o = 20;
  while (o + 4 <= msg.length) {
    const attrType = msg.readUInt16BE(o);
    const attrLen = msg.readUInt16BE(o + 2);
    o += 4;
    if (o + attrLen > msg.length) break;
    if (attrType === STUN_ATTR_XOR_MAPPED_ADDRESS && attrLen >= 8) {
      const v = msg.subarray(o, o + attrLen);
      const family = v[1];
      if (family !== 0x01) return null;
      const portXor = v.readUInt16BE(2) ^ STUN_MAGIC.readUInt16BE(0);
      const addrXor = v.readUInt32BE(4) ^ STUN_MAGIC.readUInt32BE(0);
      const a = `${(addrXor >>> 24) & 255}.${(addrXor >>> 16) & 255}.${(addrXor >>> 8) & 255}.${addrXor & 255}`;
      return { address: a, port: portXor };
    }
    const pad = (4 - (attrLen % 4)) % 4;
    o += attrLen + pad;
  }
  return null;
}

/**
 * @returns {{ req: Buffer, tid: Buffer }}
 */
function buildStunBindingRequestBuffer() {
  const tid = randomBytes(12);
  const req = Buffer.alloc(20);
  req.writeUInt16BE(STUN_BINDING_REQUEST, 0);
  req.writeUInt16BE(0, 2);
  STUN_MAGIC.copy(req, 4);
  tid.copy(req, 8);
  return { req, tid };
}

/**
 * @param {import('dgram').Socket} udpSocket
 * @param {string} stunHost
 * @param {number} stunPort
 * @param {number} timeoutMs
 * @returns {Promise<{ address: string, port: number }>}
 */
function stunBindingRequest(udpSocket, stunHost, stunPort, timeoutMs) {
  const { req, tid } = buildStunBindingRequestBuffer();
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(to);
      udpSocket.off('message', onMsg);
      udpSocket.off('error', onErr);
    };
    const to = setTimeout(() => {
      cleanup();
      if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
        try {
          const la = udpSocket.address();
          console.warn(
            `[clean-vpn] STUN/UDP: нет ответа за ${timeoutMs} мс от ${stunHost}:${stunPort} (сокет ${la.address}:${la.port})`,
          );
        } catch {
          console.warn(
            `[clean-vpn] STUN/UDP: нет ответа за ${timeoutMs} мс от ${stunHost}:${stunPort}`,
          );
        }
      }
      reject(new Error(`STUN UDP таймаут ${timeoutMs} мс к ${stunHost}:${stunPort}`));
    }, timeoutMs);
    const onMsg = (msg, rinfo) => {
      try {
        const mapped = parseStunMappedFromResponse(msg, tid);
        if (mapped) {
          cleanup();
          resolve(mapped);
          return;
        }
        if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1' && rinfo) {
          console.warn(
            `[clean-vpn] STUN/UDP: ${msg.length} B от ${rinfo.address}:${rinfo.port} — не Binding Response`,
          );
        }
      } catch {
        /* ignore */
      }
    };
    const onErr = (err) => {
      cleanup();
      reject(err);
    };
    udpSocket.on('message', onMsg);
    udpSocket.once('error', onErr);
    udpSocket.send(req, stunPort, stunHost, (err) => {
      if (err) {
        cleanup();
        reject(err);
        return;
      }
      if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
        try {
          const la = udpSocket.address();
          console.warn(
            `[clean-vpn] STUN/UDP: запрос 20 B → ${stunHost}:${stunPort} с ${la.address}:${la.port}`,
          );
        } catch {
          /* ignore */
        }
      }
    });
  });
}

/**
 * @param {import('dgram').Socket} udpSocket
 * @param {string[]} ndcIceServers
 * @param {number} perServerTimeoutMs
 */
async function stunGetMappedWithIceServers(udpSocket, ndcIceServers, perServerTimeoutMs) {
  const servers = parseStunUdpServersFromIce(ndcIceServers);
  if (!servers.length) {
    throw new Error(
      '[clean-vpn] UDP punch: в --config нет ни одного stun: сервера (нужен STUN для reflexive адреса)',
    );
  }
  console.log(
    `[clean-vpn] UDP punch STUN: ${servers.map((s) => `${s.host}:${s.port}`).join(', ')}`,
  );
  let lastErr;
  /** @type {string[]} */
  const tries = [];
  for (const { host, port } of servers) {
    const targets = await resolveStunTargetIpv4s(host);
    if (!targets.length) {
      tries.push(`${host}:${port} (DNS не дал IPv4)`);
      continue;
    }
    for (const stunHost of targets) {
      try {
        if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
          logStunRouteDiag(stunHost);
        }
        return await stunBindingRequest(udpSocket, stunHost, port, perServerTimeoutMs);
      } catch (e) {
        lastErr = e;
        tries.push(`${host}:${port}→${stunHost} (${e?.message || e})`);
      }
    }
  }
  throw new Error(
    `[clean-vpn] UDP punch: STUN не удался ни к одному серверу: ${lastErr?.message || lastErr}` +
      (tries.length ? `; попытки: ${tries.join('; ')}` : '') +
      '; на части сетей stun.l.google.com блокируется ISP — добавьте рабочий stun: в iceServers (см. config/default.json)',
  );
}

/**
 * Reflexive для punch — STUN всегда с punch-сокета (как в исходной реализации).
 * Exit с фиксированным :PORT: в сигналинг уходит public IP из STUN + listen port.
 * @param {import('dgram').Socket} udpSock
 * @param {string[]} ndcIceServers
 * @param {number} timeoutMs
 * @param {{ fixedListenPort?: boolean }} [opts]
 */
async function discoverUdpPunchReflexive(udpSock, ndcIceServers, timeoutMs, opts = {}) {
  const fixedListenPort = opts.fixedListenPort === true;
  let boundPort = 0;
  let boundAddr = '';
  try {
    const addr = udpSock.address();
    if (addr && typeof addr.port === 'number' && addr.port > 0) {
      boundPort = addr.port;
      boundAddr = addr.address || '';
    }
  } catch {
    /* socket not bound */
  }
  console.log(
    `[clean-vpn] UDP punch STUN: с punch-сокета ${boundAddr || '?'}:${boundPort || '?'}`,
  );
  const mapped = await stunGetMappedWithIceServers(udpSock, ndcIceServers, timeoutMs);
  if (fixedListenPort && boundPort > 0) {
    return { address: mapped.address, port: boundPort };
  }
  return mapped;
}

/**
 * Буфер JSON-сигналинга с WS open — сообщения не теряются до waitForJson.
 * @param {import('ws').WebSocket} sigWs
 */
function attachSignalingInbox(sigWs) {
  /** @type {object[]} */
  const queue = [];
  /** @type {Array<{ pred: (obj: object) => boolean, resolve: (obj: object) => void, to: ReturnType<typeof setTimeout> }>} */
  const waiters = [];

  /** @param {object} msg */
  const dispatch = (msg) => {
    if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1' && msg && typeof msg.type === 'string') {
      console.warn(`[clean-vpn] UDP punch inbox: recv type=${msg.type}`);
    }
    for (let i = 0; i < waiters.length; i++) {
      const w = waiters[i];
      try {
        if (w.pred(msg)) {
          clearTimeout(w.to);
          waiters.splice(i, 1);
          w.resolve(msg);
          return;
        }
      } catch {
        /* ignore */
      }
    }
    queue.push(msg);
  };

  const onMessage = (data, isBinary) => {
    if (isBinary) return;
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (!msg || typeof msg !== 'object') return;
    dispatch(msg);
  };

  sigWs.on('message', onMessage);

  return {
    /**
     * @param {(obj: object) => boolean} pred
     * @param {number} timeoutMs
     * @param {string} [waitLabel]
     */
    waitForJson(pred, timeoutMs, waitLabel) {
      const hitIdx = queue.findIndex((m) => {
        try {
          return pred(m);
        } catch {
          return false;
        }
      });
      if (hitIdx >= 0) {
        return Promise.resolve(queue.splice(hitIdx, 1)[0]);
      }
      return new Promise((resolve, reject) => {
        const to = setTimeout(() => {
          const wi = waiters.findIndex((w) => w.to === to);
          if (wi >= 0) waiters.splice(wi, 1);
          reject(
            new Error(
              `[clean-vpn] UDP punch: таймаут сигналинга ${timeoutMs} мс` +
                (waitLabel ? ` (${waitLabel})` : ''),
            ),
          );
        }, timeoutMs);
        waiters.push({ pred, resolve, to });
      });
    },
    detach() {
      sigWs.off('message', onMessage);
      queue.length = 0;
      for (const w of waiters) clearTimeout(w.to);
      waiters.length = 0;
    },
  };
}

/**
 * @param {{
 *   udpSock: import('dgram').Socket,
 *   sigWs: import('ws').WebSocket,
 *   ice: Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>,
 *   logPrefix: string,
 *   fixedListenPort?: boolean,
 *   mappedReflexive?: { address: string, port: number },
 *   sigInbox?: ReturnType<typeof attachSignalingInbox>,
 * }} opts
 * @returns {Promise<{ address: string, port: number }>}
 */
async function runUdpPunchAsPeer(opts) {
  const { udpSock, sigWs, ice, logPrefix } = opts;
  /** C-2: PSK для сигналинга udp-punch (просто HMAC nonce + ts, без DTLS). */
  const psk = opts.signalingPsk || null;
  const pskRequired = opts.signalingPskRequired !== false;
  const STUN_MS = 4000;
  const SIG_MS = 60000;
  const PUNCH_MS = 8000;
  const inbox = opts.sigInbox ?? attachSignalingInbox(sigWs);
  const ownsInbox = !opts.sigInbox;
  try {
  const mapped =
    opts.mappedReflexive ??
    (await discoverUdpPunchReflexive(udpSock, ice.ndcIceServers, STUN_MS, {
      fixedListenPort: opts.fixedListenPort === true,
    }));
  console.log(`[clean-vpn] UDP punch (${logPrefix}): reflexive ${mapped.address}:${mapped.port} (STUN)`);
  if (sigWs.readyState !== WebSocket.OPEN) {
    throw new Error('[clean-vpn] UDP punch: сигнальный WebSocket не OPEN');
  }
  if (psk) {
    const nonceHex = randomBytes(8).toString('hex');
    const ts = Date.now();
    const mac = signUdpPunchBind(psk, nonceHex, ts);
    const peerBindPromise = inbox.waitForJson(
      (m) => m.type === SIGNALING_UDPBIND_MSG_TYPE && m.nonce !== nonceHex,
      SIG_MS,
      `${logPrefix}: bind peer`,
    );
    if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
      console.warn(`[clean-vpn] UDP punch (${logPrefix}): send bind nonce=${nonceHex.slice(0, 8)}…`);
    }
    sigWs.send(
      JSON.stringify({
        type: SIGNALING_UDPBIND_MSG_TYPE,
        nonce: nonceHex,
        ts,
        mac,
      }),
    );
    const peerBind = await peerBindPromise;
    const err = verifyUdpPunchBind(psk, peerBind);
    if (err) {
      throw new Error(`[clean-vpn] UDP punch (${logPrefix}): подпись пира недопустима (bind_${err})`);
    }
    console.log(`[clean-vpn] UDP punch (${logPrefix}): подпись peer'а ОК (C-2)`);
  } else if (pskRequired) {
    throw new Error(
      `[clean-vpn] UDP punch (${logPrefix}): для C-2 нужен PSK (clean-vpn-hmac.key). Отключите проверку через --signaling-psk-required=false (только для отладки).`,
    );
  } else {
    console.warn(
      `[clean-vpn] UDP punch (${logPrefix}): PSK не задан, C-2 сигналинг bind пропущен (--signaling-psk-required=false)`,
    );
  }
  const selfRef = { address: mapped.address, port: mapped.port };
  const peerMsgPromise = inbox.waitForJson(
    (m) =>
      m.type === CLEAN_VPN_UDP_REFLEXIVE &&
      typeof m.address === 'string' &&
      Number.isFinite(Number(m.port)) &&
      (m.address !== selfRef.address || Number(m.port) !== selfRef.port),
    SIG_MS,
    `${logPrefix}: reflexive peer`,
  );
  sigWs.send(
    JSON.stringify({
      type: CLEAN_VPN_UDP_REFLEXIVE,
      address: mapped.address,
      port: mapped.port,
    }),
  );
  const peerMsg = await peerMsgPromise;
  const peerAddress = String(peerMsg.address);
  const peerPort = Number(peerMsg.port);
  console.log(`[clean-vpn] UDP punch (${logPrefix}): peer reflexive ${peerAddress}:${peerPort}`);
  const iv = setInterval(() => {
    try {
      udpSock.send(UDP_PUNCH_MAGIC, peerPort, peerAddress);
    } catch {
      /* ignore */
    }
  }, 40);
  try {
    const got = await new Promise((resolve, reject) => {
      const to = setTimeout(() => {
        udpSock.off('message', onUdp);
        reject(
          new Error(
            `[clean-vpn] UDP punch (${logPrefix}): за ${PUNCH_MS} мс не получен UDP от пира (NAT/symmetric; попробуйте webrtc или путь с белым IP)`,
          ),
        );
      }, PUNCH_MS);
      const onUdp = (msg, rinfo) => {
        if (rinfo.address === peerAddress && rinfo.port === peerPort && msg.length >= 4) {
          clearTimeout(to);
          udpSock.off('message', onUdp);
          resolve({ address: rinfo.address, port: rinfo.port });
        }
      };
      udpSock.on('message', onUdp);
    });
    return got;
  } finally {
    clearInterval(iv);
  }
  } finally {
    if (ownsInbox) inbox.detach();
  }
}

function assertOutboundWsHost(host, hint) {
  if (host === '0.0.0.0' || host === '::' || host === '[::]') {
    throw new Error(
      `[clean-vpn] для исходящего WebSocket укажите реальный адрес пира в --server, либо поднимите приёмник на этой ноде (${hint}).`,
    );
  }
}

function createWebrtcWsSignal(ws) {
  return (msg) => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(msg));
      } catch {
        /* ignore */
      }
    }
  };
}

function tryParseWebrtcSignalingJson(data, isBinary) {
  if (isBinary) return null;
  try {
    return JSON.parse(data.toString());
  } catch {
    return null;
  }
}

/**
 * Парсер минимально достаточных полей ICE candidate-line (RFC 5245):
 *   candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type> ...
 * Возвращает null если не удаётся распознать.
 * @param {string} candidate
 * @returns {{ ip: string, port: string, type: string }|null}
 */
function parseIceCandidateFields(candidate) {
  if (!candidate) return null;
  const trimmed = String(candidate).trim().replace(/^a=/i, '');
  const parts = trimmed.split(/\s+/);
  if (parts.length < 8) return null;
  const typIdx = parts.indexOf('typ');
  if (typIdx === -1 || typIdx + 1 >= parts.length) return null;
  return { ip: parts[4] || '', port: parts[5] || '', type: parts[typIdx + 1] || '' };
}

/**
 * Приватный/loopback/link-local адрес (RFC1918, IPv6 ULA, link-local).
 * @param {string} ip
 */
function isPrivateOrLoopbackIp(ip) {
  if (!ip) return false;
  if (ip === '0.0.0.0' || ip === '::' || ip === '::1') return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  const low = ip.toLowerCase();
  if (low.startsWith('fc') || low.startsWith('fd')) return true;
  if (low.startsWith('fe80:')) return true;
  return false;
}

/**
 * Отбросить ли ICE candidate (M-5): `typ host` и `typ prflx` для приватных диапазонов RFC1918
 * (утечка внутренних IP). `srflx`/`relay` остаются — это публичные mapping'и, нужны для NAT-traversal.
 * Host с публичным IPv4 (например, сервер с белым адресом) тоже остаётся — не утечка.
 * При `allowHost=true` ничего не фильтруем (флаг отладки).
 * @param {string} candidate
 * @param {boolean} allowHost
 */
function shouldDropIceCandidate(candidate, allowHost) {
  if (allowHost) return false;
  const f = parseIceCandidateFields(candidate);
  if (!f) return false;
  if (f.type === 'host' || f.type === 'prflx') {
    return isPrivateOrLoopbackIp(f.ip);
  }
  return false;
}

/**
 * Обёртка для отправки локального candidate с фильтром host/prflx-RFC1918 (M-5).
 * @param {(msg: { type: string, candidate: string, mid?: string }) => void} signal
 * @param {string} candidate
 * @param {string|undefined} mid
 * @param {boolean} allowHost
 * @param {string} logPrefix
 */
function emitFilteredLocalCandidate(signal, candidate, mid, allowHost, logPrefix) {
  if (shouldDropIceCandidate(candidate, allowHost)) {
    const f = parseIceCandidateFields(candidate);
    const detail = f ? `${f.ip} typ=${f.type}` : candidate.slice(0, 96);
    console.log(
      `[clean-vpn] ${logPrefix}: drop local host/prflx-private candidate (M-5; ${detail}; --allow-host-candidates для opt-out)`,
    );
    return;
  }
  signal({ type: 'candidate', candidate, mid });
}

/**
 * @param {import('node-datachannel').PeerConnection|null} pc
 * @param {{ type: string, sdp?: string, candidate?: string, mid?: string }} msg
 * @param {{ allowHostCandidates?: boolean, logPrefix?: string, routeCtx?: { splitDefault?: boolean, gw?: string|null, dev?: string, serverIp?: string|null, peerIp?: string|null, infraBypassIps?: string[], snapInfra?: unknown[] } }} [opts]
 */
function applyWebrtcRemoteSignal(pc, msg, opts = {}) {
  if (!pc) return;
  if (msg.type === 'offer') pc.setRemoteDescription(msg.sdp, 'Offer');
  else if (msg.type === 'answer') pc.setRemoteDescription(msg.sdp, 'Answer');
  else if (msg.type === 'candidate') {
    if (shouldDropIceCandidate(msg.candidate, !!opts.allowHostCandidates)) {
      const f = parseIceCandidateFields(msg.candidate);
      const detail = f ? `${f.ip} typ=${f.type}` : String(msg.candidate).slice(0, 96);
      console.log(
        `[clean-vpn] ${opts.logPrefix || 'webrtc'}: drop remote host/prflx-private candidate (M-5; ${detail})`,
      );
      return;
    }
    maybeBypassIceCandidateIp(opts.routeCtx, msg.candidate);
    try {
      pc.addRemoteCandidate(msg.candidate, msg.mid || '0');
    } catch (e) {
      console.warn('[clean-vpn] addRemoteCandidate:', e?.message || e);
    }
  }
}

function logWebrtcSigWsError(err) {
  console.error('[clean-vpn] webrtc signalling ws:', err.message);
}

/**
 * @param {import('ws').WebSocket} ws
 * @param {ReturnType<typeof openTunNative>['tun']} tun
 * @param {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} ice
 * @param {{
 *   setActive: (pc: import('node-datachannel').PeerConnection | null) => void;
 *   clearIfStill: (pc: import('node-datachannel').PeerConnection) => void;
 * }} pcRef
 */
function attachCleanVpnWebrtcExitSignaling(
  ws,
  tun,
  ice,
  pcRef,
  tunBridgeOpts = BRIDGE_OPTS_EXIT,
  iceOpts = {},
) {
  let handshakeDone = false;
  /** @type {import('node-datachannel').PeerConnection|null} */
  let connPc = null;
  /** @type {{ reconnectWire: (newEp: any) => void } | null} */
  let bridgeApi = null;
  const signal = createWebrtcWsSignal(ws);
  const allowHost = !!iceOpts.allowHostCandidates;
  /** C-2: PSK для подписания/проверки DTLS fingerprint. null → fallback с warning. */
  const psk = iceOpts.signalingPsk || null;
  const pskRequired = iceOpts.signalingPskRequired !== false;
  /** Expected remote (client) fingerprint после получения `clean-vpn-bind`. */
  let expectedRemoteFingerprint = /** @type {string|null} */ (null);
  /** @type {Set<string>} */
  const seenNonces = new Set();

  const closeWithReason = (reason) => {
    console.warn(`[clean-vpn] webrtc exit signaling: отклоняем (${reason})`);
    try {
      ws.close(1008, reason);
    } catch {
      /* ignore */
    }
  };

  const resetWebrtcSession = (reason = '') => {
    if (connPc) {
      const dead = connPc;
      connPc = null;
      safe(() => dead.destroy());
      pcRef.clearIfStill(dead);
    }
    handshakeDone = false;
    expectedRemoteFingerprint = null;
    seenNonces.clear();
    if (reason) {
      console.log(`[clean-vpn] webrtc exit signaling: сессия сброшена (${reason})`);
    }
  };

  const bridgeOptsWebrtc = {
    ...tunBridgeOpts,
    onWebrtcWireDown: () => resetWebrtcSession('wire down'),
  };

  const sendOwnBindForFingerprint = (fp) => {
    if (!psk || !fp) return;
    const nonceHex = randomBytes(8).toString('hex');
    const ts = Date.now();
    const mac = signSignalingBind(psk, fp, nonceHex, ts);
    signal({
      type: SIGNALING_BIND_MSG_TYPE,
      fingerprint: fp,
      nonce: nonceHex,
      ts,
      mac,
    });
  };

  const setupInitiator = () => {
    if (handshakeDone) return;
    handshakeDone = true;
    connPc = new ndcPeerConnectionClass('clean-vpn-exit', {
      iceServers: ice.ndcIceServers,
      maxMessageSize: 65536,
      ...(ice.iceMode === 'relay' ? { iceTransportPolicy: 'relay' } : {}),
    });
    pcRef.setActive(connPc);

    let boundSent = false;
    connPc.onLocalDescription((sdp, t) => {
      const fp = extractDtlsFingerprintFromSdp(sdp);
      if (psk && fp && !boundSent) {
        boundSent = true;
        sendOwnBindForFingerprint(fp);
      } else if (!psk && pskRequired) {
        closeWithReason('no_signaling_psk');
        return;
      }
      signal({ type: String(t).toLowerCase(), sdp });
    });
    connPc.onLocalCandidate((candidate, mid) => {
      emitFilteredLocalCandidate(signal, candidate, mid, allowHost, 'webrtc exit');
    });
    connPc.onStateChange((state) => {
      console.log('[clean-vpn] webrtc exit PC:', state);
    });

    const dc = connPc.createDataChannel('clean-vpn');
    dc.onOpen(() => {
      console.log('[clean-vpn] DataChannel open (exit)');
      if (!bridgeApi) {
        bridgeApi = attachTunBridge(tun, 'webrtc-dc', dc, bridgeOptsWebrtc);
      } else {
        bridgeApi.reconnectWire(dc);
      }
    });
    dc.onClosed(() => {
      console.log('[clean-vpn] DataChannel closed (exit)');
      if (handshakeDone || connPc) {
        resetWebrtcSession('dc closed');
      }
    });
    dc.onError((err) => {
      console.error('[clean-vpn] DataChannel error (exit):', err);
    });
  };

  ws.on('message', (data, isBinary) => {
    const msg = tryParseWebrtcSignalingJson(data, isBinary);
    if (!msg) return;
    if (msg.type === SIGNALING_BIND_MSG_TYPE) {
      if (!psk) {
        if (pskRequired) {
          closeWithReason('no_psk');
          return;
        }
        return;
      }
      const err = verifySignalingBind(psk, msg);
      if (err) {
        closeWithReason(`bind_${err}`);
        return;
      }
      if (seenNonces.has(msg.nonce)) {
        closeWithReason('bind_nonce_replay');
        return;
      }
      seenNonces.add(msg.nonce);
      expectedRemoteFingerprint = msg.fingerprint;
      console.log(
        `[clean-vpn] webrtc exit signaling: принят ${SIGNALING_BIND_MSG_TYPE} (fingerprint=${msg.fingerprint})`,
      );
      return;
    }
    if (msg.type === 'clean-vpn-ready') {
      if (psk == null && pskRequired && !handshakeDone) {
        closeWithReason('exit_no_psk');
        return;
      }
      if (handshakeDone) {
        resetWebrtcSession('повторный clean-vpn-ready');
      }
      if (!handshakeDone) {
        setupInitiator();
      }
      return;
    }
    if (msg.type === 'offer' || msg.type === 'answer') {
      if (psk) {
        if (!expectedRemoteFingerprint) {
          closeWithReason('bind_missing_before_sdp');
          return;
        }
        const fp = extractDtlsFingerprintFromSdp(msg.sdp);
        if (!signalingFingerprintsEqual(fp, expectedRemoteFingerprint)) {
          closeWithReason('bind_sdp_fingerprint_mismatch');
          return;
        }
      } else if (pskRequired) {
        closeWithReason('no_psk_for_sdp');
        return;
      }
    }
    applyWebrtcRemoteSignal(connPc, msg, {
      allowHostCandidates: allowHost,
      logPrefix: 'webrtc exit',
    });
  });

  ws.on('close', () => {
    resetWebrtcSession('ws close');
  });

  ws.on('error', logWebrtcSigWsError);
}

/**
 * @param {import('ws').WebSocket} ws
 * @param {ReturnType<typeof openTunNative>['tun']} tun
 * @param {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} ice
 * @param {{
 *   setActive: (pc: import('node-datachannel').PeerConnection | null) => void;
 *   clearIfStill: (pc: import('node-datachannel').PeerConnection) => void;
 * }} pcRef
 */
function attachCleanVpnWebrtcClientSignaling(
  ws,
  tun,
  ice,
  pcRef,
  tunBridgeOpts = BRIDGE_OPTS_CLIENT,
  iceOpts = {},
) {
  const signal = createWebrtcWsSignal(ws);
  const allowHost = !!iceOpts.allowHostCandidates;
  /** C-2 */
  const psk = iceOpts.signalingPsk || null;
  const pskRequired = iceOpts.signalingPskRequired !== false;
  let expectedRemoteFingerprint = /** @type {string|null} */ (null);
  /** @type {Set<string>} */
  const seenNonces = new Set();
  /** @type {import('node-datachannel').PeerConnection|null} */
  let pc = null;
  /** @type {((dc: import('node-datachannel').DataChannel) => void)|null} */
  let pendingDcOpenResolve = null;
  /** @type {ReturnType<typeof setTimeout>|null} */
  let pendingDcOpenTimer = null;
  const SIG_MS = 60000;

  const closeWithReason = (reason) => {
    console.warn(`[clean-vpn] webrtc client signaling: отклоняем (${reason})`);
    try {
      ws.close(1008, reason);
    } catch {
      /* ignore */
    }
  };

  const pcConfig = {
    iceServers: ice.ndcIceServers,
    maxMessageSize: 65536,
    ...(ice.iceMode === 'relay' ? { iceTransportPolicy: 'relay' } : {}),
  };

  const keepAliveSec =
    typeof tunBridgeOpts?.keepAliveSec === 'number' &&
    Number.isFinite(tunBridgeOpts.keepAliveSec) &&
    tunBridgeOpts.keepAliveSec > 0
      ? Math.floor(tunBridgeOpts.keepAliveSec)
      : 0;

  const resetClientSession = (reason = '') => {
    if (pendingDcOpenTimer) {
      clearTimeout(pendingDcOpenTimer);
      pendingDcOpenTimer = null;
    }
    pendingDcOpenResolve = null;
    if (pc) {
      const dead = pc;
      pc = null;
      safe(() => dead.destroy());
      pcRef.clearIfStill(dead);
    }
    expectedRemoteFingerprint = null;
    seenNonces.clear();
    if (reason) {
      console.log(`[clean-vpn] webrtc client signaling: сессия сброшена (${reason})`);
    }
  };

  const bridgeOptsWebrtc = {
    ...tunBridgeOpts,
    onWebrtcWireDown: () => resetClientSession('wire down'),
  };

  const sendOwnBindForFingerprint = (fp) => {
    if (!psk || !fp) return;
    const nonceHex = randomBytes(8).toString('hex');
    const ts = Date.now();
    const mac = signSignalingBind(psk, fp, nonceHex, ts);
    signal({
      type: SIGNALING_BIND_MSG_TYPE,
      fingerprint: fp,
      nonce: nonceHex,
      ts,
      mac,
    });
  };

  const setupPeerConnection = () => {
    if (iceOpts.routeCtx?.splitDefault) {
      void ensureClientInfraBypass(
        iceOpts.routeCtx,
        iceOpts.routeCtx.iceConfigPath,
        iceOpts.routeCtx.iceMode,
      ).catch((e) => {
        console.warn('[clean-vpn] infra bypass refresh перед ICE:', e?.message || e);
      });
    }
    resetClientSession();
    const newPc = new ndcPeerConnectionClass('clean-vpn-client', pcConfig);
    pc = newPc;
    pcRef.setActive(newPc);

    let boundSent = false;
    newPc.onLocalDescription((sdp, t) => {
      const fp = extractDtlsFingerprintFromSdp(sdp);
      if (psk && fp && !boundSent) {
        boundSent = true;
        sendOwnBindForFingerprint(fp);
      } else if (!psk && pskRequired) {
        closeWithReason('no_signaling_psk');
        return;
      }
      signal({ type: String(t).toLowerCase(), sdp });
    });
    newPc.onLocalCandidate((candidate, mid) => {
      emitFilteredLocalCandidate(signal, candidate, mid, allowHost, 'webrtc client');
    });
    newPc.onStateChange((state) => {
      console.log('[clean-vpn] webrtc client PC:', state);
    });

    newPc.onDataChannel((dc) => {
      dc.onError((err) => {
        console.error('[clean-vpn] DataChannel error (client):', err);
      });
      dc.onOpen(() => {
        console.log('[clean-vpn] DataChannel open (client)');
        if (typeof iceOpts.onWireReady === 'function') {
          try {
            iceOpts.onWireReady();
          } catch (e) {
            console.warn('[clean-vpn] webrtc client onWireReady:', e?.message || e);
          }
        }
        if (pendingDcOpenResolve) {
          const resolve = pendingDcOpenResolve;
          pendingDcOpenResolve = null;
          if (pendingDcOpenTimer) {
            clearTimeout(pendingDcOpenTimer);
            pendingDcOpenTimer = null;
          }
          resolve(dc);
        }
      });
    });

    return newPc;
  };

  const connectDataChannel = async () => {
    setupPeerConnection();
    return new Promise((resolve, reject) => {
      pendingDcOpenResolve = resolve;
      pendingDcOpenTimer = setTimeout(() => {
        pendingDcOpenTimer = null;
        pendingDcOpenResolve = null;
        reject(new Error(`timeout ожидания DataChannel (${SIG_MS}ms)`));
      }, SIG_MS);
      pendingDcOpenTimer.unref?.();
      try {
        ws.send(JSON.stringify({ type: 'clean-vpn-ready' }));
      } catch (e) {
        if (pendingDcOpenTimer) {
          clearTimeout(pendingDcOpenTimer);
          pendingDcOpenTimer = null;
        }
        pendingDcOpenResolve = null;
        reject(e);
      }
    });
  };

  attachOutboundTunBridge(
    tun,
    'webrtc-dc',
    bridgeOptsWebrtc,
    connectDataChannel,
    keepAliveSec,
    tunBridgeOpts?.keepAliveReconnectCooldownSec ?? 0,
    !!tunBridgeOpts?.eagerWireOnStart,
  );

  ws.on('message', (data, isBinary) => {
    const msg = tryParseWebrtcSignalingJson(data, isBinary);
    if (!msg || !pc) return;
    if (msg.type === SIGNALING_BIND_MSG_TYPE) {
      if (!psk) {
        if (pskRequired) {
          closeWithReason('no_psk');
          return;
        }
        return;
      }
      const err = verifySignalingBind(psk, msg);
      if (err) {
        closeWithReason(`bind_${err}`);
        return;
      }
      if (seenNonces.has(msg.nonce)) {
        closeWithReason('bind_nonce_replay');
        return;
      }
      seenNonces.add(msg.nonce);
      expectedRemoteFingerprint = msg.fingerprint;
      console.log(
        `[clean-vpn] webrtc client signaling: принят ${SIGNALING_BIND_MSG_TYPE} (fingerprint=${msg.fingerprint})`,
      );
      return;
    }
    if (msg.type === 'offer' || msg.type === 'answer') {
      if (psk) {
        if (!expectedRemoteFingerprint) {
          closeWithReason('bind_missing_before_sdp');
          return;
        }
        const fp = extractDtlsFingerprintFromSdp(msg.sdp);
        if (!signalingFingerprintsEqual(fp, expectedRemoteFingerprint)) {
          closeWithReason('bind_sdp_fingerprint_mismatch');
          return;
        }
      } else if (pskRequired) {
        closeWithReason('no_psk_for_sdp');
        return;
      }
    }
    applyWebrtcRemoteSignal(pc, msg, {
      allowHostCandidates: allowHost,
      logPrefix: 'webrtc client',
      routeCtx: iceOpts.routeCtx,
    });
  });

  ws.on('error', logWebrtcSigWsError);

  ws.on('close', () => {
    resetClientSession('ws close');
  });
}

// =============================================================================
// === Общее: разбор CLI, parseHostPort, снимки и правки ip route (client) ===
// =============================================================================

function parseArgs(argv) {
  const out = {
    role: null,
    server: null,
    type: null,
    splitDefault: false,
    extIface: null,
    configPath: null,
    iceMode: null,
    quicCertsDir: null,
    quicExtCryptoKey: null,
    sharedHmacKey: null,
    tlsCertDir: null,
    tlsServerName: null,
    tlsClientSni: null,
    tlsPublicName: null,
    tlsProbeTarget: null,
    tlsProbeMaxBytes: null,
    tlsProbeMaxSeconds: null,
    tlsProbeFullProxyPerIp: null,
    tlsHttpVers: null,
    wsChromeExecutable: null,
    wsChromeWsUrl: null,
    wsChromeUrl: null,
    wsChromeExitPage: false,
    wsChromeCdpData: false,
    rtcChromeExecutable: null,
    tunnelPeer: null,
    signaling: false,
    wsServer: false,
    punch: false,
    keepAliveSec: null,
    keepAliveReconnectCooldownSec: null,
    clientLanSubnet: null,
    transparentTlsLanBind: null,
    boringTlsHelper: null,
    boringTlsProfile: null,
    boringTlsClienthelloProfile: null,
    boringTlsJa3Strict: false,
    tlsLogJa3: false,
    ja3Verbose: false,
    tlsLogBearer: false,
    allowHostCandidates: false,
    signalingPskRequired: true,
  };
  for (const a of argv) {
    if (a.startsWith('--role=')) out.role = a.slice('--role='.length);
    else if (a.startsWith('--server=')) out.server = a.slice('--server='.length);
    else if (a.startsWith('--type=')) out.type = a.slice('--type='.length);
    else if (a.startsWith('--ext=')) out.extIface = a.slice('--ext='.length);
    else if (a.startsWith('--config=')) out.configPath = a.slice('--config='.length);
    else if (a.startsWith('--ice-mode=')) out.iceMode = a.slice('--ice-mode='.length);
    else if (a.startsWith('--quic-certs-dir=')) {
      out.quicCertsDir = a.slice('--quic-certs-dir='.length);
    } else if (a.startsWith('--quic-ext-crypto-key=')) {
      out.quicExtCryptoKey = a.slice('--quic-ext-crypto-key='.length);
    } else if (a.startsWith('--shared-hmac-key=')) {
      out.sharedHmacKey = a.slice('--shared-hmac-key='.length);
    } else if (a.startsWith('--tls-cert-dir=')) {
      out.tlsCertDir = a.slice('--tls-cert-dir='.length);
    } else if (a.startsWith('--tls-server-name=')) {
      out.tlsServerName = a.slice('--tls-server-name='.length);
    } else if (a.startsWith('--tls-client-sni=')) {
      out.tlsClientSni = a.slice('--tls-client-sni='.length);
    } else if (a.startsWith('--tls-public-name=')) {
      out.tlsPublicName = a.slice('--tls-public-name='.length);
    } else if (a.startsWith('--tls-probe-target=')) {
      out.tlsProbeTarget = a.slice('--tls-probe-target='.length);
    } else if (a.startsWith('--tls-probe-max-bytes=')) {
      out.tlsProbeMaxBytes = parseInt(a.slice('--tls-probe-max-bytes='.length), 10);
    } else if (a.startsWith('--tls-probe-max-seconds=')) {
      out.tlsProbeMaxSeconds = parseInt(a.slice('--tls-probe-max-seconds='.length), 10);
    } else if (a.startsWith('--tls-probe-full-proxy-per-ip=')) {
      out.tlsProbeFullProxyPerIp = parseInt(a.slice('--tls-probe-full-proxy-per-ip='.length), 10);
    } else if (a.startsWith('--http-vers=')) {
      out.tlsHttpVers = a.slice('--http-vers='.length).trim();
    } else if (a.startsWith('--ws-chrome-executable=')) {
      out.wsChromeExecutable = a.slice('--ws-chrome-executable='.length);
    } else if (a.startsWith('--ws-chrome-ws-url=')) {
      out.wsChromeWsUrl = a.slice('--ws-chrome-ws-url='.length);
    } else if (a.startsWith('--ws-chrome-url=')) {
      out.wsChromeUrl = a.slice('--ws-chrome-url='.length);
    } else if (a === '--ws-chrome-exit-page') out.wsChromeExitPage = true;
    else if (a === '--ws-chrome-cdp-data') out.wsChromeCdpData = true;
    else if (a.startsWith('--rtc-chrome-executable=')) {
      out.rtcChromeExecutable = a.slice('--rtc-chrome-executable='.length);
    } else if (a.startsWith('--tunnel-peer=')) {
      out.tunnelPeer = a.slice('--tunnel-peer='.length);
    } else if (a === '--split-default') out.splitDefault = true;
    else if (a === '--signaling' || a === '--signalling') out.signaling = true;
    else if (a === '--ws-server') out.wsServer = true;
    else if (a === '--punch') out.punch = true;
    else if (a.startsWith('--keep-alive=')) {
      out.keepAliveSec = parseInt(a.slice('--keep-alive='.length), 10);
    } else if (a.startsWith('--keep-alive-reconnect-cooldown=')) {
      out.keepAliveReconnectCooldownSec = parseInt(
        a.slice('--keep-alive-reconnect-cooldown='.length),
        10,
      );
    } else if (a.startsWith('--client-lan-subnet=')) {
      out.clientLanSubnet = a.slice('--client-lan-subnet='.length).trim();
    } else if (a.startsWith('--transparent-tls-lan-bind=')) {
      out.transparentTlsLanBind = a.slice('--transparent-tls-lan-bind='.length).trim();
    } else if (a.startsWith('--boring-tls-helper=')) {
      out.boringTlsHelper = a.slice('--boring-tls-helper='.length).trim();
    } else if (a.startsWith('--boring-tls-profile=')) {
      out.boringTlsProfile = a.slice('--boring-tls-profile='.length).trim();
    } else if (a.startsWith('--boring-tls-clienthello-profile=')) {
      out.boringTlsClienthelloProfile = path.resolve(
        a.slice('--boring-tls-clienthello-profile='.length).trim(),
      );
    } else if (a === '--boring-tls-profile-ja3-strict') {
      out.boringTlsJa3Strict = true;
    } else if (a === '--tls-log-ja3') {
      out.tlsLogJa3 = true;
    } else if (a === '--tls-log-bearer') {
      out.tlsLogBearer = true;
    } else if (a === '--ja3-verbose') {
      out.ja3Verbose = true;
    } else if (a === '--allow-host-candidates') {
      out.allowHostCandidates = true;
    } else if (a === '--signaling-psk-required=false' || a === '--no-signaling-psk-required') {
      out.signalingPskRequired = false;
    } else if (a === '--signaling-psk-required' || a === '--signaling-psk-required=true') {
      out.signalingPskRequired = true;
    }
  }
  if (out.type) out.type = String(out.type).trim();
  return out;
}

function parseHostPort(s) {
  const m = String(s).match(/^(.+):(\d+)$/);
  if (!m) throw new Error(`Неверный --server=${s}, ожидается host:port`);
  return { host: m[1], port: parseInt(m[2], 10) };
}

/** Только IPv4 (+ опционально :PORT); для `--type=transparent-tls` + client без iptables SO_ORIGINAL_DST. */
function parseTransparentTlsTunnelPeerIpv4(s) {
  const t = String(s).trim();
  const m = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/);
  if (!m)
    throw new Error(
      'transparent-tls + --tunnel-peer: ожидается IPv4 или IPv4:PORT (без имени хоста), порт по умолчанию 443.',
    );
  const port = m[2] != null ? parseInt(m[2], 10) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('transparent-tls: неверный порт в --tunnel-peer');
  return { address: m[1], port };
}

/**
 * Exit transparent-tls: TLS ClientHello (0x16) → enc-SNI relay; иначе IPv4 mux в TUN.
 * @param {{ tlsLogJa3?: boolean, ja3Verbose?: boolean }} [ttlLogOpts]
 */
function peekDispatchExitTransparentTlsOrIpv4Sock(sock, vpnSecretBuf, publicName, startBridgeTcp, ttlLogOpts) {
  const peer = tlsClientIp(sock);
  const rp = sock.remotePort ?? '?';
  const release = exitPeekAcquire();
  if (!release) {
    console.log(
      `[clean-vpn transparent-tls exit] peek отклонён: лимит pending peek превышен; peer=${peer}:${rp}`,
    );
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
    return;
  }
  /** @type {Buffer[]} */
  let acc = [];
  let len = 0;
  let finalized = false;
  /** @type {ReturnType<typeof setTimeout>|undefined} */
  let stallTimer;

  const cleanupPeek = () => {
    sock.off('data', onData);
    sock.off('error', onPeekErrOrClose);
    sock.off('close', onPeekErrOrClose);
    if (stallTimer !== undefined) {
      clearTimeout(stallTimer);
      stallTimer = undefined;
    }
    release();
  };

  const failStale = (reason) => {
    if (finalized) return;
    finalized = true;
    cleanupPeek();
    console.log(
      `[clean-vpn transparent-tls exit] peek прерван: peer=${peer}:${rp} reason=${reason}`,
    );
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
  };

  const timeoutMs = exitPeekTimeoutMs();
  stallTimer = setTimeout(() => failStale(`${timeoutMs}ms без данных`), timeoutMs);
  stallTimer.unref?.();

  function onPeekErrOrClose() {
    failStale('error/close до маршрутизации');
  }

  /** @type {(chunk: Buffer | string) => void} */
  function onData(chunk) {
    if (finalized) return;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    acc.push(b);
    len += b.length;
    if (len < 1) return;

    const merged = Buffer.concat(acc, len);
    if (merged[0] !== 0x16) {
      finalized = true;
      cleanupPeek();
      const pref = peekPrefixDescribe(merged);
      logNonTlsExitDispatch('transparent-tls', 'ipv4-mux', {
        peer: `${peer}:${rp}`,
        firstByte: pref.firstByte,
        len: pref.len,
        hexPreview: pref.hexPreview,
      });
      startBridgeTcp(sock, merged, 'tcp');
      return;
    }

    const parsed = parseFirstTlsClientHelloFromTcpBuf(merged);
    if ('needMore' in parsed && parsed.needMore) {
      if (len > TLS_MUX_MAX_CLIENT_BUF) failStale('client_hello_oversize');
      return;
    }

    finalized = true;
    cleanupPeek();
    console.log(
      `[clean-vpn transparent-tls exit] TLS ClientHello → enc-SNI relay peer=${peer}:${rp}`,
    );
    wireTransparentTlsEncSniSession(/** @type {import('net').Socket} */ (sock), {
      vpnSecretBuf,
      publicName,
      logOpts: ttlLogOpts,
      initialBuf: merged,
      modeTag: 'transparent-tls',
    });
  }

  sock.on('data', onData);
  sock.once('error', onPeekErrOrClose);
  sock.once('close', onPeekErrOrClose);
}

/**
 * Exit `--type=combo-tls`: enc-SNI relay (SNI `*.publicName` + decrypt OK) или TLS mux.
 * @param {Buffer} vpnSecretBuf PSK для enc-SNI и Bearer
 */
function peekDispatchExitComboTlsSock(sock, vpnSecretBuf, publicName, tlsCtx, ttlLogOpts) {
  const peer = tlsClientIp(sock);
  const rp = sock.remotePort ?? '?';
  const release = exitPeekAcquire();
  if (!release) {
    console.log(
      `[clean-vpn combo-tls exit] peek отклонён: лимит pending peek превышен; peer=${peer}:${rp}`,
    );
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
    return;
  }
  /** @type {Buffer[]} */
  let acc = [];
  let len = 0;
  let finalized = false;
  /** @type {ReturnType<typeof setTimeout>|undefined} */
  let stallTimer;

  const cleanupPeek = () => {
    sock.off('data', onData);
    sock.off('error', onPeekErrOrClose);
    sock.off('close', onPeekErrOrClose);
    if (stallTimer !== undefined) {
      clearTimeout(stallTimer);
      stallTimer = undefined;
    }
    release();
  };

  const failStale = (reason) => {
    if (finalized) return;
    finalized = true;
    cleanupPeek();
    console.log(
      `[clean-vpn combo-tls exit] peek прерван: peer=${peer}:${rp} reason=${reason}`,
    );
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
  };

  const timeoutMs = exitPeekTimeoutMs();
  stallTimer = setTimeout(() => failStale(`${timeoutMs}ms без данных`), timeoutMs);
  stallTimer.unref?.();

  function onPeekErrOrClose() {
    failStale('error/close до маршрутизации');
  }

  /** @type {(chunk: Buffer | string) => void} */
  function onData(chunk) {
    if (finalized) return;
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    acc.push(b);
    len += b.length;

    const merged = Buffer.concat(acc, len);
    const route = classifyComboTlsExitPrefix(merged, publicName, vpnSecretBuf);
    if (route.status === 'need_more') {
      if (len > TLS_MUX_MAX_CLIENT_BUF) failStale('client_hello_oversize');
      return;
    }

    finalized = true;
    cleanupPeek();

    const tagPeer = `${peer}:${rp}`;
    if (route.status === 'relay') {
      wireTransparentTlsEncSniSession(/** @type {import('net').Socket} */ (sock), {
        vpnSecretBuf,
        publicName,
        logOpts: ttlLogOpts,
        initialBuf: merged,
        modeTag: 'combo-tls',
      });
      return;
    }

    if (merged[0] !== 0x16) {
      const pref = peekPrefixDescribe(merged);
      logNonTlsExitDispatch('combo-tls', 'tls-mux', {
        peer: tagPeer,
        firstByte: pref.firstByte,
        len: pref.len,
        hexPreview: pref.hexPreview,
      });
      logComboTlsExitBranch('boring-tls', tagPeer, {
        note: 'не TLS → tls-mux handler (VPN/TUN через boring-tls на client)',
      });
    } else {
      const ch = parseFirstTlsClientHelloFromTcpBuf(merged);
      const wireSni =
        'ok' in ch && ch.ok && ch.sni?.length ? ch.sni.join(',') : null;
      logComboTlsExitBranch('boring-tls', tagPeer, {
        wireSni,
        note: 'TLS ClientHello без enc-SNI → tls-mux (VPN/TUN через boring-tls на client)',
      });
    }
    handleTlsExitInbound(sock, tlsCtx);
    if (merged.length) process.nextTick(() => sock.emit('data', merged));
  }

  sock.on('data', onData);
  sock.once('error', onPeekErrOrClose);
  sock.once('close', onPeekErrOrClose);
}

/**
 * iptables nat OUTPUT: tcp/443 перенаправляется на localPort для transparent-tls (SO_ORIGINAL_DST).
 * nftables-бэкенд (iptables 1.8.x) не допускает несколько «-d» в одном правиле → отдельная цепочка.
 * Откатывается возвращаемым вызовом.
 */
function installOutputRedirectHttpsToLocalIpv4(localPort, opts = {}) {
  const commentMarker = String(opts.commentMarker ?? TRANSPARENT_TLS_IPT_COMMENT).slice(0, 200);
  const ex = opts.vpnServerIpv4Exclude;
  const chain = `CVPN-TTL-${process.pid}`;
  const jumpComment = `${commentMarker}-jmp`;

  const run = (/** @type {string[]} */ args) => execFileSync('iptables', args, { stdio: 'inherit' });

  try {
    run(['-t', 'nat', '-N', chain]);
  } catch {
    run(['-t', 'nat', '-F', chain]);
  }

  for (const cidr of ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
    run(['-t', 'nat', '-A', chain, '-d', cidr, '-j', 'RETURN']);
  }
  if (ex && net.isIPv4(ex)) {
    run(['-t', 'nat', '-A', chain, '-d', `${ex}/32`, '-j', 'RETURN']);
  }
  run([
    '-t',
    'nat',
    '-A',
    chain,
    '-p',
    'tcp',
    '--dport',
    '443',
    '-m',
    'comment',
    '--comment',
    `${commentMarker}-redir`,
    '-j',
    'REDIRECT',
    '--to-ports',
    String(localPort),
  ]);

  const jumpRule = [
    '-t',
    'nat',
    '-A',
    'OUTPUT',
    '-p',
    'tcp',
    '--dport',
    '443',
    '-m',
    'comment',
    '--comment',
    jumpComment,
    '-j',
    chain,
  ];
  run(jumpRule);

  const jumpDelete = /** @type {string[]} */ (['-t', 'nat', '-D', 'OUTPUT', ...jumpRule.slice(4)]);

  return () => {
    safe(() => run(jumpDelete));
    safe(() => run(['-t', 'nat', '-F', chain]));
    safe(() => run(['-t', 'nat', '-X', chain]));
  };
}

/**
 * nat PREROUTING + DNAT (не REDIRECT→127): tcp/443 с LAN → LAN-IP шлюза:interceptPort — стабильный reply-path
 * к клиентам за шлюзом; SO_ORIGINAL_DST по-прежнему даёт апстрим.
 */
function installPreroutingDnatForwardedHttpsLanToGatewayIpv4(sourceCidr, gatewayIpv4, interceptPort, opts = {}) {
  if (!net.isIPv4(gatewayIpv4)) {
    throw new Error('[clean-vpn] transparent-tls DNAT LAN: нужен ipv4 адрес шлюза в LAN');
  }
  const commentMarker = String(opts.commentMarker ?? TRANSPARENT_TLS_IPT_COMMENT).slice(0, 200);
  const ex = opts.vpnServerIpv4Exclude;
  const chain = `CVPN-TTL-FWD-${process.pid}`;
  const jumpComment = `${commentMarker}-prejmp`;

  const run = (/** @type {string[]} */ args) => execFileSync('iptables', args, { stdio: 'inherit' });

  try {
    run(['-t', 'nat', '-N', chain]);
  } catch {
    run(['-t', 'nat', '-F', chain]);
  }

  for (const cidr of ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) {
    run(['-t', 'nat', '-A', chain, '-d', cidr, '-j', 'RETURN']);
  }
  if (ex && net.isIPv4(ex)) {
    run(['-t', 'nat', '-A', chain, '-d', `${ex}/32`, '-j', 'RETURN']);
  }
  run([
    '-t',
    'nat',
    '-A',
    chain,
    '-p',
    'tcp',
    '--dport',
    '443',
    '-m',
    'comment',
    '--comment',
    `${commentMarker}-prednat`,
    '-j',
    'DNAT',
    '--to-destination',
    `${gatewayIpv4}:${interceptPort}`,
  ]);

  const jumpRule = [
    '-t',
    'nat',
    '-A',
    'PREROUTING',
    '-s',
    String(sourceCidr),
    '-p',
    'tcp',
    '--dport',
    '443',
    '-m',
    'comment',
    '--comment',
    jumpComment,
    '-j',
    chain,
  ];
  run(jumpRule);

  const jumpDelete = /** @type {string[]} */ (['-t', 'nat', '-D', 'PREROUTING', ...jumpRule.slice(4)]);

  return () => {
    safe(() => run(jumpDelete));
    safe(() => run(['-t', 'nat', '-F', chain]));
    safe(() => run(['-t', 'nat', '-X', chain]));
  };
}

/**
 * filter INPUT: accept для transparent-tls (127 после OUTPUT DNAT и LAN-трафика на GW:port после PREROUTING DNAT).
 */
function installFilterInputAcceptTransparentTlsInterceptIpv4(localPort, opts = {}) {
  const commentMarker = String(opts.commentMarker ?? TRANSPARENT_TLS_IPT_COMMENT).slice(0, 180);
  const run = (/** @type {string[]} */ args) => execFileSync('iptables', args, { stdio: 'inherit' });
  /** @type {(() => void)[]} */
  const undos = [];

  /** @param {string[]} afterProto условие после `-p tcp` */
  const addAccept = (afterProto, suffix) => {
    const rule = [
      '-t',
      'filter',
      '-I',
      'INPUT',
      '1',
      '-p',
      'tcp',
      ...afterProto,
      '-m',
      'comment',
      '--comment',
      `${commentMarker}-in-${suffix}`,
      '-j',
      'ACCEPT',
    ];
    run(rule);
    const delSpec = rule.slice(5); // от -p tcp … до ACCEPT (для -D без -I позиции)
    undos.unshift(() => safe(() => run(['-t', 'filter', '-D', 'INPUT', ...delSpec])));
  };

  addAccept(['-d', '127.0.0.1', '--dport', String(localPort)], 'loop');

  const gw = opts.lanGatewayIpv4;
  const lan = opts.lanSourceCidr;
  if (gw && lan && net.isIPv4(gw)) {
    addAccept(['-s', String(lan), '-d', gw, '--dport', String(localPort)], 'lan');
  }

  return () => {
    for (const u of undos) u();
    undos.length = 0;
  };
}

/**
 * Вызов iproute2: при sudo/cron/unit PATH без /sbin программа может отсутствовать как «ip».
 * Перебираем типичные пути, затем полагаемся на PATH.
 */
function execIpFileSync(args, execOpts = {}) {
  const candidates = ['/sbin/ip', '/usr/sbin/ip', 'ip'];
  let lastEnoent = null;
  for (const file of candidates) {
    try {
      return execFileSync(file, args, execOpts);
    } catch (e) {
      if (typeof e === 'object' && e && /** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT') {
        lastEnoent = e;
        continue;
      }
      throw e;
    }
  }
  if (lastEnoent) throw lastEnoent;
  throw new Error('execIpFileSync failed');
}

function getDefaultRouteLinux() {
  try {
    const out = execIpFileSync(['-4', 'route', 'show', 'default'], { encoding: 'utf8' });
    const line = out.trim().split('\n')[0] || '';
    const via = line.match(/default via (\S+)/);
    const dev = line.match(/dev (\S+)/);
    if (via && dev) return { gw: via[1], dev: dev[1] };
    if (dev) return { gw: null, dev: dev[1] };
  } catch {
    /* ignore */
  }
  return null;
}

/** IPv4 src для исходящего uplink (STUN/UDP punch bind). */
function resolveUplinkBindIpv4() {
  try {
    const out = execIpFileSync(['-4', 'route', 'get', '8.8.8.8'], { encoding: 'utf8' });
    const m = out.match(/\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

function getSysctlNum(key) {
  try {
    const v = execFileSync('sysctl', ['-n', key], { encoding: 'utf8' }).trim();
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? null : n;
  } catch {
    return null;
  }
}

/** Записи table main с данным dst (как в `ip -json route list`). */
function captureRoutesByDst(dst) {
  try {
    const out = execIpFileSync(['-4', '-json', 'route', 'list', 'table', 'main'], {
      encoding: 'utf8',
    });
    const arr = JSON.parse(out);
    return arr.filter((r) => r.dst === dst);
  } catch {
    return [];
  }
}

function captureServerRoutes(serverIp) {
  const a = captureRoutesByDst(`${serverIp}/32`);
  if (a.length) return a;
  return captureRoutesByDst(serverIp);
}

function ipRouteAddFromRecord(r) {
  if (!r?.dst) return;
  const args = ['route', 'add', r.dst];
  if (r.gateway) args.push('via', r.gateway);
  if (r.prefsrc) args.push('src', r.prefsrc);
  if (r.dev) args.push('dev', r.dev);
  if (typeof r.metric === 'number') args.push('metric', String(r.metric));
  if (r.scope && r.scope !== 'global') args.push('scope', r.scope);
  execIpFileSync(args, { stdio: 'inherit' });
}

function restoreRoutesFromRecords(records) {
  for (const r of records) {
    try {
      ipRouteAddFromRecord(r);
    } catch {
      /* ignore */
    }
  }
}

function tryIpRoute(args) {
  try {
    execIpFileSync(args, { stdio: 'inherit' });
  } catch {
    /* ignore */
  }
}

// =============================================================================
// === tun (продолжение): имя интерфейса, native addon, ip addr, sysctl, NAT ===
// =============================================================================

function findFreeTunName() {
  try {
    const out = execIpFileSync(['link', 'show'], { encoding: 'utf8' });
    const used = new Set();
    for (const m of out.matchAll(/tun(\d+):/g)) used.add(parseInt(m[1], 10));
    let i = 0;
    while (used.has(i)) i += 1;
    return `tun${i}`;
  } catch {
    return 'tun0';
  }
}

/** Таймаут graceful FIN при keep-alive idle (TCP server → end()). Env: CLEAN_VPN_TCP_GRACEFUL_CLOSE_MS. */
const TCP_GRACEFUL_CLOSE_MS_DEFAULT = 5000;

/**
 * @param {import('net').Socket|null|undefined} sock
 * @param {number} [timeoutMs]
 * @returns {Promise<void>}
 */
function gracefulCloseTcpEndpoint(sock, timeoutMs = parsePositiveEnvInt(
  'CLEAN_VPN_TCP_GRACEFUL_CLOSE_MS',
  TCP_GRACEFUL_CLOSE_MS_DEFAULT,
)) {
  return new Promise((resolve) => {
    if (!sock || sock.destroyed) {
      resolve();
      return;
    }
    // socket-like поверх JSStream/h2/quic (boring-tls, combo-tls на client, QUIC):
    // честный FIN недоступен и .end() ассертит — рвём через destroy().
    if (sock.__cleanVpnGracefulFinUnsafe) {
      resetTcpEndpoint(sock);
      resolve();
      return;
    }
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    const timer = setTimeout(() => {
      resetTcpEndpoint(sock);
      finish();
    }, timeoutMs);
    timer.unref?.();
    sock.once('close', () => {
      clearTimeout(timer);
      finish();
    });
    try {
      if (!sock.writableEnded) sock.end();
      else resetTcpEndpoint(sock);
    } catch {
      resetTcpEndpoint(sock);
      clearTimeout(timer);
      finish();
    }
  });
}

/** @param {import('net').Socket|null|undefined} sock */
function respondFinTcpEndpoint(sock) {
  if (!sock || sock.destroyed) return;
  // Для socket-like без реального FIN (boring-tls/combo/QUIC поверх JSStream/h2) .end()
  // приводит к ERR_INTERNAL_ASSERTION — закрываем destroy() вместо FIN.
  if (sock.__cleanVpnGracefulFinUnsafe) {
    resetTcpEndpoint(sock);
    return;
  }
  try {
    if (!sock.writableEnded) sock.end();
  } catch {
    resetTcpEndpoint(sock);
  }
}

/** RST (`destroy`) — нештатное закрытие, перезапуск пира, write/read после разрыва. */
function resetTcpEndpoint(sock) {
  if (!sock || sock.destroyed) return;
  try {
    sock.destroy();
  } catch {
    /* ignore */
  }
}

/** @param {unknown} err */
function isTcpWireResetError(err) {
  const code = err && typeof err === 'object' && 'code' in err ? String(/** @type {{code?: string}} */ (err).code) : '';
  return Boolean(code && TCP_BENIGN_AFTER_DATA_CODES.has(code));
}

// =============================================================================
// === Общее: uint32+IPv4 фрейминг, writeFramed, attachTunBridge (все transport) ===
// =============================================================================

/** Слить очередь chunk-буферов в один при большом числе осколков (меньше overhead очереди). */
const STREAM_FRAMER_CHUNK_MERGE_AFTER = 24;

class StreamFramer {
  constructor() {
    /** @type {Buffer[]} */
    this.chunks = [];
    /** @type {number} */
    this.len = 0;
  }

  /**
   * @param {Buffer} chunk
   * @param {(pkt: Buffer) => void} onPacket — срез внутреннего буфера; не мутировать после колбэка.
   */
  push(chunk, onPacket) {
    if (chunk.length) {
      // Нельзя хранить ссылку на `chunk` из socket 'data': Node переиспользует slab.
      this.chunks.push(Buffer.from(chunk));
      this.len += chunk.length;
    }
    for (;;) {
      if (this.len < 4) break;
      const packedLen = this.#peekUInt32BE();
      if (packedLen == null) break;
      if (packedLen <= 0 || packedLen > MAX_PKT) {
        this.chunks = [];
        this.len = 0;
        throw new Error(`bad frame length ${packedLen}`);
      }
      const frameLen = 4 + packedLen;
      if (this.len < frameLen) break;
      const frame = this.#consume(frameLen);
      const pkt = frame.subarray(4);
      onPacket(pkt);
    }
    this.#mergeChunksIfNeeded();
  }

  /** @returns {number|null} */
  #peekUInt32BE() {
    if (this.len < 4) return null;
    const c0 = this.chunks[0];
    if (!c0) return null;
    if (c0.length >= 4) return c0.readUInt32BE(0);
    const tmp = Buffer.allocUnsafe(4);
    let copied = 0;
    for (let i = 0; i < this.chunks.length && copied < 4; i++) {
      const c = this.chunks[i];
      const need = 4 - copied;
      if (c.length >= need) {
        c.copy(tmp, copied, 0, need);
        copied = 4;
        break;
      }
      c.copy(tmp, copied);
      copied += c.length;
    }
    return copied >= 4 ? tmp.readUInt32BE(0) : null;
  }

  /** @param {number} n */
  #consume(n) {
    const out = Buffer.allocUnsafe(n);
    let off = 0;
    while (off < n) {
      const first = /** @type {Buffer} */ (this.chunks[0]);
      const avail = first.length;
      const need = n - off;
      if (avail <= need) {
        first.copy(out, off);
        off += avail;
        this.len -= avail;
        this.chunks.shift();
      } else {
        first.copy(out, off, 0, need);
        this.chunks[0] = first.subarray(need);
        this.len -= need;
        off = n;
      }
    }
    return out;
  }

  #mergeChunksIfNeeded() {
    if (this.chunks.length < STREAM_FRAMER_CHUNK_MERGE_AFTER || this.len === 0) return;
    const merged = Buffer.allocUnsafe(this.len);
    let o = 0;
    for (const c of this.chunks) {
      c.copy(merged, o);
      o += c.length;
    }
    this.chunks = [merged];
  }
}

/** Uint32 BE длина + IPv4-пакет (отдельный буфер на кадр). */
function encodeCleanVpnFramedPkt(pkt) {
  const len = pkt.length;
  const buf = Buffer.allocUnsafe(4 + len);
  buf.writeUInt32BE(len, 0);
  if (len) pkt.copy(buf, 4);
  return buf;
}

/**
 * TCP-транспорт с опциональным батчем нескольких кадров в одном write (совместимо с StreamFramer).
 * Env: `CLEAN_VPN_FRAME_BATCH_BYTES` (=0 выкл), `CLEAN_VPN_FRAME_BATCH_FLUSH_MS`.
 *
 * @param {NodeJS.WritableStream & { write: (...args: any[]) => boolean }} endpoint
 * @param {(err: Error) => void} [onWriteError]
 * @returns {(pkt: Buffer) => void}
 */
function createTcpFramedBatchedWriter(endpoint, onWriteError) {
  const maxBatch = parseNonNegativeEnvInt('CLEAN_VPN_FRAME_BATCH_BYTES', 0);
  const flushMs = parseNonNegativeEnvInt('CLEAN_VPN_FRAME_BATCH_FLUSH_MS', 1);
  if (maxBatch <= 0) {
    return (pkt) => {
      try {
        endpoint.write(encodeCleanVpnFramedPkt(pkt), (err) => {
          if (err && onWriteError) onWriteError(err);
        });
      } catch (e) {
        if (onWriteError) onWriteError(/** @type {Error} */ (e));
      }
    };
  }

  /** @type {Buffer[]} */
  let batch = [];
  let batchLen = 0;
  /** @type {ReturnType<typeof setTimeout>|null} */
  let flushTimer = null;
  let flushDeferred = false;

  const flush = () => {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    flushDeferred = false;
    if (!batchLen) return;
    const payload = batch.length === 1 ? batch[0] : Buffer.concat(batch, batchLen);
    batch = [];
    batchLen = 0;
    try {
      endpoint.write(payload, (err) => {
        if (err && onWriteError) onWriteError(err);
      });
    } catch (e) {
      if (onWriteError) onWriteError(/** @type {Error} */ (e));
    }
  };

  const scheduleFlush = () => {
    if (batchLen === 0) return;
    if (flushMs <= 0) {
      if (flushDeferred) return;
      flushDeferred = true;
      setImmediate(() => flush());
      return;
    }
    if (flushTimer) return;
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flush();
    }, flushMs);
    flushTimer.unref?.();
  };

  return (pkt) => {
    const piece = encodeCleanVpnFramedPkt(pkt);
    batch.push(piece);
    batchLen += piece.length;
    if (batchLen >= maxBatch) {
      flush();
    } else {
      scheduleFlush();
    }
  };
}

function writeFramed(sock, pkt) {
  return sock.write(encodeCleanVpnFramedPkt(pkt));
}

function ip(args) {
  execIpFileSync(args, { stdio: 'inherit' });
}

function sysctlForward(on) {
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${on ? 1 : 0}`], { stdio: 'inherit' });
  } catch {
    console.warn('[clean-vpn] sysctl ip_forward не применён');
  }
}

/**
 * IPv4 CIDR для iptables (`192.168.7.0/24`).
 * @param {string} raw
 * @returns {string}
 */
function parseIpv4CidrStrict(raw) {
  const s = String(raw).trim();
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) {
    throw new Error(`Неверный IPv4 CIDR: «${raw}», ожидается вида 192.168.7.0/24`);
  }
  const o = [m[1], m[2], m[3], m[4]].map((x) => Number.parseInt(x, 10));
  for (const x of o) {
    if (!Number.isFinite(x) || x < 0 || x > 255) {
      throw new Error(`Неверный IPv4 CIDR: октет вне 0..255 в «${raw}»`);
    }
  }
  const prefix = Number.parseInt(m[5], 10);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Неверная маска /prefix в «${raw}» (ожидается 0..32)`);
  }
  const addrNum = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  if (prefix > 0 && prefix < 32) {
    const mask = (-1 << (32 - prefix)) >>> 0;
    // `&` даёт signed Int32; для адресов ≥128.0.0.0 без >>> 0 сравнение с addrNum ломается.
    const net = (addrNum & mask) >>> 0;
    if (addrNum !== net) {
      throw new Error(
        `CIDR «${raw}»: укажите адрес сети под маской /${prefix} (часто 192.168.7.0/24 для gadget), не адрес хоста в середине префикса`,
      );
    }
  }
  return `${o.join('.')}/${prefix}`;
}

/** @returns {number} */
function ipv4StringToUint32(ip) {
  const m = String(ip).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return NaN;
  const o = [m[1], m[2], m[3], m[4]].map((x) => Number.parseInt(x, 10));
  if (o.some((x) => !Number.isFinite(x) || x < 0 || x > 255)) return NaN;
  return (((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0) >>> 0;
}

/** @param {number} host @param {string} normalizedCidr уже нормализованный вида net/pref */
function ipv4HostContainedInNormalizedCidr(host, normalizedCidr) {
  const p = normalizedCidr.indexOf('/');
  if (p < 0) return false;
  const baseNum = ipv4StringToUint32(normalizedCidr.slice(0, p));
  const pref = Number.parseInt(normalizedCidr.slice(p + 1), 10);
  if (!Number.isFinite(baseNum) || !Number.isFinite(pref) || pref < 0 || pref > 32) return false;
  if (pref === 0) return true;
  const mask = (-1 << (32 - pref)) >>> 0;
  // Обе стороны через >>> 0: `&` даёт signed Int32, иначе 192.168.x.x всегда «вне» сети.
  return ((host & mask) >>> 0) === ((baseNum & mask) >>> 0);
}

/**
 * Локальный IPv4 шлюза в подсети --client-lan-subnet (для DNAT вместо 127.0.0.1).
 * Пропускаем lo и типичный tun*.
 * Альтернатива `ip -json`: BusyBox/старый ip без -json или JSON с другими именами полей → fallback через `ip -o -4 addr`.
 */
function detectIpv4LanGatewayOwnAddress(normalizedLanCidr) {
  const consider = /** @type {(iface: string, ip: string) => string|null} */ (iface, ip) => {
    if (!iface || iface === 'lo') return null;
    if (/^tun/i.test(iface)) return null;
    const t = ip.trim();
    if (!net.isIPv4(t)) return null;
    const u = ipv4StringToUint32(t);
    if (Number.isFinite(u) && ipv4HostContainedInNormalizedCidr(u, normalizedLanCidr)) return t;
    return null;
  };

  try {
    const out = execIpFileSync(['-json', 'addr'], { encoding: 'utf8', maxBuffer: 2 ** 20 });
    const arr = JSON.parse(out);
    for (const ent of arr) {
      const ifn = String(ent.ifname ?? ent.if ?? '');
      for (const ai of ent.addr_info ?? []) {
        const fam = String(ai.family ?? '').toLowerCase();
        if (fam !== 'inet') continue;
        const lip = ai.local ?? ai.address;
        const lipStr = typeof lip === 'string' ? lip : null;
        if (!lipStr) continue;
        const hit = consider(ifn, lipStr);
        if (hit) return hit;
      }
    }
  } catch {
    /* -json недоступен или формат другой — ниже текстовый ip -o */
  }

  /** Одна строка на адрес: `2: usb0 inet 192.168.7.1/24 ...` (GNU iproute2/BusyBox чаще совместимо). */
  try {
    const out = execIpFileSync(['-o', '-4', 'addr', 'show'], {
      encoding: 'utf8',
      maxBuffer: 2 ** 20,
    });
    for (const line of out.split(/\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const mStd = trimmed.match(/^\d+:\s+(\S+)\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})\//);
      if (!mStd) continue;
      const hit = consider(mStd[1], mStd[2]);
      if (hit) return hit;
    }
  } catch {
    /* ignore */
  }

  return null;
}

/**
 * SNAT LAN → адрес туннеля + FORWARD + ip_forward (USB gadget / AP за клиентом).
 * @param {{ ifname: string }} routeCtx
 * @param {string} cidr
 */
function setupClientLanGateway(routeCtx, cidr) {
  const normalized = parseIpv4CidrStrict(cidr);
  const tunIf = routeCtx.ifname;
  const prevIpForward = getSysctlNum('net.ipv4.ip_forward');
  sysctlForward(true);
  try {
    execFileSync(
      'iptables',
      [
        '-t',
        'nat',
        '-A',
        'POSTROUTING',
        '-s',
        normalized,
        '-o',
        tunIf,
        '-j',
        'SNAT',
        '--to-source',
        IP_CLIENT,
      ],
      { stdio: 'inherit' },
    );
    execFileSync(
      'iptables',
      ['-A', 'FORWARD', '-s', normalized, '-o', tunIf, '-j', 'ACCEPT'],
      { stdio: 'inherit' },
    );
    execFileSync(
      'iptables',
      [
        '-A',
        'FORWARD',
        '-d',
        normalized,
        '-i',
        tunIf,
        '-m',
        'conntrack',
        '--ctstate',
        'RELATED,ESTABLISHED',
        '-j',
        'ACCEPT',
      ],
      { stdio: 'inherit' },
    );
  } catch (e) {
    try {
      execFileSync('iptables', [
        '-t',
        'nat',
        '-D',
        'POSTROUTING',
        '-s',
        normalized,
        '-o',
        tunIf,
        '-j',
        'SNAT',
        '--to-source',
        IP_CLIENT,
      ]);
    } catch {
      /* ignore */
    }
    try {
      execFileSync('iptables', ['-D', 'FORWARD', '-s', normalized, '-o', tunIf, '-j', 'ACCEPT']);
    } catch {
      /* ignore */
    }
    try {
      execFileSync('iptables', [
        '-D',
        'FORWARD',
        '-d',
        normalized,
        '-i',
        tunIf,
        '-m',
        'conntrack',
        '--ctstate',
        'RELATED,ESTABLISHED',
        '-j',
        'ACCEPT',
      ]);
    } catch {
      /* ignore */
    }
    try {
      if (prevIpForward != null) {
        execFileSync('sysctl', [`net.ipv4.ip_forward=${prevIpForward}`], { stdio: 'inherit' });
      }
    } catch {
      /* ignore */
    }
    throw e;
  }
  routeCtx.clientLanGateway = { cidr: normalized, tunIf, prevIpForward };
  console.log(
    `[clean-vpn] client LAN gateway: ip_forward=1; SNAT ${normalized} → ${IP_CLIENT} out ${tunIf}; FORWARD разрешён`,
  );
}

/**
 * @param {unknown} routeCtx
 */
function teardownClientLanGateway(routeCtx) {
  const g = routeCtx && /** @type {{ clientLanGateway?: object }} */ (routeCtx).clientLanGateway;
  if (!g || typeof g !== 'object') return;
  const { cidr, tunIf, prevIpForward } = /** @type {{ cidr: string, tunIf: string, prevIpForward: number|null }} */ (
    g
  );
  delete /** @type {{ clientLanGateway?: object }} */ (routeCtx).clientLanGateway;
  try {
    execFileSync('iptables', [
      '-t',
      'nat',
      '-D',
      'POSTROUTING',
      '-s',
      cidr,
      '-o',
      tunIf,
      '-j',
      'SNAT',
      '--to-source',
      IP_CLIENT,
    ]);
  } catch {
    /* ignore */
  }
  try {
    execFileSync('iptables', ['-D', 'FORWARD', '-s', cidr, '-o', tunIf, '-j', 'ACCEPT']);
  } catch {
    /* ignore */
  }
  try {
    execFileSync('iptables', [
      '-D',
      'FORWARD',
      '-d',
      cidr,
      '-i',
      tunIf,
      '-m',
      'conntrack',
      '--ctstate',
      'RELATED,ESTABLISHED',
      '-j',
      'ACCEPT',
    ]);
  } catch {
    /* ignore */
  }
  if (prevIpForward != null) {
    try {
      execFileSync('sysctl', [`net.ipv4.ip_forward=${prevIpForward}`], { stdio: 'inherit' });
    } catch {
      /* ignore */
    }
  }
  console.log('[clean-vpn] client LAN gateway: iptables/sysctl восстановлены');
}

function setupTunIp(role, ifname) {
  if (role === 'exit') {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_EXIT}/32`, 'peer', `${IP_CLIENT}/32`, 'dev', ifname]);
  } else {
    ip(['addr', 'flush', 'dev', ifname]);
    ip(['addr', 'add', `${IP_CLIENT}/32`, 'peer', `${IP_EXIT}/32`, 'dev', ifname]);
  }
  ip(['link', 'set', 'dev', ifname, 'mtu', String(TUN_MTU), 'up']);
}

/**
 * IPv4 пира TCP сокета (для WebSocket-сервера на client: 0.0.0.0 + bypass после accept).
 * @param {string|undefined} remoteAddress
 */
function normalizePeerIpv4(remoteAddress) {
  if (!remoteAddress || typeof remoteAddress !== 'string') {
    throw new Error('clean-vpn: нет remoteAddress у сокета WebSocket');
  }
  let a = remoteAddress;
  if (a.startsWith('::ffff:')) a = a.slice(7);
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(a)) {
    throw new Error(
      `clean-vpn: ожидался IPv4-пир WS (NAT), получено: ${remoteAddress}`,
    );
  }
  return a;
}

/**
 * @param {{ serverIp: string|null, gw: string|null, dev: string, snapPeer?: unknown[] }} ctx
 * @param {string} peerIp
 */
function addClientWsPeerBypass(ctx, peerIp) {
  if (ctx.peerIp) {
    throw new Error('clean-vpn: bypass пира WS уже установлен');
  }
  const { gw, dev } = ctx;
  const snapPeer = captureServerRoutes(peerIp);
  console.log(
    `[clean-vpn] bypass маршрут к пиру WebSocket ${peerIp}/32 через ${dev}`,
  );
  if (gw) {
    ip(['route', 'replace', `${peerIp}/32`, 'via', gw, 'dev', dev]);
  } else {
    ip(['route', 'replace', `${peerIp}/32`, 'dev', dev]);
  }
  ctx.peerIp = peerIp;
  ctx.snapPeer = snapPeer;
}

/**
 * @param {{ gw: string|null, dev: string, splitDefault?: boolean, serverIp?: string|null, peerIp?: string|null, infraBypassIps?: string[], snapInfra?: unknown[] }} ctx
 * @param {string} infraIp
 * @param {string} [logLabel]
 * @returns {boolean}
 */
function addClientInfraBypassIp(ctx, infraIp, logLabel = 'STUN/TURN') {
  if (!ctx?.splitDefault) return false;
  if (!isIpv4InfraBypassSafe(infraIp)) return false;
  if (infraIp === ctx.serverIp || infraIp === ctx.peerIp) return false;
  if (!ctx.infraBypassIps) ctx.infraBypassIps = [];
  if (ctx.infraBypassIps.includes(infraIp)) return false;
  if (!ctx.snapInfra) ctx.snapInfra = [];
  const { gw, dev } = ctx;
  ctx.snapInfra.push(...captureServerRoutes(infraIp));
  if (gw) {
    ip(['route', 'replace', `${infraIp}/32`, 'via', gw, 'dev', dev]);
  } else {
    ip(['route', 'replace', `${infraIp}/32`, 'dev', dev]);
  }
  ctx.infraBypassIps.push(infraIp);
  console.log(
    `[clean-vpn] infra bypass ${logLabel}: ${infraIp}/32 через ${dev}` +
      (gw ? ` via ${gw}` : ''),
  );
  return true;
}

/** @param {Parameters<typeof addClientInfraBypassIp>[0]|undefined} ctx
 *  @param {string} candidate */
function maybeBypassIceCandidateIp(ctx, candidate) {
  if (!ctx?.splitDefault) return;
  const f = parseIceCandidateFields(candidate);
  if (!f?.ip) return;
  addClientInfraBypassIp(ctx, f.ip, 'ICE peer');
}

/**
 * /32 uplink bypass для STUN/TURN IP из --config (split-default иначе уводит ICE UDP в tun).
 * @param {{ gw: string|null, dev: string, splitDefault?: boolean, serverIp?: string|null, peerIp?: string|null, infraBypassApplied?: boolean, snapInfra?: unknown[], infraBypassIps?: string[] }} ctx
 * @param {string|null|undefined} configPath
 * @param {string|null|undefined} iceMode
 */
async function ensureClientInfraBypass(ctx, configPath, iceMode) {
  if (!ctx?.splitDefault) return;
  const ips = await resolveIceInfraIpv4FromConfig(configPath, iceMode);
  if (!ips.length) return;
  /** @type {string[]} */
  const applied = [];
  for (const infraIp of ips) {
    if (addClientInfraBypassIp(ctx, infraIp)) applied.push(infraIp);
  }
  if (applied.length) {
    console.log(
      `[clean-vpn] infra bypass STUN/TURN: +${applied.length} IPv4` +
        ` (${applied.slice(0, 6).join(', ')}${applied.length > 6 ? '…' : ''})`,
    );
  }
  ctx.infraBypassApplied = true;
}

/**
 * @param {string} ifname
 * @param {string} serverHost
 * @param {boolean} splitDefault
 * @param {{ deferPeerBypass?: boolean; websocketListenNoSplitDefault?: boolean; deferPeerKind?: 'ws-listen'|'webrtc'; deferSplitDefault?: boolean; configPath?: string|null; iceMode?: string|null }} [opts]
 */
async function setupClientRoutesAsync(ifname, serverHost, splitDefault, opts) {
  const deferPeerBypass = opts?.deferPeerBypass === true;
  const websocketListenNoSplitDefault = opts?.websocketListenNoSplitDefault === true;
  const deferKind = opts?.deferPeerKind === 'webrtc' ? 'webrtc' : 'ws-listen';
  const dr = getDefaultRouteLinux();
  if (!dr) throw new Error('Не найден default route (ip route show default)');
  const { gw, dev } = dr;

  /** @type {string|null} */
  let serverIp = null;
  /** @type {unknown[]} */
  let snapHost = [];
  if (!deferPeerBypass) {
    if (!websocketListenNoSplitDefault || splitDefault) {
      serverIp = await resolveHostToIpv4(serverHost);
      snapHost = captureServerRoutes(serverIp);
      console.log(`[clean-vpn] bypass маршрут к серверу ${serverIp} через ${dev}`);
      if (gw) {
        ip(['route', 'replace', `${serverIp}/32`, 'via', gw, 'dev', dev]);
      } else {
        ip(['route', 'replace', `${serverIp}/32`, 'dev', dev]);
      }
    } else {
      console.log(
        '[clean-vpn] WebSocket-сервер на client без --split-default: bypass к --tunnel-peer не настраивается (default через uplink)',
      );
    }
  } else if (splitDefault) {
    console.log(
      deferKind === 'webrtc'
        ? '[clean-vpn] WebRTC сигналинг: bypass к TCP-пиру после accept (--split-default)'
        : '[clean-vpn] WebSocket-сервер на client: bypass к TCP-пиру после accept (--split-default)',
    );
  } else {
    console.log(
      deferKind === 'webrtc'
        ? '[clean-vpn] WebRTC сигналинг без --split-default: bypass к пиру после accept не настраивается (default через uplink)'
        : '[clean-vpn] WebSocket-сервер на client без --split-default: bypass к пиру после accept не настраивается (default через uplink)',
    );
  }

  const deferSplitDefault = opts?.deferSplitDefault === true;
  const iceInfraBypass = opts?.iceInfraBypass === true;
  const prevRpAll = getSysctlNum('net.ipv4.conf.all.rp_filter');
  const snap01 = splitDefault ? [...captureRoutesByDst('0.0.0.0/1')] : [];
  const snap128 = splitDefault ? [...captureRoutesByDst('128.0.0.0/1')] : [];

  let splitDefaultApplied = false;
  if (splitDefault && !deferSplitDefault) {
    applyClientSplitDefaultRoutes(ifname, gw, dev);
    splitDefaultApplied = true;
  } else if (splitDefault && deferSplitDefault) {
    console.log(
      '[clean-vpn] split-default: отложен до готовности туннеля (STUN/сигналинг/Puppeteer — uplink остаётся рабочим)',
    );
  }
  try {
    execFileSync('sysctl', ['net.ipv4.conf.all.rp_filter=2'], { stdio: 'inherit' });
  } catch {
    /* ignore */
  }

  const routeCtx = {
    serverIp,
    peerIp: null,
    gw,
    dev,
    splitDefault,
    prevRpAll,
    snapHost,
    snapPeer: [],
    snap01,
    snap128,
    ifname,
    splitDefaultApplied,
    infraBypassApplied: false,
    snapInfra: [],
    infraBypassIps: [],
    iceConfigPath: opts?.configPath ?? null,
    iceMode: opts?.iceMode ?? null,
    iceInfraBypass,
  };

  if (splitDefault && !deferSplitDefault && iceInfraBypass) {
    await ensureClientInfraBypass(routeCtx, routeCtx.iceConfigPath, routeCtx.iceMode);
  }

  return routeCtx;
}

/** IPv4 default через TUN (split-default). */
function applyClientSplitDefaultRoutes(ifname, gw, dev) {
  ip(['route', 'replace', '0.0.0.0/1', 'dev', ifname]);
  ip(['route', 'replace', '128.0.0.0/1', 'dev', ifname]);
  addSplitPrivateUplinkRoutes(gw, dev);
  console.log('[clean-vpn] split-default (0.0.0.0/1 + 128.0.0.0/1) через', ifname);
  console.log(
    '[clean-vpn] split-default: частные сети',
    SPLIT_PRIVATE_V4.join(', '),
    '→ uplink',
    gw ? `via ${gw}` : '',
    dev,
  );
  console.warn(
    '[clean-vpn] split-default только для IPv4; IPv6 default не в туннеле. Проверка внешнего IPv4: curl -4 https://ifconfig.me',
  );
}

/** Отложенный split-default (ws-chrome / rtc-chrome / udp punch / webrtc). */
async function applyDeferredClientSplitDefault(ctx) {
  if (!ctx?.splitDefault) return;
  if (!ctx.splitDefaultApplied) {
    applyClientSplitDefaultRoutes(ctx.ifname, ctx.gw, ctx.dev);
    ctx.splitDefaultApplied = true;
  }
  if (ctx.iceInfraBypass) {
    await ensureClientInfraBypass(ctx, ctx.iceConfigPath, ctx.iceMode);
  }
}

function teardownClientRoutes(ctx) {
  if (!ctx) return;
  teardownClientLanGateway(ctx);
  const {
    serverIp,
    peerIp,
    gw,
    dev,
    splitDefault,
    prevRpAll,
    snapHost,
    snapPeer,
    snap01,
    snap128,
    ifname,
  } = ctx;

  if (splitDefault && ctx.splitDefaultApplied !== false) {
    tryIpRoute(['route', 'del', '0.0.0.0/1', 'dev', ifname]);
    tryIpRoute(['route', 'del', '128.0.0.0/1', 'dev', ifname]);
    restoreRoutesFromRecords(snap01);
    restoreRoutesFromRecords(snap128);
    delSplitPrivateUplinkRoutes(gw, dev);
  }

  if (peerIp) {
    if (gw) {
      tryIpRoute(['route', 'del', `${peerIp}/32`, 'via', gw, 'dev', dev]);
    } else {
      tryIpRoute(['route', 'del', `${peerIp}/32`, 'dev', dev]);
    }
    restoreRoutesFromRecords(snapPeer || []);
  }

  if (serverIp) {
    if (gw) {
      tryIpRoute(['route', 'del', `${serverIp}/32`, 'via', gw, 'dev', dev]);
    } else {
      tryIpRoute(['route', 'del', `${serverIp}/32`, 'dev', dev]);
    }
    restoreRoutesFromRecords(snapHost || []);
  }

  const infraBypassIps = ctx.infraBypassIps || [];
  for (const ip of infraBypassIps) {
    if (gw) {
      tryIpRoute(['route', 'del', `${ip}/32`, 'via', gw, 'dev', dev]);
    } else {
      tryIpRoute(['route', 'del', `${ip}/32`, 'dev', dev]);
    }
  }
  restoreRoutesFromRecords(ctx.snapInfra || []);

  if (prevRpAll != null) {
    try {
      execFileSync('sysctl', [`net.ipv4.conf.all.rp_filter=${prevRpAll}`], { stdio: 'inherit' });
    } catch {
      /* ignore */
    }
  }
  console.log('[clean-vpn] client: маршруты и rp_filter восстановлены');
}

function setupExitNat(tunName, extIface) {
  const prevIpForward = getSysctlNum('net.ipv4.ip_forward');
  sysctlForward(true);
  const ext = extIface || getDefaultRouteLinux()?.dev;
  if (!ext) throw new Error('Укажите --ext=eth0 или настройте default route');
  console.log(`[clean-vpn] NAT: ${tunName} -> ${ext} (MASQUERADE)`);
  execFileSync(
    'iptables',
    ['-t', 'nat', '-A', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
    { stdio: 'inherit' },
  );
  execFileSync('iptables', ['-A', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
    stdio: 'inherit',
  });
  execFileSync(
    'iptables',
    [
      '-A',
      'FORWARD',
      '-i',
      ext,
      '-o',
      tunName,
      '-m',
      'conntrack',
      '--ctstate',
      'RELATED,ESTABLISHED',
      '-j',
      'ACCEPT',
    ],
    { stdio: 'inherit' },
  );
  return { ext, tunName, prevIpForward };
}

function restoreExitSysctl(prevIpForward) {
  if (prevIpForward == null) return;
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${prevIpForward}`], { stdio: 'inherit' });
    console.log('[clean-vpn] exit: net.ipv4.ip_forward восстановлен');
  } catch {
    /* ignore */
  }
}

function teardownExitNat(tunName, ext) {
  try {
    execFileSync(
      'iptables',
      ['-t', 'nat', '-D', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
  try {
    execFileSync('iptables', ['-D', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
      stdio: 'inherit',
    });
  } catch {
    /* ignore */
  }
  try {
    execFileSync(
      'iptables',
      [
        '-D',
        'FORWARD',
        '-i',
        ext,
        '-o',
        tunName,
        '-m',
        'conntrack',
        '--ctstate',
        'RELATED,ESTABLISHED',
        '-j',
        'ACCEPT',
      ],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
}

/**
 * @param {string} s
 * @returns {Uint8Array|null} четыре октета или null
 */
function parseDottedIPv4FourOctets(s) {
  const parts = String(s).split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

/**
 * @param {Buffer} buf
 * @param {number} off
 * @param {number} len — чётность по длине как у IPv4 checksum
 */
function internetChecksum16(buf, off, len) {
  let sum = 0;
  for (let i = 0; i < len; i += 2) {
    if (i + 1 < len) {
      sum += buf.readUInt16BE(off + i);
    } else {
      sum += buf[off + i] << 8;
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

/**
 * ICMP Echo Request к нашему TUN-IPv4 → полный IPv4 Echo Reply для записи в TUN.
 * Только IHL=5, нефрагментированный первый кусок, protocol ICMP.
 *
 * @param {Buffer} pkt
 * @param {Uint8Array} localDst4 — dst запроса = наш адрес на TUN
 * @param {() => number} nextIpIdentification — 16-bit BE для нового IPv4 id
 * @returns {Buffer|null}
 */
function tryBuildTunIcmpEchoReplyForLocalIp(pkt, localDst4, nextIpIdentification) {
  if (pkt.length < 28) return null;
  if ((pkt[0] >> 4) !== 4) return null;
  const ihlWords = pkt[0] & 0x0f;
  if (ihlWords !== 5) return null;
  const totalLen = pkt.readUInt16BE(2);
  if (totalLen < 28 || totalLen > pkt.length) return null;
  const fragOff = pkt.readUInt16BE(6) & 0x1fff;
  if (fragOff !== 0) return null;
  if (pkt[9] !== 1) return null;
  if (
    pkt[16] !== localDst4[0] ||
    pkt[17] !== localDst4[1] ||
    pkt[18] !== localDst4[2] ||
    pkt[19] !== localDst4[3]
  ) {
    return null;
  }
  const icmpOff = 20;
  if (pkt[icmpOff] !== 8 || pkt[icmpOff + 1] !== 0) return null;

  const icmpTotal = totalLen - 20;
  if (icmpTotal < 8) return null;
  const icmpBody = pkt.subarray(icmpOff + 8, icmpOff + icmpTotal);
  const icmpPacket = Buffer.allocUnsafe(8 + icmpBody.length);
  icmpPacket.writeUInt8(0, 0);
  icmpPacket.writeUInt8(0, 1);
  icmpPacket.writeUInt16BE(0, 2);
  if (icmpBody.length) icmpBody.copy(icmpPacket, 8);
  icmpPacket.writeUInt16BE(internetChecksum16(icmpPacket, 0, icmpPacket.length), 2);

  const ipHeader = Buffer.allocUnsafe(20);
  ipHeader.writeUInt8(0x45, 0);
  ipHeader.writeUInt8(0, 1);
  ipHeader.writeUInt16BE(20 + icmpPacket.length, 2);
  ipHeader.writeUInt16BE(nextIpIdentification() & 0xffff, 4);
  ipHeader.writeUInt16BE(0, 6);
  ipHeader.writeUInt8(64, 8);
  ipHeader.writeUInt8(1, 9);
  ipHeader.writeUInt16BE(0, 10);
  pkt.copy(ipHeader, 12, 16, 20);
  pkt.copy(ipHeader, 16, 12, 16);
  ipHeader.writeUInt16BE(internetChecksum16(ipHeader, 0, 20), 10);

  return Buffer.concat([ipHeader, icmpPacket]);
}

/**
 * Кадр с TUN — валидный IPv4 для моста (не IPv6/мусор): версия 4, IHL ≥ 5, total length согласован с буфером.
 * @param {Buffer} pkt
 */
function isIpv4Bridgeable(pkt) {
  if (!pkt || pkt.length < 20) return false;
  if ((pkt[0] >> 4) !== 4) return false;
  const ihlWords = pkt[0] & 0x0f;
  if (ihlWords < 5) return false;
  const hdrBytes = ihlWords * 4;
  if (pkt.length < hdrBytes) return false;
  const totalLen = pkt.readUInt16BE(2);
  if (totalLen < hdrBytes || totalLen > pkt.length || totalLen > MAX_PKT) return false;
  return true;
}

/** rtc-chrome + keep-alive после idle: reconnect только на новый TCP SYN (не ACK). */
function ipv4TcpSynOnly(pkt) {
  if (!isIpv4Bridgeable(pkt)) return false;
  if (pkt.readUInt8(9) !== 6) return false;
  const ihl = (pkt.readUInt8(0) & 0x0f) * 4;
  if (pkt.length < ihl + 14) return false;
  const fl = pkt.readUInt8(ihl + 13);
  return (fl & 0x02) !== 0 && (fl & 0x10) === 0;
}

/** Исходящий DNS-запрос (UDP → :53) — нужен до TCP SYN при split-default. */
function ipv4DnsQuery(pkt) {
  if (!isIpv4Bridgeable(pkt)) return false;
  if (pkt.readUInt8(9) !== 17) return false;
  const ihl = (pkt.readUInt8(0) & 0x0f) * 4;
  if (pkt.length < ihl + 4) return false;
  return pkt.readUInt16BE(ihl + 2) === 53;
}

/** Lazy connect к exit после idle: TCP SYN или DNS-запрос (curl без ping). */
function ipv4TriggersExitLazyConnect(pkt) {
  return ipv4TcpSynOnly(pkt) || ipv4DnsQuery(pkt);
}

/**
 * Мост TUN↔транспорт без keep-alive / lazy (как раньше).
 *
 * @param {{ write: (b: Buffer) => void, startRead: (cb: (batch: ArrayBuffer[]) => void) => void }} tun — native addon
 * @param {'tcp'|'websocket'|'udp-client'|'udp-server'|'webrtc-dc'} transport
 * @param {import('net').Socket|import('ws')|import('dgram').Socket|{sock: import('dgram').Socket, peer?: import('dgram').RemoteInfo}|import('node-datachannel').DataChannel} endpoint
 * @param {{ localTunIp?: string }} [bridgeOpts]
 */
function attachTunBridgeNoKeepalive(tun, transport, endpoint, bridgeOpts) {
  const framer = new StreamFramer();
  const local4 = bridgeOpts?.localTunIp
    ? parseDottedIPv4FourOctets(bridgeOpts.localTunIp)
    : null;
  let ipIdCounter = randomBytes(2).readUInt16BE(0);
  const nextIpId = () => {
    ipIdCounter = (ipIdCounter + 1) & 0xffff;
    return ipIdCounter;
  };
  let icmpEchoReplyLogged = false;

  const writeTun = (pkt) => {
    try {
      tun.write(pkt);
    } catch (e) {
      console.error('[clean-vpn] tun write:', e?.message || e);
    }
  };

  /** @type {Buffer[]} */
  const dcQueue = [];
  let dcHead = 0;
  const DC_QUEUE_COMPACT_AFTER = 2048;
  const DC_BUFFER_HIGH = 8 * 1024 * 1024;
  let dcPumpScheduled = false;
  const pumpDcQueue = () => {
    dcPumpScheduled = false;
    if (transport !== 'webrtc-dc') return;
    while (dcHead < dcQueue.length) {
      if (typeof endpoint.isOpen === 'function' && !endpoint.isOpen()) return;
      let buffered = 0;
      try {
        buffered =
          typeof endpoint.bufferedAmount === 'function' ? endpoint.bufferedAmount() : 0;
      } catch {
        buffered = 0;
      }
      if (buffered > DC_BUFFER_HIGH) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
        return;
      }
      const pkt = dcQueue[dcHead++];
      if (!pkt) break;
      try {
        endpoint.sendMessageBinary(pkt);
      } catch (e) {
        console.error('[clean-vpn] webrtc-dc send:', e?.message || e);
      }
    }
    if (
      dcHead >= DC_QUEUE_COMPACT_AFTER &&
      dcHead > (dcQueue.length >> 1)
    ) {
      dcQueue.splice(0, dcHead);
      dcHead = 0;
    }
  };

  const sendTcpFramed = createTcpFramedBatchedWriter(endpoint);

  const sendOnWire = (pkt) => {
    if (transport === 'websocket') {
      endpoint.send(pkt);
    } else if (transport === 'tcp') {
      sendTcpFramed(pkt);
    } else if (transport === 'udp-client') {
      if (pkt.length > 65507) {
        console.warn('[clean-vpn] udp: пакет больше типичного MTU датаграммы');
      }
      endpoint.send(pkt, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
    } else if (transport === 'udp-server') {
      const pr = endpoint.peer;
      if (!pr) return;
      if (pkt.length > 65507) return;
      endpoint.sock.send(pkt, pr.port, pr.address, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
    } else if (transport === 'webrtc-dc') {
      dcQueue.push(pkt);
      if (!dcPumpScheduled) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
      }
    }
  };

  if (transport === 'websocket') {
    endpoint.on('message', (data, isBinary) => {
      if (!isBinary) return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      writeTun(buf);
    });
  } else if (transport === 'tcp') {
    endpoint.on('data', (chunk) => {
      try {
        framer.push(chunk, writeTun);
      } catch (e) {
        console.error('[clean-vpn] framing error:', e.message);
        endpoint.destroy();
      }
    });
  } else if (transport === 'udp-client') {
    endpoint.on('message', (msg) => {
      if (!msg.length || msg.length > MAX_PKT) return;
      writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
    });
  } else if (transport === 'udp-server') {
    endpoint.sock.on('message', (msg, rinfo) => {
      if (!msg.length || msg.length > MAX_PKT) return;
      bindOrMigrateUdpServerPeer(endpoint, rinfo);
      writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
    });
  } else if (transport === 'webrtc-dc') {
    endpoint.onMessage((data) => {
      if (typeof data === 'string') return;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (!buf.length || buf.length > MAX_PKT) return;
      writeTun(buf);
    });
  }

  tun.startRead((batch) => {
    const pkts = Array.isArray(batch) ? batch : [batch];
    for (const raw of pkts) {
      const pkt = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (!pkt.length || pkt.length > MAX_PKT) continue;
      if (local4) {
        const reply = tryBuildTunIcmpEchoReplyForLocalIp(pkt, local4, nextIpId);
        if (reply) {
          writeTun(reply);
          if (!icmpEchoReplyLogged) {
            icmpEchoReplyLogged = true;
            console.log(
              `[clean-vpn] ICMP echo reply на TUN (${bridgeOpts?.localTunIp}); дальнейшие ответы без лога`,
            );
          }
          continue;
        }
      }
      if (!isIpv4Bridgeable(pkt)) {
        if (process.env.CLEAN_VPN_KEEPALIVE_DEBUG === '1') {
          const v = pkt[0] >> 4;
          const hex = pkt.subarray(0, Math.min(8, pkt.length)).toString('hex');
          console.log(
            `[clean-vpn] keep-alive [${transport}]: drop-nonv4 verNibble=${v} head=${hex} len=${pkt.length}`,
          );
        }
        continue;
      }
      sendOnWire(pkt);
    }
  });
}

/**
 * Один активный мост на TUN: иначе второй TCP-клиент на exit вешает второй
 * listener и пакеты дублируются / рассинхрон.
 *
 * @param {{ write: (b: Buffer) => void, startRead: (cb: (batch: ArrayBuffer[]) => void) => void }} tun
 * @param {'tcp'|'websocket'|'udp-client'|'udp-server'|'webrtc-dc'} transport
 * @param {import('net').Socket|import('ws')|import('dgram').Socket|{sock: import('dgram').Socket, peer?: import('dgram').RemoteInfo}|import('node-datachannel').DataChannel|null} endpoint — null только с lazyConnect
 * @param {{
 *   localTunIp?: string,
 *   keepAliveSec?: number,
 *   keepAliveReconnectCooldownSec?: number,
 *   lazyConnect?: () => Promise<any>,
 *   onWebrtcWireDown?: (reason: string) => void,
 *   softKeepAliveIdle?: () => void,
 *   softKeepAliveIdleKeepsWire?: boolean,
 *   onTunOutbound?: (pkt: Buffer) => void,
 *   tunOutboundSendIf?: (pkt: Buffer) => boolean,
 *   shouldCountKeepaliveActivity?: () => boolean,
 *   lazyConnectFilter?: (pkt: Buffer) => boolean,
 *   tcpWireRole?: 'server'|'client', // graceful FIN при keep-alive idle (inbound=server, outbound=client)
 * }} [bridgeOpts]
 * @returns {{ reconnectWire: (newEp: any) => void } | null}
 */
function attachTunBridge(tun, transport, endpoint, bridgeOpts) {
  const kaRaw = bridgeOpts?.keepAliveSec;
  const keepAliveSec =
    typeof kaRaw === 'number' && Number.isFinite(kaRaw) && kaRaw > 0 ? Math.floor(kaRaw) : 0;
  const lazyConnect =
    typeof bridgeOpts?.lazyConnect === 'function' ? bridgeOpts.lazyConnect : null;
  const cdRaw = bridgeOpts?.keepAliveReconnectCooldownSec;
  const reconnectCooldownSec =
    typeof cdRaw === 'number' && Number.isFinite(cdRaw) && cdRaw > 0 ? Math.floor(cdRaw) : 0;
  let idleCooldownUntilMs = 0;
  const kaDebug = process.env.CLEAN_VPN_KEEPALIVE_DEBUG === '1';

  if (!keepAliveSec && !lazyConnect && !RECONNECT_BRIDGE_TRANSPORTS.has(transport)) {
    attachTunBridgeNoKeepalive(tun, transport, endpoint, bridgeOpts);
    return null;
  }

  const framer = new StreamFramer();
  const local4 = bridgeOpts?.localTunIp
    ? parseDottedIPv4FourOctets(bridgeOpts.localTunIp)
    : null;
  let ipIdCounter = randomBytes(2).readUInt16BE(0);
  const nextIpId = () => {
    ipIdCounter = (ipIdCounter + 1) & 0xffff;
    return ipIdCounter;
  };
  let icmpEchoReplyLogged = false;

  const writeTun = (pkt) => {
    try {
      tun.write(pkt);
    } catch (e) {
      console.error('[clean-vpn] tun write:', e?.message || e);
    }
  };

  /** @type {Buffer[]} */
  const dcQueue = [];
  let dcHead = 0;
  const DC_QUEUE_COMPACT_AFTER = 2048;
  const DC_BUFFER_HIGH = 8 * 1024 * 1024;
  let dcPumpScheduled = false;
  /** @type {any} */
  let ep = lazyConnect ? null : endpoint;
  let wireArmed = !lazyConnect;
  let connecting = false;
  /** @type {Buffer[]} */
  const tunQueue = [];
  let idleTimer = null;
  let pingTimer = null;
  let wireOff = () => {};
  /** Пересоздаётся при каждом новом TCP-wire (lazy reconnect). */
  /** @type {((pkt: Buffer) => void)|null} */
  let tcpFramedSend = null;
  let teardownBusy = false;
  /** После TCP client idle-disarm: ждём FIN сервера на ep. */
  let tcpIdleDrainOff = () => {};

  const resolveTcpWireRole = () => {
    const r = bridgeOpts?.tcpWireRole;
    if (r === 'server' || r === 'client') return r;
    return lazyConnect ? 'client' : 'server';
  };

  const clearTcpEndpointRef = (/** @type {import('net').Socket|null|undefined} */ sock) => {
    if (sock && ep === sock) {
      ep = null;
      tcpFramedSend = null;
    }
  };

  const handleTcpWireFailure = (phase, err) => {
    const sock = ep;
    const resetLike = isTcpWireResetError(err);
    const detail = resetLike
      ? `${phase}: ${/** @type {NodeJS.ErrnoException} */ (err)?.code || 'RST'}`
      : `${phase}: ${/** @type {Error} */ (err)?.message || String(err)}`;
    logKa(resetLike ? 'TCP RST' : 'ошибка TCP', detail);
    if (wireArmed) {
      teardownWire(resetLike ? 'peer_reset' : 'peer_error');
      return;
    }
    if (!sock) return;
    tcpIdleDrainOff();
    clearTcpEndpointRef(sock);
    resetTcpEndpoint(sock);
  };

  const attachTcpIdleDrainHandlers = (/** @type {import('net').Socket} */ sock) => {
    tcpIdleDrainOff();
    const onEnd = () => respondFinTcpEndpoint(sock);
    const onClose = () => {
      tcpIdleDrainOff();
      clearTcpEndpointRef(sock);
    };
    const onErr = (e) => handleTcpWireFailure('idle-drain', e);
    const onUnexpectedData = () => {
      logKa('TCP RST', 'данные на idle-disarm сокете (пир использует закрываемое соединение)');
      tcpIdleDrainOff();
      clearTcpEndpointRef(sock);
      resetTcpEndpoint(sock);
    };
    sock.on('end', onEnd);
    sock.on('data', onUnexpectedData);
    sock.once('close', onClose);
    sock.once('error', onErr);
    tcpIdleDrainOff = () => {
      try {
        sock.off('end', onEnd);
        sock.off('data', onUnexpectedData);
        sock.off('close', onClose);
        sock.off('error', onErr);
      } catch {
        /* ignore */
      }
      tcpIdleDrainOff = () => {};
    };
  };

  const rearmTcpClientWire = () => {
    if (wireArmed || connecting) return false;
    if (transport !== 'tcp' || !ep || ep.destroyed) return false;
    if (resolveTcpWireRole() !== 'client') return false;
    if (ep.readableEnded || ep.writableEnded || ep.writable === false) {
      logKa('reuse пропущен', 'сокет уже закрывается (FIN/RST), нужен новый connect');
      tcpIdleDrainOff();
      clearTcpEndpointRef(ep);
      resetTcpEndpoint(ep);
      return false;
    }
    tcpIdleDrainOff();
    attachWireHandlers();
    wireArmed = true;
    bumpActivity();
    logKa('re-arm', 'reuse открытый TCP client (после idle без FIN)');
    return true;
  };

  function tcpClientIdleDisarm(reason) {
    if (teardownBusy) return;
    teardownBusy = true;
    try {
      if (!wireArmed && !ep) return;
      cancelTimers();
      wireOff();
      wireOff = () => {};
      wireArmed = false;
      tunQueue.length = 0;
      if (reason === 'idle' && reconnectCooldownSec > 0 && lazyConnect) {
        idleCooldownUntilMs = Date.now() + reconnectCooldownSec * 1000;
        logKa(
          'пауза lazy-reconnect',
          `${reconnectCooldownSec}s (пакеты с TUN до этого времени игнорируются)`,
        );
      }
      if (ep && !ep.destroyed) attachTcpIdleDrainHandlers(ep);
      logKa(
        'отключено',
        `простой ${keepAliveSec}s (TUN снят; TCP client ждёт FIN от сервера)`,
      );
    } finally {
      teardownBusy = false;
    }
  }

  async function tcpServerIdleGracefulClose() {
    if (teardownBusy) return;
    teardownBusy = true;
    try {
      cancelTimers();
      wireOff();
      wireOff = () => {};
      wireArmed = false;
      tunQueue.length = 0;
      dcQueue.length = 0;
      dcHead = 0;
      dcPumpScheduled = false;
      if (reconnectCooldownSec > 0 && lazyConnect) {
        idleCooldownUntilMs = Date.now() + reconnectCooldownSec * 1000;
        logKa(
          'пауза lazy-reconnect',
          `${reconnectCooldownSec}s (пакеты с TUN до этого времени игнорируются)`,
        );
      }
      const sock = ep;
      ep = null;
      tcpFramedSend = null;
      logKa('отключено', `простой ${keepAliveSec}s (TCP server → FIN)`);
      if (sock && !sock.destroyed) await gracefulCloseTcpEndpoint(sock);
    } finally {
      teardownBusy = false;
    }
  }

  const logKa = (event, detail = '') => {
    const tail = detail ? ` — ${detail}` : '';
    console.log(`[clean-vpn] keep-alive [${transport}]: ${event}${tail}`);
  };

  const cancelTimers = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = null;
    if (pingTimer) clearInterval(pingTimer);
    pingTimer = null;
  };

  const bumpActivity = () => {
    if (!keepAliveSec) return;
    const kaFn = bridgeOpts?.shouldCountKeepaliveActivity;
    if (typeof kaFn === 'function' && !kaFn()) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      idleTimer = null;
      if (typeof bridgeOpts?.softKeepAliveIdle === 'function') {
        softTeardownWire('idle');
      } else {
        teardownWire('idle');
      }
    }, keepAliveSec * 1000);
    idleTimer.unref?.();
  };

  function softTeardownWire(reason) {
    if (teardownBusy) return;
    teardownBusy = true;
    try {
      if (!wireArmed && !connecting) {
        tunQueue.length = 0;
        return;
      }
      cancelTimers();
      if (!bridgeOpts?.softKeepAliveIdleKeepsWire) {
        wireArmed = false;
      }
      tunQueue.length = 0;
      if (reason === 'idle' && reconnectCooldownSec > 0 && lazyConnect) {
        idleCooldownUntilMs = Date.now() + reconnectCooldownSec * 1000;
        logKa(
          'пауза lazy-reconnect',
          `${reconnectCooldownSec}s (пакеты с TUN до этого времени игнорируются)`,
        );
      }
      logKa(
        'отключено',
        bridgeOpts?.softKeepAliveIdleKeepsWire
          ? `простой ${keepAliveSec}s (локальный мост остаётся; переподключение к exit — по IPv4 с TUN)`
          : `простой ${keepAliveSec}s (транспорт остаётся; переподключение WebRTC/WS к exit)`,
      );
      try {
        bridgeOpts?.softKeepAliveIdle?.();
      } catch (e) {
        console.error('[clean-vpn] softKeepAliveIdle:', e?.message || e);
      }
    } finally {
      teardownBusy = false;
    }
  }

  const pumpDcQueue = () => {
    dcPumpScheduled = false;
    if (transport !== 'webrtc-dc') return;
    if (!wireArmed || !ep) return;
    while (dcHead < dcQueue.length) {
      if (typeof ep.isOpen === 'function' && !ep.isOpen()) return;
      let buffered = 0;
      try {
        buffered = typeof ep.bufferedAmount === 'function' ? ep.bufferedAmount() : 0;
      } catch {
        buffered = 0;
      }
      if (buffered > DC_BUFFER_HIGH) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
        return;
      }
      const pkt = dcQueue[dcHead++];
      if (!pkt) break;
      try {
        bumpActivity();
        ep.sendMessageBinary(pkt);
      } catch (e) {
        console.error('[clean-vpn] webrtc-dc send:', e?.message || e);
      }
    }
    if (dcHead >= DC_QUEUE_COMPACT_AFTER && dcHead > (dcQueue.length >> 1)) {
      dcQueue.splice(0, dcHead);
      dcHead = 0;
    }
  };

  const sendOnWire = (pkt) => {
    if (!wireArmed || !ep) return;
    if (transport === 'udp-server') {
      const pr = ep.peer;
      if (!pr) return;
      bumpActivity();
      if (pkt.length > 65507) return;
      ep.sock.send(pkt, pr.port, pr.address, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
      return;
    }
    bumpActivity();
    if (transport === 'websocket') {
      ep.send(pkt);
    } else if (transport === 'tcp') {
      if (!tcpFramedSend) {
        tcpFramedSend = createTcpFramedBatchedWriter(ep, (err) => handleTcpWireFailure('write', err));
      }
      tcpFramedSend(pkt);
    } else if (transport === 'udp-client') {
      if (pkt.length > 65507) {
        console.warn('[clean-vpn] udp: пакет больше типичного MTU датаграммы');
      }
      ep.send(pkt, (err) => {
        if (err) console.error('[clean-vpn] udp send:', err.message);
      });
    } else if (transport === 'webrtc-dc') {
      dcQueue.push(pkt);
      if (!dcPumpScheduled) {
        dcPumpScheduled = true;
        setImmediate(pumpDcQueue);
      }
    }
  };

  function applyWireKeepalive() {
    if (!ep || !keepAliveSec) return;
    if (transport === 'tcp' && typeof ep.setKeepAlive === 'function') {
      try {
        ep.setKeepAlive(true, Math.min(keepAliveSec * 1000, 120000));
      } catch {
        /* ignore */
      }
    }
    if (transport === 'websocket' && typeof ep.ping === 'function') {
      if (pingTimer) clearInterval(pingTimer);
      pingTimer = setInterval(() => {
        try {
          if (ep && ep.readyState === WebSocket.OPEN) ep.ping();
        } catch {
          /* ignore */
        }
      }, keepAliveSec * 1000);
      pingTimer.unref?.();
    }
  }

  function attachWireHandlers() {
    wireOff();
    wireOff = () => {};
    if (transport === 'websocket') {
      const ws = ep;
      const onMsg = (data, isBinary) => {
        if (!isBinary) return;
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        bumpActivity();
        writeTun(buf);
      };
      const onPeerClose = () => {
        if (wireArmed) teardownWire('peer_close');
      };
      const onPeerErr = (e) => {
        logKa('ошибка WebSocket', e?.message || String(e));
        if (wireArmed) teardownWire('peer_error');
      };
      ws.on('message', onMsg);
      ws.once('close', onPeerClose);
      ws.once('error', onPeerErr);
      wireOff = () => {
        try {
          ws.off('message', onMsg);
          ws.off('close', onPeerClose);
          ws.off('error', onPeerErr);
        } catch {
          /* ignore */
        }
      };
    } else if (transport === 'tcp') {
      const sock = ep;
      const onData = (chunk) => {
        try {
          bumpActivity();
          framer.push(chunk, writeTun);
        } catch (e) {
          console.error('[clean-vpn] framing error:', e.message);
          resetTcpEndpoint(sock);
        }
      };
      const onPeerEnd = () => {
        if (wireArmed) teardownWire('peer_close');
      };
      const onPeerClose = () => {
        tcpIdleDrainOff();
        clearTcpEndpointRef(sock);
      };
      const onPeerErr = (e) => handleTcpWireFailure('read', e);
      sock.on('data', onData);
      sock.on('end', onPeerEnd);
      sock.once('close', onPeerClose);
      sock.once('error', onPeerErr);
      wireOff = () => {
        try {
          sock.off('data', onData);
          sock.off('end', onPeerEnd);
          sock.off('close', onPeerClose);
          sock.off('error', onPeerErr);
        } catch {
          /* ignore */
        }
      };
    } else if (transport === 'udp-client') {
      const udp = ep;
      const onMsg = (msg) => {
        if (!msg.length || msg.length > MAX_PKT) return;
        bumpActivity();
        writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
      };
      const onPeerClose = () => {
        if (wireArmed) teardownWire('peer_close');
      };
      const onPeerErr = (e) => {
        logKa('ошибка UDP', e?.message || String(e));
        if (wireArmed) teardownWire('peer_error');
      };
      udp.on('message', onMsg);
      udp.once('close', onPeerClose);
      udp.once('error', onPeerErr);
      wireOff = () => {
        try {
          udp.off('message', onMsg);
          udp.off('close', onPeerClose);
          udp.off('error', onPeerErr);
        } catch {
          /* ignore */
        }
      };
    } else if (transport === 'udp-server') {
      const onMsg = (msg, rinfo) => {
        if (!msg.length || msg.length > MAX_PKT) return;
        bindOrMigrateUdpServerPeer(ep, rinfo);
        bumpActivity();
        writeTun(Buffer.isBuffer(msg) ? msg : Buffer.from(msg));
      };
      ep.sock.on('message', onMsg);
      wireOff = () => {
        try {
          ep.sock.off('message', onMsg);
        } catch {
          /* ignore */
        }
      };
    } else if (transport === 'webrtc-dc') {
      const ch = ep;
      const onDc = (data) => {
        if (typeof data === 'string') return;
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        if (!buf.length || buf.length > MAX_PKT) return;
        bumpActivity();
        writeTun(buf);
      };
      ch.onMessage(onDc);
      if (typeof ch.onClosed === 'function') {
        ch.onClosed(() => {
          if (wireArmed) teardownWire('webrtc_dc_close');
        });
      }
      wireOff = () => {
        /* onMessage/onClosed снять нельзя — канал закрывается в teardownWire */
      };
    }
  }

  function teardownWire(reason) {
    if (transport === 'udp-server' && reason === 'idle' && ep) {
      if (!ep.peer) {
        cancelTimers();
        return;
      }
      cancelTimers();
      ep.peer = undefined;
      logKa(
        'отключено',
        `udp-server: сброс peer по простою (${keepAliveSec}s), ждём новую датаграмму`,
      );
      return;
    }
    if (
      transport === 'tcp' &&
      reason === 'idle' &&
      keepAliveSec > 0 &&
      !bridgeOpts?.softKeepAliveIdle
    ) {
      const role = resolveTcpWireRole();
      if (role === 'client') {
        tcpClientIdleDisarm(reason);
        return;
      }
      if (role === 'server') {
        void tcpServerIdleGracefulClose();
        return;
      }
    }
    if (teardownBusy) return;
    teardownBusy = true;
    try {
    if (!wireArmed && !ep && !connecting) {
      tunQueue.length = 0;
      return;
    }
    cancelTimers();
    wireOff();
    wireOff = () => {};
    wireArmed = false;
    tunQueue.length = 0;
    dcQueue.length = 0;
    dcHead = 0;
    dcPumpScheduled = false;
    if (reason === 'idle' && reconnectCooldownSec > 0 && lazyConnect) {
      idleCooldownUntilMs = Date.now() + reconnectCooldownSec * 1000;
      logKa(
        'пауза lazy-reconnect',
        `${reconnectCooldownSec}s (пакеты с TUN до этого времени игнорируются)`,
      );
    }
    const sock = ep;
    ep = null;
    tcpFramedSend = null;
    tcpIdleDrainOff();
    try {
      if (transport === 'tcp') {
        if (reason === 'peer_close') {
          respondFinTcpEndpoint(sock);
        } else {
          resetTcpEndpoint(sock);
        }
      } else if (transport === 'websocket') {
        try {
          ep?.close?.();
        } catch {
          /* ignore */
        }
      } else if (transport === 'udp-client') {
        try {
          ep?.disconnect?.();
        } catch {
          /* ignore */
        }
        try {
          ep?.close?.();
        } catch {
          /* ignore */
        }
      } else if (transport === 'udp-server') {
        if (ep) ep.peer = undefined;
      } else if (transport === 'webrtc-dc') {
        try {
          ep?.close?.();
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
    const reasonRu =
      reason === 'idle'
        ? `простой ${keepAliveSec}s (следующий трафик с TUN поднимет client заново; exit — ждёт пира)`
        : reason === 'peer_close'
          ? 'пир прислал FIN (ответили FIN)'
          : reason === 'peer_reset'
            ? 'пир сбросил соединение (RST/ECONNRESET)'
          : reason === 'peer_error'
            ? 'ошибка на транспорте'
            : reason === 'webrtc_dc_close'
              ? 'DataChannel закрыт'
              : String(reason || 'неизвестно');
    logKa('отключено', reasonRu);
    if (
      transport === 'webrtc-dc' &&
      (reason === 'idle' || reason === 'webrtc_dc_close') &&
      typeof bridgeOpts?.onWebrtcWireDown === 'function'
    ) {
      try {
        bridgeOpts.onWebrtcWireDown(reason);
      } catch (e) {
        console.error('[clean-vpn] onWebrtcWireDown:', e?.message || e);
      }
    }
    } finally {
      teardownBusy = false;
    }
  }

  function closeBridgeEndpoint(prev) {
    if (!prev || prev.destroyed) return;
    try {
      if (transport === 'tcp') {
        if (prev.readableEnded || prev.writableEnded || prev.writable === false) {
          resetTcpEndpoint(prev);
        } else if (resolveTcpWireRole() === 'server') {
          void gracefulCloseTcpEndpoint(prev);
        } else {
          respondFinTcpEndpoint(prev);
        }
      } else if (transport === 'websocket') {
        prev.close?.();
      } else if (transport === 'udp-client') {
        prev.disconnect?.();
        prev.close?.();
      } else if (transport === 'webrtc-dc') {
        prev.close?.();
      }
    } catch {
      /* ignore */
    }
  }

  function reconnectWire(newEp) {
    if (!newEp) return;
    if (connecting) return;
    cancelTimers();
    wireOff();
    wireOff = () => {};
    const prev = ep;
    const pending = tunQueue.splice(0);
    ep = newEp;
    wireArmed = true;
    dcQueue.length = 0;
    dcHead = 0;
    dcPumpScheduled = false;
    tcpFramedSend = null;
    attachWireHandlers();
    applyWireKeepalive();
    bumpActivity();
    closeBridgeEndpoint(prev);
    logKa(
      'переподключено',
      pending.length ? `${transport}, очередь TUN ${pending.length} пакет(ов)` : transport,
    );
    for (const q of pending) {
      sendOnWire(q);
    }
  }

  async function ensureWire() {
    if (wireArmed || connecting) return;
    if (rearmTcpClientWire()) {
      const pending = tunQueue.splice(0);
      logKa('подключено', `reuse TCP client, очередь TUN ${pending.length} пакет(ов)`);
      for (const q of pending) {
        sendOnWire(q);
      }
      return;
    }
    if (!lazyConnect) return;
    connecting = true;
    try {
      const newEp = await lazyConnect();
      const sameEp = ep && newEp === ep;
      ep = newEp;
      wireArmed = true;
      if (sameEp) {
        applyWireKeepalive();
        bumpActivity();
      } else {
        attachWireHandlers();
        applyWireKeepalive();
        bumpActivity();
      }
      const pending = tunQueue.splice(0);
      logKa('подключено', `lazy, очередь TUN ${pending.length} пакет(ов)`);
      for (const q of pending) {
        sendOnWire(q);
      }
    } catch (e) {
      logKa('ошибка lazy-connect', e?.message || String(e));
      console.error('[clean-vpn] keep-alive lazy connect:', e?.message || e);
      wireArmed = false;
      ep = null;
      tcpFramedSend = null;
    } finally {
      connecting = false;
    }
  }

  if (wireArmed && ep) {
    attachWireHandlers();
    applyWireKeepalive();
    bumpActivity();
    logKa('подключено', 'сессия активна сразу (без lazy)');
  }

  tun.startRead((batch) => {
    const pkts = Array.isArray(batch) ? batch : [batch];
    for (const raw of pkts) {
      const pkt = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (!pkt.length || pkt.length > MAX_PKT) continue;
      if (local4) {
        const reply = tryBuildTunIcmpEchoReplyForLocalIp(pkt, local4, nextIpId);
        if (reply) {
          writeTun(reply);
          if (!icmpEchoReplyLogged) {
            icmpEchoReplyLogged = true;
            console.log(
              `[clean-vpn] ICMP echo reply на TUN (${bridgeOpts?.localTunIp}); дальнейшие ответы без лога`,
            );
          }
          continue;
        }
      }
      if (!isIpv4Bridgeable(pkt)) {
        if (kaDebug) {
          const v = pkt.length ? pkt[0] >> 4 : -1;
          const hex = pkt.subarray(0, Math.min(8, pkt.length)).toString('hex');
          logKa('drop-nonv4', `verNibble=${v} head=${hex} len=${pkt.length}`);
        }
        continue;
      }
      if (!wireArmed && lazyConnect) {
        if (Date.now() < idleCooldownUntilMs) {
        if (kaDebug) {
          const ipProto = pkt.length >= 10 ? pkt.readUInt8(9) : -1;
          logKa('cooldown', `drop ${pkt.length} B ip-proto=${ipProto}`);
        }
          continue;
        }
        const lazyFilter = bridgeOpts?.lazyConnectFilter;
        if (typeof lazyFilter === 'function' && !lazyFilter(pkt)) {
          if (kaDebug) {
            const ipProto = pkt.length >= 10 ? pkt.readUInt8(9) : -1;
            logKa('lazy-skip', `${pkt.length} B ip-proto=${ipProto} (не триггер lazy-reconnect)`);
          }
          continue;
        }
        if (rearmTcpClientWire()) {
          try {
            bridgeOpts?.onTunOutbound?.(pkt);
          } catch (e) {
            console.error('[clean-vpn] onTunOutbound:', e?.message || e);
          }
          if (
            typeof bridgeOpts?.tunOutboundSendIf === 'function' &&
            !bridgeOpts.tunOutboundSendIf(pkt)
          ) {
            continue;
          }
          sendOnWire(pkt);
          continue;
        }
        if (kaDebug) {
          const ipProto = pkt.length >= 10 ? pkt.readUInt8(9) : -1;
          logKa('lazy-queue', `${pkt.length} B ip-proto=${ipProto} до=${tunQueue.length + 1}`);
        }
        if (tunQueue.length >= KEEPALIVE_TUN_QUEUE_MAX) {
          if (kaDebug) logKa('lazy-queue-drop', 'старый пакет (очередь полна)');
          tunQueue.shift();
        }
        tunQueue.push(pkt);
        void ensureWire();
        continue;
      }
      if (!wireArmed) continue;
      try {
        bridgeOpts?.onTunOutbound?.(pkt);
      } catch (e) {
        console.error('[clean-vpn] onTunOutbound:', e?.message || e);
      }
      if (typeof bridgeOpts?.tunOutboundSendIf === 'function' && !bridgeOpts.tunOutboundSendIf(pkt)) {
        if (kaDebug) {
          const ipProto = pkt.length >= 10 ? pkt.readUInt8(9) : -1;
          logKa('tun-drop', `${pkt.length} B ip-proto=${ipProto} (exit не готов)`);
        }
        continue;
      }
      sendOnWire(pkt);
    }
  });

  return { reconnectWire };
}

/**
 * @param {{ localTunIp?: string }} base
 * @param {number} keepAliveSec
 * @param {number} [reconnectCooldownSec] — после idle не поднимать lazy по TUN N секунд (0 = выкл.)
 */
function withKeepalive(base, keepAliveSec, reconnectCooldownSec = 0) {
  const n = keepAliveSec == null ? 0 : Number(keepAliveSec);
  if (!Number.isFinite(n) || n <= 0) return { ...base };
  const out = { ...base, keepAliveSec: Math.floor(n) };
  const c = reconnectCooldownSec == null ? 0 : Number(reconnectCooldownSec);
  if (Number.isFinite(c) && c > 0) out.keepAliveReconnectCooldownSec = Math.floor(c);
  return out;
}

/**
 * Client/outbound: один мост с lazyConnect. Без --keep-alive connect сразу (eager), с N>0 — после первого IPv4 с TUN.
 *
 * @param {Parameters<typeof attachTunBridge>[0]} tun
 * @param {Parameters<typeof attachTunBridge>[1]} transport
 * @param {{ localTunIp?: string }} bridgeBase
 * @param {() => Promise<any>} connectFn
 * @param {number} keepAliveSec
 * @param {number} [reconnectCooldownSec]
 * @param {boolean} [eagerOnStart] — сразу connectFn (rtc-chrome / split-default + keep-alive на TLS TUN)
 * @returns {{ reconnectWire: (newEp: any) => void } | null}
 */
function shouldEagerOutboundTunConnect(transportType, splitDefault, keepAliveSec) {
  return (
    Boolean(splitDefault) &&
    keepAliveSec > 0 &&
    (isTlsLikeType(transportType) || transportType === 'combo-tls' || transportType === 'transparent-tls')
  );
}

function attachOutboundTunBridge(
  tun,
  transport,
  bridgeBase,
  connectFn,
  keepAliveSec,
  reconnectCooldownSec = 0,
  eagerOnStart = false,
) {
  const ka = keepAliveSec > 0 ? Math.floor(keepAliveSec) : 0;
  const api = attachTunBridge(tun, transport, null, {
    ...withKeepalive(bridgeBase, ka, reconnectCooldownSec),
    lazyConnect: connectFn,
    tcpWireRole: 'client',
  });
  if (ka === 0 || eagerOnStart) {
    if (eagerOnStart && ka > 0) {
      console.log(
        `[clean-vpn] ${transport}: eager connect при keep-alive=${ka}s (--split-default; TUN-транспорт до первого пакета с tun0)`,
      );
    }
    void connectFn()
      .then((ep) => api?.reconnectWire(ep))
      .catch((e) => {
        console.error(`[clean-vpn] eager connect [${transport}]:`, e?.message || e);
      });
  }
  return api;
}

/**
 * Exit/inbound (или client reverse-listen): один мост; каждое новое соединение — reconnectWire.
 *
 * @param {Parameters<typeof attachTunBridge>[0]} tun
 * @param {{ localTunIp?: string }} bridgeBase
 * @param {number} keepAliveSec
 * @param {number} [reconnectCooldownSec]
 */
function createInboundTunBridgeAttach(tun, bridgeBase, keepAliveSec, reconnectCooldownSec = 0) {
  /** @type {{ reconnectWire: (newEp: any) => void } | null} */
  let bridgeApi = null;
  const bridgeOpts = {
    ...withKeepalive(bridgeBase, keepAliveSec, reconnectCooldownSec),
    tcpWireRole: 'server',
  };
  return (
    /** @type {Parameters<typeof attachTunBridge>[1]} */ transport,
    endpoint,
    onAttached,
  ) => {
    if (!bridgeApi) {
      bridgeApi = attachTunBridge(tun, transport, endpoint, bridgeOpts);
    } else {
      bridgeApi.reconnectWire(endpoint);
    }
    onAttached?.();
    return bridgeApi;
  };
}

/**
 * Разобрать первую HTTP/1.1 строку и заголовок `Authorization: Bearer <token>`.
 * `kind='non_http'` означает, что request-line не соответствует `^METHOD PATH HTTP/1.x$`
 * (или вообще нет CRLFCRLF в первых 16 KiB) — в обоих случаях вызывающий уже видит
 * полный буфер преамбулы, поэтому достаточно одного маркера.
 * @param {Buffer} buf
 * @returns {{ kind: 'http'|'non_http', method: string, path: string, bearer: string|null }}
 */
function parseHttpRequestForVpn(buf) {
  const idx = buf.indexOf('\r\n\r\n');
  if (idx === -1) return { kind: 'non_http', method: '', path: '', bearer: null };
  const head = buf.subarray(0, idx).toString('latin1');
  const lines = head.split('\r\n');
  const reqLine = lines[0] || '';
  const m = /^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/.exec(reqLine);
  if (!m) return { kind: 'non_http', method: '', path: '', bearer: null };
  let bearer = null;
  for (let i = 1; i < lines.length; i++) {
    const c = lines[i].indexOf(':');
    if (c <= 0) continue;
    const name = lines[i].slice(0, c).trim().toLowerCase();
    if (name !== 'authorization') continue;
    const val = lines[i].slice(c + 1).trim();
    const bm = /^Bearer\s+(\S+)/i.exec(val);
    if (bm) bearer = bm[1];
    break;
  }
  return { kind: 'http', method: m[1], path: m[2], bearer };
}

/** Hex16 от первых байт буфера — для prefix=… в логах cover/passthrough. */
function tlsPreviewHex16(buf) {
  return buf.subarray(0, Math.min(16, buf.length)).toString('hex');
}

/** Из заголовка Authorization (HTTP/1 или HTTP/2) извлекает Bearer-токен или null. */
function tlsVpnBearerFromAuthorizationHeader(raw) {
  if (raw == null) return null;
  const s = Array.isArray(raw) ? String(raw[0]) : String(raw);
  const bm = /^Bearer\s+(\S+)/i.exec(s.trim());
  return bm ? bm[1] : null;
}

/**
 * Общая проверка VPN vs cover по методу, пути и bearer.
 * @param {'http1'|'http2'} layer — GET для h1, POST для h2.
 * @param {Buffer|null} [exporter=null] — TLS exporter этой сессии (RFC 5705) для channel-binding v2.
 */
function mapCoverOutcomeFromParts(method, path, bearer, vpnSecret, layer, exporter = null) {
  const wantMethod = layer === 'http2' ? 'POST' : 'GET';
  if (method !== wantMethod) {
    return { outcome: 'cover_wrong_method', windowOffset: null, legacy: false };
  }
  if (path !== '/clean-vpn') {
    return { outcome: 'cover_wrong_path', windowOffset: null, legacy: false };
  }
  if (!bearer) return { outcome: 'cover_no_bearer', windowOffset: null, legacy: false };
  const v = verifyTlsVpnBearerToken(vpnSecret, bearer, exporter);
  if (!v.ok) return { outcome: 'cover_bad_bearer', windowOffset: null, legacy: false };
  return { outcome: 'vpn', windowOffset: v.windowOffset, legacy: v.legacy };
}

/** Маппинг распарсенной HTTP/1.1 преамбулы на конкретный cover_* outcome. */
function mapCoverOutcome(parsed, vpnSecret, exporter = null) {
  if (!parsed || parsed.kind !== 'http') {
    return { outcome: 'cover_non_http', windowOffset: null, legacy: false };
  }
  return mapCoverOutcomeFromParts(
    parsed.method,
    parsed.path,
    parsed.bearer,
    vpnSecret,
    'http1',
    exporter,
  );
}

/**
 * После рукопожатия: разбор HTTP-преамбулы. Совпавший Bearer → VPN-мост,
 * иначе — «It works!» (как обычная HTTPS-страница). Логи:
 *   - `tls vpn: connected ip=… windowOffset=…` при VPN connect;
 *   - `tls cover: served ip=… reason=cover_… prefix=…` при отдаче «It works!»;
 *   - `tls cover: idle ip=… ms=30000` при тишине после handshake;
 *   - `tls cover: oversize ip=… bytes=…` при > 16 KiB без CRLFCRLF;
 *   - `tls handshake: ip=… code=… msg=…` при ошибке до 'secure';
 *   - `tls done: ip=… outcome=… bytesIn=… ms=…` ровно одна на close;
 *   - `outcome=tls_peer_closed_before_http` — пир закрыл TLS после рукопожатия, не отправив HTTP (типично `probe.js --type=handshake`).
 *
 * @param {import('tls').TLSSocket} tlsSock
 * @param {{
 *   startBridge: (sock: any, restBuf: Buffer|null, transport: 'tcp') => void,
 *   vpnSecret: Buffer,
 * }} ctx
 */
function wireExitTlsSocket(tlsSock, ctx) {
  const st = {
    ip: tlsClientIp(tlsSock),
    port: tlsSock.remotePort ?? null,
    startMs: Date.now(),
    bytesIn: 0,
    /** @type {string|null} */
    outcome: null,
    /** @type {string|null} */
    reasonExtra: null,
    /** @type {number|null} */
    windowOffset: null,
    secured: false,
    summarized: false,
    /** @type {string} */
    httpLabel: '—',
  };
  const setOutcomeOnce = (outcome, extra) => {
    if (st.outcome) return;
    st.outcome = outcome;
    if (extra !== undefined) st.reasonExtra = extra;
  };
  const summarize = () => {
    if (st.summarized) return;
    st.summarized = true;
    const ms = Date.now() - st.startMs;
    const outcome =
      st.outcome ||
      (st.secured
        ? st.bytesIn === 0
          ? 'tls_peer_closed_before_http'
          : 'tls_runtime_error'
        : 'tls_handshake_fail');
    /** @type {string[]} */
    const fields = [
      `ip=${st.ip}`,
      `port=${st.port ?? '?'}`,
      `outcome=${outcome}`,
      `http=${st.httpLabel}`,
      `bytesIn=${st.bytesIn}`,
      `ms=${ms}`,
    ];
    if (outcome === 'vpn' && st.windowOffset !== null) {
      fields.push(`windowOffset=${st.windowOffset}`);
    }
    if (st.reasonExtra) fields.push(st.reasonExtra);
    console.log(`[clean-vpn] tls done: ${fields.join(' ')}`);
  };

  tlsSock.on('error', (e) => {
    const code = /** @type {any} */ (e)?.code ?? '';
    const msg = e?.message || String(e);
    if (!st.secured) {
      setOutcomeOnce('tls_handshake_fail', `code=${code || '—'} msg=${msg}`);
      console.error(`[clean-vpn] tls handshake: ip=${st.ip} code=${code || '—'} msg=${msg}`);
      return;
    }
    if (st.bytesIn > 0 && TCP_BENIGN_AFTER_DATA_CODES.has(code)) {
      return; // benign post-data reset
    }
    setOutcomeOnce('tls_runtime_error', `code=${code || '—'} msg=${msg}`);
    console.error(`[clean-vpn] tls socket: ip=${st.ip} code=${code || '—'} msg=${msg}`);
  });
  tlsSock.on('close', summarize);

  const beginHttp1Wire = () => {
    st.secured = true;
    applyCleanVpnTlsTcpBuffers(tlsSock);
    const apRaw = tlsSock.alpnProtocol;
    const ap = apRaw === false ? '' : String(apRaw);
    st.httpLabel = tlsAlpnToHttpLabel(ap);
    try {
      let httpBuf = Buffer.alloc(0);
      const idleTimer = setTimeout(() => {
        if (tlsSock.destroyed) return;
        setOutcomeOnce('cover_idle');
        console.log(
          `[clean-vpn] tls cover: idle ip=${st.ip} port=${st.port ?? '?'} ms=30000 http=${st.httpLabel}`,
        );
        try {
          tlsSock.destroy();
        } catch {
          /* ignore */
        }
      }, 30000);
      idleTimer.unref?.();
      const respondPublic = (outcome, prefixHex) => {
        if (tlsCoverShouldThrottle(st.ip)) {
          setOutcomeOnce('cover_ratelimit', `reason=${outcome}`);
          console.log(
            `[clean-vpn] tls cover: ratelimit ip=${st.ip} port=${st.port ?? '?'} reason=${outcome} prefix=${prefixHex} http=${st.httpLabel}`,
          );
          try {
            tlsSock.destroy();
          } catch {
            /* ignore */
          }
          return;
        }
        setOutcomeOnce(outcome, `reason=${outcome}`);
        console.log(
          `[clean-vpn] tls cover: served ip=${st.ip} port=${st.port ?? '?'} reason=${outcome} prefix=${prefixHex} http=${st.httpLabel}`,
        );
        const body = TLS_HTTP_WORKS_BODY;
        const res =
          `HTTP/1.1 200 OK\r\n` +
          `Content-Type: text/plain; charset=utf-8\r\n` +
          `Content-Length: ${Buffer.byteLength(body)}\r\n` +
          `Connection: close\r\n\r\n${body}`;
        tlsSock.write(res, () => {
          try {
            tlsSock.end();
          } catch {
            /* ignore */
          }
        });
      };
      const onHttp = (d) => {
        st.bytesIn += d.length;
        httpBuf = httpBuf.length === 0 ? Buffer.from(d) : Buffer.concat([httpBuf, d]);
        const idx = httpBuf.indexOf('\r\n\r\n');
        if (idx === -1) {
          if (httpBuf.length > 16384) {
            tlsSock.off('data', onHttp);
            clearTimeout(idleTimer);
            const prefixHex = tlsPreviewHex16(httpBuf);
            setOutcomeOnce('cover_oversize', `prefix=${prefixHex}`);
            console.log(
              `[clean-vpn] tls cover: oversize ip=${st.ip} port=${st.port ?? '?'} bytes=${httpBuf.length} prefix=${prefixHex} http=${st.httpLabel}`,
            );
            try {
              tlsSock.destroy();
            } catch {
              /* ignore */
            }
          }
          return;
        }
        tlsSock.off('data', onHttp);
        clearTimeout(idleTimer);
        const parsed = parseHttpRequestForVpn(httpBuf);
        const exporter = tlsVpnExporterFromSocket(tlsSock);
        const { outcome, windowOffset, legacy } = mapCoverOutcome(
          parsed,
          ctx.vpnSecret,
          exporter,
        );
        if (outcome !== 'vpn') {
          if (outcome === 'cover_bad_bearer') {
            tlsLogBearerDebug('exit http1 reject', parsed.bearer, exporter, false);
          }
          respondPublic(outcome, tlsPreviewHex16(httpBuf));
          return;
        }
        st.windowOffset = windowOffset;
        setOutcomeOnce('vpn');
        const ack = `HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n`;
        tlsSock.write(ack);
        const rest = httpBuf.subarray(idx + 4);
        const bearerLabel = legacy ? ' bearer_legacy=1' : '';
        if (legacy) {
          console.warn(
            `[clean-vpn] tls: принят legacy Bearer (v1, без channel-binding) ip=${st.ip} port=${st.port ?? '?'} — обновите client до Phase 2 (H-1+H-2)`,
          );
        }
        tlsLogBearerDebug('exit http1 accept', parsed.bearer, exporter, legacy);
        console.log(
          `[clean-vpn] tls vpn: connected ip=${st.ip} port=${st.port ?? '?'} windowOffset=${windowOffset}${bearerLabel} http=${st.httpLabel}`,
        );
        ctx.startBridge(tlsSock, rest.length ? rest : null, 'tcp');
      };
      tlsSock.on('data', onHttp);
    } catch (e) {
      setOutcomeOnce('tls_runtime_error', `msg=${e?.message || e}`);
      console.error('[clean-vpn] tls secure handler:', e?.message || e);
      try {
        tlsSock.destroy();
      } catch {
        /* ignore */
      }
    }
  };

  if (tlsSock.encrypted) beginHttp1Wire();
  else tlsSock.once('secure', beginHttp1Wire);
}

/**
 * HTTP/2 (ALPN h2): ClientHello уже прочитан для mux — отдаём сырой TCP в общий Http2SecureServer.
 * Важно: сначала `emit('connection', tcp)`, затем `unshift(ClientHello)`; иначе handshake/stream не поднимаются.
 *
 * @param {import('net').Socket} tcpSocket
 * @param {Buffer} prefixBuf полный буфер с первым TLS ClientHello (и возможным хвостом)
 * @param {{
 *   startBridge: (sock: any, restBuf: Buffer|null, transport: 'tcp') => void,
 *   vpnSecret: Buffer,
 *   tlsExitHttp2Server: import('http2').Http2SecureServer,
 * }} ctx
 */
function wireExitHttp2VpnInjected(tcpSocket, prefixBuf, ctx) {
  applyCleanVpnTlsTcpBuffers(tcpSocket);
  const peerKey = tlsPeerTuple(tcpSocket);
  const st = {
    ip: tlsClientIp(tcpSocket),
    port: tcpSocket.remotePort ?? null,
    startMs: Date.now(),
    bytesIn: 0,
    /** @type {string|null} */
    outcome: null,
    /** @type {string|null} */
    reasonExtra: null,
    /** @type {number|null} */
    windowOffset: null,
    secured: false,
    summarized: false,
    httpLabel: 'HTTP/2',
  };
  /** @type {import('tls').TLSSocket|null} */
  let tlsLayerSock = null;
  const h2 = ctx.tlsExitHttp2Server;
  const setOutcomeOnce = (outcome, extra) => {
    if (st.outcome) return;
    st.outcome = outcome;
    if (extra !== undefined) st.reasonExtra = extra;
  };
  const summarize = () => {
    if (st.summarized) return;
    st.summarized = true;
    const ms = Date.now() - st.startMs;
    const outcome =
      st.outcome ||
      (st.secured
        ? st.bytesIn === 0
          ? 'tls_peer_closed_before_http'
          : 'tls_runtime_error'
        : 'tls_handshake_fail');
    /** @type {string[]} */
    const fields = [
      `ip=${st.ip}`,
      `port=${st.port ?? '?'}`,
      `outcome=${outcome}`,
      `http=${st.httpLabel}`,
      `bytesIn=${st.bytesIn}`,
      `ms=${ms}`,
    ];
    if (outcome === 'vpn' && st.windowOffset !== null) {
      fields.push(`windowOffset=${st.windowOffset}`);
    }
    if (st.reasonExtra) fields.push(st.reasonExtra);
    console.log(`[clean-vpn] tls done: ${fields.join(' ')}`);
  };

  const destroyIdleTarget = () => tlsLayerSock || tcpSocket;

  let idleTimer = setTimeout(() => {
    const sock = destroyIdleTarget();
    if (sock.destroyed) return;
    setOutcomeOnce('cover_idle');
    console.log(
      `[clean-vpn] tls cover: idle ip=${st.ip} port=${st.port ?? '?'} ms=30000 http=${st.httpLabel}`,
    );
    try {
      sock.destroy();
    } catch {
      /* ignore */
    }
  }, 30000);
  idleTimer.unref?.();

  let streamHandled = false;
  const cleanupListeners = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = /** @type {any} */ (null);
    try {
      h2.off('stream', onStream);
    } catch {
      /* ignore */
    }
    try {
      h2.off('session', onSession);
    } catch {
      /* ignore */
    }
  };

  const onTlsLayerError = (e) => {
    const code = /** @type {any} */ (e)?.code ?? '';
    const msg = e?.message || String(e);
    if (st.bytesIn > 0 && TCP_BENIGN_AFTER_DATA_CODES.has(code)) {
      return;
    }
    setOutcomeOnce('tls_runtime_error', `code=${code || '—'} msg=${msg}`);
    console.error(`[clean-vpn] tls socket: ip=${st.ip} code=${code || '—'} msg=${msg}`);
  };

  /** @param {import('http2').Http2Session} sess */
  const onSession = (sess) => {
    const s = /** @type {import('tls').TLSSocket} */ (sess.socket);
    if (tlsPeerTuple(s) !== peerKey) return;
    try {
      h2.off('session', onSession);
    } catch {
      /* ignore */
    }
    tlsLayerSock = s;
    applyCleanVpnHttp2ConnWindow(sess);
    st.secured = true;
    const apRaw = s.alpnProtocol;
    const ap = apRaw === false ? '' : String(apRaw);
    try {
      s.on('error', onTlsLayerError);
      s.once('close', summarize);
    } catch {
      /* ignore */
    }
    console.log(
      `[clean-vpn] tls: рукопожатие ip=${st.ip} port=${st.port ?? '?'} http=${tlsAlpnToHttpLabel(ap)} negotiated ALPN=${ap || '—'}`,
    );
  };

  /** @type {(stream: import('http2').ServerHttp2Stream, headers: import('http2').IncomingHttpHeaders) => void} */
  const onStream = (stream, headers) => {
    if (tlsPeerTuple(stream.session.socket) !== peerKey) return;
    if (streamHandled) {
      try {
        stream.respond({ ':status': '404' });
        stream.destroy();
      } catch {
        /* ignore */
      }
      return;
    }
    streamHandled = true;
    cleanupListeners();

    const method = headers[':method'];
    const path = headers[':path'];
    const bearer = tlsVpnBearerFromAuthorizationHeader(headers.authorization);
    const tlsForDestroy = /** @type {import('tls').TLSSocket} */ (stream.session.socket);
    const exporter = tlsVpnExporterFromSocket(tlsForDestroy);
    const { outcome, windowOffset, legacy } = mapCoverOutcomeFromParts(
      typeof method === 'string' ? method : '',
      typeof path === 'string' ? path : '',
      bearer,
      ctx.vpnSecret,
      'http2',
      exporter,
    );

    const previewBuf = Buffer.from(
      `${typeof method === 'string' ? method : '?'} ${typeof path === 'string' ? path : '?'}`,
      'utf8',
    );

    if (outcome !== 'vpn') {
      if (outcome === 'cover_bad_bearer') {
        tlsLogBearerDebug('exit http2 reject', bearer, exporter, false);
      }
      if (tlsCoverShouldThrottle(st.ip)) {
        setOutcomeOnce('cover_ratelimit', `reason=${outcome}`);
        console.log(
          `[clean-vpn] tls cover: ratelimit ip=${st.ip} port=${st.port ?? '?'} reason=${outcome} prefix=${tlsPreviewHex16(previewBuf)} http=${st.httpLabel}`,
        );
        try {
          stream.destroy();
        } catch {
          /* ignore */
        }
        try {
          tlsForDestroy.destroy();
        } catch {
          /* ignore */
        }
        return;
      }
      setOutcomeOnce(outcome, `reason=${outcome}`);
      console.log(
        `[clean-vpn] tls cover: served ip=${st.ip} port=${st.port ?? '?'} reason=${outcome} prefix=${tlsPreviewHex16(previewBuf)} http=${st.httpLabel}`,
      );
      const body = TLS_HTTP_WORKS_BODY;
      try {
        stream.respond({
          ':status': '200',
          'content-type': 'text/plain; charset=utf-8',
          'content-length': Buffer.byteLength(body),
        });
        stream.end(body);
      } catch (e) {
        setOutcomeOnce('tls_runtime_error', `msg=${e?.message || e}`);
        try {
          stream.destroy();
        } catch {
          /* ignore */
        }
      }
      return;
    }

    st.windowOffset = windowOffset;
    setOutcomeOnce('vpn');
    try {
      stream.respond(
        {
          ':status': '200',
          'content-type': 'application/octet-stream',
        },
        { endStream: false },
      );
    } catch (e) {
      setOutcomeOnce('tls_runtime_error', `msg=${e?.message || e}`);
      try {
        tlsForDestroy.destroy();
      } catch {
        /* ignore */
      }
      return;
    }

    applyCleanVpnHttp2StreamWindow(stream);

    stream.on('data', (d) => {
      st.bytesIn += d.length;
    });

    const bearerLabel = legacy ? ' bearer_legacy=1' : '';
    if (legacy) {
      console.warn(
        `[clean-vpn] tls: принят legacy Bearer (v1, без channel-binding) ip=${st.ip} port=${st.port ?? '?'} — обновите client до Phase 2 (H-1+H-2)`,
      );
    }
    tlsLogBearerDebug('exit http2 accept', bearer, exporter, legacy);
    console.log(
      `[clean-vpn] tls vpn: connected ip=${st.ip} port=${st.port ?? '?'} windowOffset=${windowOffset}${bearerLabel} http=${st.httpLabel}`,
    );

    const wrapped = http2StreamToSocketLike(stream, stream.session, tlsForDestroy);
    ctx.startBridge(wrapped, null, 'tcp');
  };

  tcpSocket.once('close', () => {
    cleanupListeners();
    summarize();
  });

  try {
    h2.on('session', onSession);
    h2.on('stream', onStream);
    h2.emit('connection', tcpSocket);
    tcpSocket.unshift(prefixBuf);
    try {
      tcpSocket.resume();
    } catch {
      /* ignore */
    }
  } catch (e) {
    cleanupListeners();
    setOutcomeOnce('tls_runtime_error', `msg=${e?.message || e}`);
    console.error('[clean-vpn] tls HTTP/2 emit(connection):', e?.message || e);
    try {
      tcpSocket.destroy();
    } catch {
      /* ignore */
    }
  }
}

/**
 * @param {import('net').Socket} clientSock
 * @param {Buffer} prefixBuf
 * @param {{
 *   probeTargetHost: string,
 *   probeTargetPort: number,
 *   probeShortMaxBytes: number,
 *   probeMaxSeconds: number,
 *   probeFullProxyPerIp: number,
 *   probeBudget: Map<string, { day: number, fullCount: number }>,
 * }} ctx
 */
function runTlsProbePassthrough(clientSock, prefixBuf, ctx) {
  const ip = tlsClientIp(clientSock);
  const port = clientSock.remotePort ?? '?';
  const remote = net.createConnection(
    { port: ctx.probeTargetPort, host: ctx.probeTargetHost },
    () => {
      remote.write(prefixBuf);
      const day = tlsUtcDayBucket();
      const ipKey = tlsClientIp(clientSock);
      let fb = ctx.probeBudget.get(ipKey);
      if (!fb || fb.day !== day) {
        fb = { day, fullCount: 0 };
        ctx.probeBudget.set(ipKey, fb);
      }
      let maxBytes = ctx.probeShortMaxBytes;
      if (ctx.probeFullProxyPerIp > 0 && fb.fullCount < ctx.probeFullProxyPerIp) {
        fb.fullCount += 1;
        maxBytes = Number.MAX_SAFE_INTEGER;
      }
      pipeTcpWithLimits(
        clientSock,
        remote,
        {
          maxBytes,
          maxMs: ctx.probeMaxSeconds * 1000,
          treatCommonResetAsClose: true,
        },
        (meta) => {
          const ok = !meta.socketError;
          console.log(
            `[clean-vpn] tls passthrough: end ip=${ip} port=${port} result=${ok ? 'ok' : 'fail'} bytes=${meta.totalBytes} cause=${meta.cause}`,
          );
        },
      );
    },
  );
  remote.on('error', (e) => {
    console.log(
      `[clean-vpn] tls passthrough: end ip=${ip} port=${port} result=fail cause=upstream err=${e.message}`,
    );
    try {
      clientSock.destroy();
    } catch {
      /* ignore */
    }
  });
}

/**
 * JA3 и поля ClientHello, которые в Wireshark видны отдельно от JA3 (ALPN, supported_versions и т.д.).
 * Классический JA3 не включает строки ALPN — только тип расширения 16 в списке ext types.
 *
 * @param {Buffer} fullBuf
 * @param {{ sni: string[], alpn: string[], supportedVersions: number[] }} helloParse
 * @param {{ tlsLogJa3?: boolean, ja3Verbose?: boolean }} opts
 */
function tryLogExitTlsJa3(fullBuf, helloParse, opts) {
  if (!opts.tlsLogJa3) return;
  try {
    let recordLegacy = null;
    if (fullBuf.length >= 3 && fullBuf[0] === 0x16) {
      recordLegacy = fullBuf.readUInt16BE(1);
    }
    const chBody = extractFirstClientHelloBody(fullBuf);
    const chLegacy =
      chBody && chBody.length >= 2 ? chBody.readUInt16BE(0) : null;
    const alpnStr = helloParse.alpn?.length ? helloParse.alpn.join(',') : '—';
    const sniStr = helloParse.sni?.length ? helloParse.sni.join(',') : '—';
    const supStr = helloParse.supportedVersions?.length
      ? helloParse.supportedVersions.join(',')
      : '—';
    const recStr =
      recordLegacy != null ? `0x${recordLegacy.toString(16)}` : '—';
    console.log(
      `[clean-vpn] tls hello (wire): tls_record_legacy=${recStr} clienthello_legacy=${chLegacy ?? '—'} supported_versions=${supStr} offered_alpn=${alpnStr} sni=${sniStr}`,
    );
    console.log(
      '[clean-vpn] tls hello (hint): MD5 JA3 не зависит от имён протоколов в ALPN (меняется только содержимое расширения 16); при тех же типах расширений и шифрах digest часто совпадает при h2 и http/1.1.',
    );
    if (opts.ja3Verbose) {
      const d = ja3DebugFromTcpBuf(fullBuf);
      if (!d) {
        console.log('[clean-vpn] tls ja3 (exit): не удалось извлечь ClientHello для JA3');
        return;
      }
      console.log(`[clean-vpn] tls ja3 (exit): ja3_md5=${d.ja3Digest}`);
      console.log(`[clean-vpn] tls ja3 (exit): ja3_sorted_md5=${d.ja3SortedDigest}`);
      console.log(`[clean-vpn] tls ja3 (exit): ja3_string=${d.ja3String}`);
      console.log(`[clean-vpn] tls ja3 (exit): ja3_sorted_string=${d.ja3SortedString}`);
      console.log(`[clean-vpn] tls ja3 (exit): legacy_version=${d.legacyVersion}`);
      console.log(`[clean-vpn] tls ja3 (exit): ciphers=${d.ciphers.join(',')}`);
      console.log(`[clean-vpn] tls ja3 (exit): extensions=${d.extTypes.join(',')}`);
      console.log(`[clean-vpn] tls ja3 (exit): supported_groups=${d.curves.join(',')}`);
      console.log(`[clean-vpn] tls ja3 (exit): ec_point_formats=${d.ecPointFormats.join(',')}`);
      console.log(`[clean-vpn] tls ja3 (exit): hex_preview=${d.hexPreview}`);
      try {
        const j4 = ja4FromTcpBuf(fullBuf);
        if (j4) {
          console.log(`[clean-vpn] tls ja4 (exit): ja4=${j4.fingerprint}`);
          console.log(`[clean-vpn] tls ja4 (exit): ja4_a=${j4.ja4_a} ja4_b=${j4.ja4_b} ja4_c=${j4.ja4_c}`);
        }
      } catch {
        /* ignore */
      }
    } else {
      const j = ja3FromTcpBuf(fullBuf);
      if (!j) return;
      console.log(`[clean-vpn] tls ja3 (exit): ja3_md5=${j.ja3Digest}`);
      console.log(`[clean-vpn] tls ja3 (exit): ja3_sorted_md5=${j.ja3SortedDigest}`);
      const j4 = ja4FromTcpBuf(fullBuf);
      if (j4) {
        console.log(`[clean-vpn] tls ja4 (exit): ja4=${j4.fingerprint}`);
      }
    }
  } catch (e) {
    console.warn('[clean-vpn] tls ja3 (exit):', e?.message || e);
  }
}

/**
 * @param {import('net').Socket} socket
 * @param {{
 *   startBridge: (sock: any, restBuf: Buffer|null, transport: 'tcp') => void,
 *   creds: { cert: string, key: string },
 *   tlsPublicName: string|null,
 *   probeTargetHost: string,
 *   probeTargetPort: number,
 *   probeShortMaxBytes: number,
 *   probeMaxSeconds: number,
 *   probeFullProxyPerIp: number,
 *   probeBudget: Map<string, { day: number, fullCount: number }>,
 *   tlsExitSecureContext: import('tls').SecureContext,
 *   vpnSecret: Buffer,
 *   tlsHttpVers: null|'1.1',
 *   tlsExitHttp2Server: import('http2').Http2SecureServer,
 *   tlsLogJa3?: boolean,
 *   ja3Verbose?: boolean,
 * }} ctx
 */
function handleTlsExitInbound(socket, ctx) {
  const ip = tlsClientIp(socket);
  const rp = socket.remotePort;
  console.log(`[clean-vpn] tls: входящий TCP с ${ip}:${rp ?? '?'}`);
  /** @type {Buffer[]} */
  const chunks = [];
  let muxFinished = false;
  let incompleteLogged = false;
  const bytesFromPeer = () => Buffer.concat(chunks).length;
  const logMuxIncomplete = (reason) => {
    if (muxFinished || incompleteLogged) return;
    incompleteLogged = true;
    console.log(
      `[clean-vpn] tls mux: ${reason} ip=${ip} port=${rp ?? '?'} bytesFromPeer=${bytesFromPeer()}`,
    );
  };

  const helloTimer = setTimeout(() => {
    logMuxIncomplete('таймаут 60s ожидания полного ClientHello');
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
  }, 60000);
  helloTimer.unref?.();

  const onData = (c) => {
    if (tlsMuxDebugEnabled() && chunks.length === 0 && c.length) {
      const hex = Buffer.from(c).subarray(0, Math.min(32, c.length)).toString('hex');
      console.log(
        `[clean-vpn] tls mux debug: первый chunk от peer ip=${ip} port=${rp ?? '?'} len=${c.length} prefix=${hex}`,
      );
    }
    chunks.push(c);
    const buf = Buffer.concat(chunks);
    const p = parseFirstTlsClientHello(buf);
    if ('needMore' in p && p.needMore) return;
    clearTimeout(helloTimer);
    muxFinished = true;
    socket.off('data', onData);
    const fullBuf = Buffer.concat(chunks);
    if (!('ok' in p && p.ok)) {
      logTlsPassthrough(socket, p.reason || 'parse_fail', fullBuf);
      runTlsProbePassthrough(socket, fullBuf, ctx);
      return;
    }
    if (
      ctx.tlsPublicName &&
      !sniMatchesTlsPublicName(p.sni, ctx.tlsPublicName)
    ) {
      logTlsPassthrough(socket, 'sni_mismatch_public_name', fullBuf);
      runTlsProbePassthrough(socket, fullBuf, ctx);
      return;
    }
    const scannerLike = p.alpn.length === 0 && p.sni.length === 0;
    console.log(
      `[clean-vpn] tls: ClientHello ок (ALPN=${p.alpn.join(',') || '—'}; SNI=${p.sni.join(',') || '—'})${scannerLike ? ' [scanner-like]' : ''} → TLS server (HTTP/1.1 или HTTP/2 по ALPN)`,
    );
    tryLogExitTlsJa3(fullBuf, p, ctx);
    setImmediate(() => {
      try {
        try {
          socket.pause();
        } catch {
          /* ignore */
        }
        const alpnList = resolveTlsAlpnProtocols(ctx.tlsHttpVers ?? null).server;
        const negotiated = pickNegotiatedAlpn(p.alpn, alpnList);

        if (negotiated === 'h2') {
          wireExitHttp2VpnInjected(socket, fullBuf, ctx);
          return;
        }

        const tlsSock = new tls.TLSSocket(socket, {
          isServer: true,
          secureContext: ctx.tlsExitSecureContext,
          ALPNProtocols: alpnList,
          requestCert: false,
          handshakeTimeout: 60000,
        });
        tlsSock.once('secure', () => {
          const apRaw = tlsSock.alpnProtocol;
          const ap = apRaw === false ? '' : String(apRaw);
          const httpLabel = tlsAlpnToHttpLabel(ap);
          console.log(
            `[clean-vpn] tls: рукопожатие ip=${tlsClientIp(tlsSock)} port=${tlsSock.remotePort ?? '?'} http=${httpLabel} negotiated ALPN=${ap || '—'}`,
          );
          if (ap === 'h2') {
            console.error(
              '[clean-vpn] tls: после ручного TLS получен ALPN h2 (расхождение с предвыбором) — закрываем',
            );
            try {
              tlsSock.destroy();
            } catch {
              /* ignore */
            }
            return;
          }
          if (ap === 'http/1.1' || ap === '') {
            wireExitTlsSocket(tlsSock, ctx);
            return;
          }
          console.error(
            `[clean-vpn] tls: неподдерживаемый ALPN «${ap || '—'}» после рукопожатия — закрываем`,
          );
          try {
            tlsSock.destroy();
          } catch {
            /* ignore */
          }
        });
        tlsSock.on('error', (e) => {
          const code = /** @type {any} */ (e)?.code ?? '';
          const msg = e?.message || String(e);
          console.error(
            `[clean-vpn] tls handshake (ручной TLSSocket): ip=${tlsClientIp(socket)} code=${code || '—'} msg=${msg}`,
          );
          try {
            tlsSock.destroy();
          } catch {
            /* ignore */
          }
        });
        socket.unshift(fullBuf);
        try {
          socket.resume();
        } catch {
          /* ignore */
        }
      } catch (e) {
        console.error('[clean-vpn] tls: TLS server (inbound):', e?.message || e);
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }
    });
  };
  socket.on('data', onData);
  socket.once('error', (e) => {
    const code = /** @type {any} */ (e)?.code ?? '';
    const msg = e?.message || String(e);
    if (!muxFinished) {
      console.error(
        `[clean-vpn] tls mux: ошибка TCP до завершения разбора ClientHello ip=${ip} port=${rp ?? '?'} code=${code || '—'} msg=${msg}`,
      );
    }
    clearTimeout(helloTimer);
  });
  socket.once('close', (hadError) => {
    clearTimeout(helloTimer);
    logMuxIncomplete(`TCP закрыт до полного ClientHello hadError=${hadError}`);
  });
}

// =============================================================================
// === Общее: HTTP-преамбула для --type=socket | --type=http ===
// =============================================================================

function handleHttpSocket(sock, onReady) {
  const HTTP_PREAMBLE_COMPACT = 32768;
  const onData = (chunk) => {
    let base = sock.__httpBuf;
    if (base && base.byteOffset >= HTTP_PREAMBLE_COMPACT) {
      const c = Buffer.allocUnsafe(base.length);
      base.copy(c);
      base = c;
    }
    const buf =
      base == null
        ? Buffer.from(chunk)
        : (() => {
            const n = Buffer.allocUnsafe(base.length + chunk.length);
            base.copy(n, 0);
            chunk.copy(n, base.length);
            return n;
          })();
    const idx = buf.indexOf('\r\n\r\n');
    if (idx === -1) {
      sock.__httpBuf = buf;
      return;
    }
    const rest = buf.subarray(idx + 4);
    delete sock.__httpBuf;
    sock.off('data', onData);
    if (sock.__isServer) {
      const res =
        'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n';
      sock.write(res);
    }
    onReady(rest);
  };
  sock.on('data', onData);
}

/** Exit --type=ws-chrome: страница для Puppeteer (GET /clean-vpn-chrome). */
const WS_CHROME_BRIDGE_PAGE_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>clean-vpn-chrome</title></head><body>
<script>
(function () {
  var ws = new WebSocket((location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/');
  ws.binaryType = 'arraybuffer';
  ws.onopen = function () { if (window.cleanVpnWsReady) window.cleanVpnWsReady(); };
  ws.onmessage = function (ev) {
    var d = ev.data;
    if (d instanceof ArrayBuffer && window.cleanVpnBrowserToNode) {
      window.cleanVpnBrowserToNode(Array.from(new Uint8Array(d)));
    }
  };
  ws.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  ws.onerror = function () {};
  window.__cleanVpnSend = function (u8) {
    if (ws.readyState === WebSocket.OPEN) ws.send(u8);
  };
})();
</script></body></html>`;

/** На Linux arm64/arm предпочитаем системный Chromium — бандл из ~/.cache/puppeteer там часто x86_64 (chrome-linux64). */
function isLinuxArmHost() {
  return process.platform === 'linux' && (process.arch === 'arm64' || process.arch === 'arm');
}

function resolveLinuxArmSystemChromium() {
  if (!isLinuxArmHost()) return null;
  const candidates = [
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
    '/snap/bin/chromium',
  ];
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      /* ignore */
    }
  }
  for (const cmd of ['chromium', 'chromium-browser', 'google-chrome-stable']) {
    try {
      const out = execFileSync('sh', ['-c', `command -v ${cmd} 2>/dev/null || true`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      const p = out.split('\n')[0]?.trim();
      if (p && fs.existsSync(p)) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

/**
 * Аргументы запуска Chromium/Puppeteer (ARM/Radxa, sudo, headless).
 * @returns {string[]}
 */
function buildPuppeteerLaunchArgs() {
  const args = [
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
  ];
  if (
    process.env.CLEAN_VPN_PUPPETEER_NO_SANDBOX === '1' ||
    (typeof process.getuid === 'function' && process.getuid() === 0)
  ) {
    args.push('--no-sandbox', '--disable-setuid-sandbox');
  }
  if (process.env.CLEAN_VPN_PUPPETEER_EXTRA_ARGS) {
    for (const a of String(process.env.CLEAN_VPN_PUPPETEER_EXTRA_ARGS).split(/\s+/)) {
      if (a) args.push(a);
    }
  }
  return args;
}

/**
 * @param {'ws-chrome'|'rtc-chrome'} kind
 * @param {string|null|undefined} explicitPath
 * @param {import('puppeteer').PuppeteerNode} puppeteer
 * @returns {{ launchOpts: import('puppeteer').LaunchOptions, executablePath: string|null }}
 */
function buildPuppeteerLaunchOptions(kind, explicitPath, puppeteer) {
  const executablePath = resolvePuppeteerChromeExecutable(kind, explicitPath, puppeteer);
  const launchOpts = {
    headless: true,
    args: buildPuppeteerLaunchArgs(),
    timeout: 120000,
  };
  if (executablePath) launchOpts.executablePath = executablePath;
  return { launchOpts, executablePath };
}

/**
 * Puppeteer на ARM без системного Chromium часто берёт …/linux_arm-…/chrome-linux64/chrome (x64) → shell: Syntax error "(".
 * @param {'ws-chrome'|'rtc-chrome'} kind
 * @param {string|null|undefined} explicitPath
 * @param {import('puppeteer').PuppeteerNode} puppeteer
 * @returns {string|null}
 */
function resolvePuppeteerChromeExecutable(kind, explicitPath, puppeteer) {
  let executablePath = explicitPath || process.env.PUPPETEER_EXECUTABLE_PATH || null;
  if (!executablePath && isLinuxArmHost()) {
    const sys = resolveLinuxArmSystemChromium();
    if (sys) {
      executablePath = sys;
      console.log(`[clean-vpn] ${kind}: используем системный браузер ${sys}`);
    }
  }
  if (!executablePath && isLinuxArmHost()) {
    let bundled = '';
    try {
      bundled =
        typeof puppeteer.executablePath === 'function' ? puppeteer.executablePath() : '';
    } catch {
      /* ignore */
    }
    const extra =
      bundled && bundled.includes('chrome-linux64')
        ? `\nОбнаружен битый кэш Puppeteer: ${bundled}`
        : '';
    const flag = kind === 'rtc-chrome' ? '--rtc-chrome-executable' : '--ws-chrome-executable';
    throw new Error(
      `${kind}: на Linux ARM (Radxa и т.п.) нужен системный Chromium — встроенный Chrome из ~/.cache/puppeteer часто x86_64 и не запускается.${extra}

  sudo apt update && sudo apt install -y chromium
  # на старых образах: chromium-browser

  sudo env PATH=$PATH node scripts/clean-vpn.js ... ${flag}=/usr/bin/chromium
  # или: export PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

  rm -rf ~/.cache/puppeteer   # убрать битый x64-кэш

  При sudo node добавляются --no-sandbox; при необходимости: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
  См. https://pptr.dev/troubleshooting`,
    );
  }
  if (executablePath && isLinuxArmHost() && executablePath.includes('chrome-linux64')) {
    throw new Error(
      `${kind}: путь ${executablePath} — x64 Chrome на ARM; установите chromium из apt и укажите /usr/bin/chromium`,
    );
  }
  return executablePath;
}

/**
 * H-4: проверка secret в request.url локального 127.0.0.1 WS. `timingSafeEqual` для защиты от timing.
 * @param {import('http').IncomingMessage} request
 * @param {string} expectedSecret
 */
function localWsRequestHasSecret(request, expectedSecret) {
  if (!expectedSecret) return false;
  try {
    const url = String(request.url || '');
    const q = url.indexOf('?');
    if (q < 0) return false;
    const search = new URLSearchParams(url.slice(q + 1));
    const got = search.get('t') || '';
    const a = Buffer.from(String(got), 'utf8');
    const b = Buffer.from(String(expectedSecret), 'utf8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** Встроенная страница для режима CDP (медленный путь): один WS к exit + exposeFunction/evaluate на пакет. */
function buildWsChromeCdpEmbeddedPageHtml(wsUrl) {
  const u = JSON.stringify(wsUrl);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var ws = new WebSocket(${u});
  ws.binaryType = 'arraybuffer';
  ws.onopen = function () { window.cleanVpnWsReady(); };
  ws.onmessage = function (ev) {
    var d = ev.data;
    if (d instanceof ArrayBuffer) window.cleanVpnBrowserToNode(Array.from(new Uint8Array(d)));
  };
  ws.onclose = function () { window.cleanVpnWsClosed(); };
  ws.onerror = function () {};
  window.__cleanVpnSend = function (u8) {
    if (ws.readyState === WebSocket.OPEN) ws.send(u8);
  };
})();
</script></body></html>`;
}

/**
 * Два WebSocket: к exit и к локальному Node (127.0.0.1). Бинарные кадры 1:1; горячий путь без CDP.
 * @param {boolean} [lazyExitConnect] — local WS сразу; exit WS через __cleanVpnExitConnect (keep-alive).
 */
function buildWsChromeDualBridgePageHtml(wsUrl, localWsUrl, lazyExitConnect = false) {
  const u = JSON.stringify(wsUrl);
  const l = JSON.stringify(localWsUrl);
  if (!lazyExitConnect) {
    return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var OPEN = 1;
  var exitWs = new WebSocket(${u});
  var localWs = new WebSocket(${l});
  exitWs.binaryType = 'arraybuffer';
  localWs.binaryType = 'arraybuffer';
  var exitBuf = [];
  var localBuf = [];
  function flushToLocal() {
    while (exitBuf.length && localWs.readyState === OPEN) {
      localWs.send(exitBuf.shift());
    }
  }
  function flushToExit() {
    while (localBuf.length && exitWs.readyState === OPEN) {
      exitWs.send(localBuf.shift());
    }
  }
  exitWs.onopen = function () {
    flushToLocal();
    if (window.cleanVpnWsReady) window.cleanVpnWsReady();
  };
  localWs.onopen = function () {
    flushToExit();
  };
  exitWs.onmessage = function (ev) {
    var d = ev.data;
    if (localWs.readyState !== OPEN) {
      exitBuf.push(d);
      return;
    }
    localWs.send(d);
  };
  localWs.onmessage = function (ev) {
    var d = ev.data;
    if (exitWs.readyState !== OPEN) {
      localBuf.push(d);
      return;
    }
    exitWs.send(d);
  };
  exitWs.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  localWs.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  exitWs.onerror = function () {};
  localWs.onerror = function () {};
})();
</script></body></html>`;
  }
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var OPEN = 1;
  var exitWsUrl = ${u};
  var exitWs = null;
  var idleClosing = false;
  var localWs = new WebSocket(${l});
  localWs.binaryType = 'arraybuffer';
  var exitBuf = [];
  var localBuf = [];
  function flushToLocal() {
    while (exitBuf.length && localWs.readyState === OPEN) {
      localWs.send(exitBuf.shift());
    }
  }
  function flushToExit() {
    while (localBuf.length && exitWs && exitWs.readyState === OPEN) {
      exitWs.send(localBuf.shift());
    }
  }
  function wireExitWs() {
    if (!exitWs) return;
    exitWs.binaryType = 'arraybuffer';
    exitWs.onopen = function () {
      flushToExit();
      flushToLocal();
      if (window.cleanVpnWsReady) window.cleanVpnWsReady();
    };
    exitWs.onmessage = function (ev) {
      var d = ev.data;
      if (localWs.readyState !== OPEN) {
        exitBuf.push(d);
        return;
      }
      localWs.send(d);
    };
    exitWs.onclose = function () {
      if (idleClosing) return;
      if (window.cleanVpnWsClosed) window.cleanVpnWsClosed();
    };
    exitWs.onerror = function () {};
  }
  localWs.onopen = function () {
    flushToExit();
    flushToLocal();
  };
  localWs.onmessage = function (ev) {
    var d = ev.data;
    if (!exitWs || exitWs.readyState !== OPEN) {
      localBuf.push(d);
      return;
    }
    exitWs.send(d);
  };
  localWs.onclose = function () { if (window.cleanVpnWsClosed) window.cleanVpnWsClosed(); };
  localWs.onerror = function () {};
  window.__cleanVpnExitIdleTeardown = function () {
    idleClosing = true;
    if (exitWs) {
      try { exitWs.close(); } catch (e) {}
      exitWs = null;
    }
    localBuf.length = 0;
    exitBuf.length = 0;
    idleClosing = false;
  };
  window.__cleanVpnExitConnect = function () {
    idleClosing = false;
    if (exitWs) {
      try { exitWs.close(); } catch (e) {}
      exitWs = null;
    }
    exitWs = new WebSocket(exitWsUrl);
    wireExitWs();
  };
})();
</script></body></html>`;
}

/** page.exposeFunction сериализует Uint8Array в plain object {0:..,1:..}; Buffer.from(data) падает. */
function bufferFromPuppeteerExpose(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) return Buffer.from(data);
  if (data && typeof data === 'object') {
    const keys = Object.keys(data);
    if (keys.length === 0) return Buffer.alloc(0);
    const numeric = keys.filter((k) => /^\d+$/.test(k));
    if (numeric.length === keys.length && numeric.length > 0) {
      const len = numeric.length;
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) {
        out[i] = Number(data[String(i)]) & 0xff;
      }
      return out;
    }
  }
  throw new TypeError('ws-chrome: неподдерживаемый формат пакета из браузера');
}

/**
 * Долгоживущая сессия ws-chrome: Chrome + локальный WS; keep-alive рвёт только WS к exit.
 * @param {{
 *   wsUrl: string,
 *   useLocalBridge: boolean,
 *   executablePath?: string|null,
 *   pageMode: 'embedded'|'goto',
 *   gotoUrl?: string|null,
 *   lazyExitConnect?: boolean,
 * }} opts
 */
async function createWsChromeClientSession(opts) {
  if (!opts.useLocalBridge) {
    throw new Error('ws-chrome session: только useLocalBridge');
  }
  if (opts.pageMode === 'goto') {
    throw new Error('ws-chrome: локальный мост несовместим с pageMode goto');
  }
  const lazyExitConnect = !!opts.lazyExitConnect;

  const localWss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await awaitWebSocketServerListening(localWss);
  const ad = localWss.address();
  if (!ad || typeof ad === 'string') {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('ws-chrome: не удалось получить адрес локального WSS');
  }
  const localSecret = randomBytes(16).toString('hex');
  const localWsUrl = `ws://127.0.0.1:${ad.port}/?t=${localSecret}`;

  let puppeteerMod;
  try {
    puppeteerMod = await import('puppeteer');
  } catch (e) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('Для --type=ws-chrome установите: npm install puppeteer', { cause: e });
  }
  const puppeteer = puppeteerMod.default ?? puppeteerMod;
  const { launchOpts } = buildPuppeteerLaunchOptions('ws-chrome', opts.executablePath, puppeteer);
  console.log('[clean-vpn] ws-chrome: запуск Chromium…');

  let browser;
  try {
    browser = await puppeteer.launch(launchOpts);
  } catch (launchErr) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    const hint = `ws-chrome: не удалось запустить браузер (${launchErr?.message || launchErr}).
Частые причины на Linux ARM (Radxa, Multipass на Mac M*):
  sudo apt update && sudo apt install -y chromium
  sudo ... --ws-chrome-executable=/usr/bin/chromium
  rm -rf ~/.cache/puppeteer
При sudo node добавляются --no-sandbox; при необходимости: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
См. https://pptr.dev/troubleshooting`;
    throw new Error(hint, { cause: launchErr });
  }

  const page = await browser.newPage();
  const lifecycle = new EventEmitter();
  let bridgeWs = null;
  let exitWsReady = !lazyExitConnect;
  /** @type {Promise<import('ws').WebSocket>|null} */
  let exitConnectPromise = null;
  let exitConnectGen = 0;
  /** @type {number|null} */
  let exitConnectStartedMs = null;
  const EXIT_WS_CONNECT_TIMEOUT_MS = 30000;
  const EXIT_WS_CONNECT_STALE_MS = 25000;

  console.log('[clean-vpn] ws-chrome: локальный WS-мост 127.0.0.1 (данные не через CDP)');

  const bridgeWsPromise = new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('ws-chrome: таймаут подключения локального WS моста')),
      120000,
    );
    localWss.on('connection', (ws, request) => {
      if (!localWsRequestHasSecret(request, localSecret)) {
        console.warn('[clean-vpn] ws-chrome: локальный WS — отклонён без/с неверным ?t=… (H-4)');
        try {
          ws.close(1008, 'bad token');
        } catch {
          /* ignore */
        }
        try {
          request.socket?.destroy();
        } catch {
          /* ignore */
        }
        return;
      }
      if (bridgeWs) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        return;
      }
      clearTimeout(to);
      bridgeWs = ws;
      resolve(ws);
    });
  });

  await page.exposeFunction('cleanVpnWsReady', () => {
    lifecycle.emit('_chromeWsOpen');
  });
  await page.exposeFunction('cleanVpnWsClosed', () => {
    lifecycle.emit('close');
  });

  await page.setContent(
    buildWsChromeDualBridgePageHtml(opts.wsUrl, localWsUrl, lazyExitConnect),
    { waitUntil: 'domcontentloaded' },
  );

  await bridgeWsPromise;
  console.log('[clean-vpn] ws-chrome: Chrome подключился к локальному WS-мосту');

  const waitExitWsReady = (gen) =>
    new Promise((resolve, reject) => {
      const to = setTimeout(
        () => reject(new Error('ws-chrome: таймаут WebSocket к exit')),
        EXIT_WS_CONNECT_TIMEOUT_MS,
      );
      const done = () => clearTimeout(to);
      lifecycle.once('_chromeWsOpen', () => {
        if (gen !== exitConnectGen) {
          done();
          reject(new Error('ws-chrome: reconnect отменён'));
          return;
        }
        done();
        resolve(undefined);
      });
      lifecycle.once('close', () => {
        done();
        reject(new Error('ws-chrome: WebSocket к exit закрыт до готовности'));
      });
      lifecycle.once('_exitConnectAbort', () => {
        done();
        reject(new Error('ws-chrome: reconnect отменён'));
      });
    });

  const ensureExitWsReady = async () => {
    if (exitWsReady && bridgeWs && bridgeWs.readyState === WebSocket.OPEN) {
      return bridgeWs;
    }
    if (
      exitConnectPromise &&
      exitConnectStartedMs != null &&
      Date.now() - exitConnectStartedMs < EXIT_WS_CONNECT_STALE_MS
    ) {
      return exitConnectPromise;
    }
    if (exitConnectPromise) {
      exitConnectGen++;
      lifecycle.emit('_exitConnectAbort');
      exitConnectPromise = null;
      exitConnectStartedMs = null;
    }

    const gen = exitConnectGen;
    exitConnectStartedMs = Date.now();
    exitConnectPromise = (async () => {
      lifecycle.removeAllListeners('_chromeWsOpen');
      lifecycle.removeAllListeners('close');
      lifecycle.removeAllListeners('_exitConnectAbort');
      const readyWait = waitExitWsReady(gen);
      await page.evaluate(() => window.__cleanVpnExitConnect());
      await readyWait;
      if (gen !== exitConnectGen) {
        throw new Error('ws-chrome: reconnect отменён');
      }
      exitWsReady = true;
      exitConnectPromise = null;
      exitConnectStartedMs = null;
      console.log('[clean-vpn] ws-chrome: WebSocket к exit готов');
      return bridgeWs;
    })().catch((e) => {
      if (gen === exitConnectGen) {
        exitConnectPromise = null;
        exitConnectStartedMs = null;
        exitWsReady = false;
      }
      throw e;
    });

    return exitConnectPromise;
  };

  const idleExitTeardown = () => {
    exitConnectGen++;
    lifecycle.emit('_exitConnectAbort');
    exitWsReady = false;
    exitConnectPromise = null;
    exitConnectStartedMs = null;
    lifecycle.removeAllListeners('_chromeWsOpen');
    lifecycle.removeAllListeners('close');
    lifecycle.removeAllListeners('_exitConnectAbort');
    void page.evaluate(() => window.__cleanVpnExitIdleTeardown()).catch((e) => {
      console.warn('[clean-vpn] ws-chrome idle teardown:', e?.message || e);
    });
  };

  const close = async () => {
    idleExitTeardown();
    try {
      await browser.close();
    } catch {
      /* ignore */
    }
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
  };

  if (!lazyExitConnect) {
    await ensureExitWsReady();
  } else {
    console.log('[clean-vpn] ws-chrome: Chrome готов; WS к exit — по TCP SYN с TUN');
  }

  return {
    bridgeWs: /** @type {import('ws').WebSocket} */ (bridgeWs),
    browser,
    page,
    localWss,
    isExitWsReady: () => exitWsReady,
    ensureExitWsReady,
    idleExitTeardown,
    close,
  };
}

/**
 * Puppeteer: страница держит WebSocket к exit; мост с API как у `ws` для attachTunBridge.
 * @param {{
 *   wsUrl: string,
 *   useLocalBridge: boolean,
 *   executablePath?: string|null,
 *   pageMode: 'embedded'|'goto',
 *   gotoUrl?: string|null,
 * }} opts
 */
async function createWsChromeClientBridge(opts) {
  if (opts.useLocalBridge && opts.pageMode === 'goto') {
    throw new Error('ws-chrome: локальный мост несовместим с pageMode goto');
  }

  if (opts.useLocalBridge) {
    const session = await createWsChromeClientSession({ ...opts, lazyExitConnect: false });
    return {
      bridge: session.bridgeWs,
      browser: session.browser,
      page: session.page,
      localWss: session.localWss,
    };
  }

  let puppeteerMod;
  try {
    puppeteerMod = await import('puppeteer');
  } catch (e) {
    throw new Error('Для --type=ws-chrome установите: npm install puppeteer', { cause: e });
  }
  const puppeteer = puppeteerMod.default ?? puppeteerMod;
  const { launchOpts } = buildPuppeteerLaunchOptions('ws-chrome', opts.executablePath, puppeteer);
  console.log('[clean-vpn] ws-chrome: запуск Chromium…');
  let browser;
  try {
    browser = await puppeteer.launch(launchOpts);
  } catch (launchErr) {
    const hint = `ws-chrome: не удалось запустить браузер (${launchErr?.message || launchErr}).
Частые причины на Linux ARM (Radxa, Multipass на Mac M*):
  sudo apt update && sudo apt install -y chromium
  sudo ... --ws-chrome-executable=/usr/bin/chromium
  rm -rf ~/.cache/puppeteer
При sudo node добавляются --no-sandbox; при необходимости: CLEAN_VPN_PUPPETEER_NO_SANDBOX=1
См. https://pptr.dev/troubleshooting`;
    throw new Error(hint, { cause: launchErr });
  }
  const page = await browser.newPage();

  const bridge = new EventEmitter();

  await page.exposeFunction('cleanVpnBrowserToNode', (data) => {
    try {
      const buf = bufferFromPuppeteerExpose(data);
      bridge.emit('message', buf, true);
    } catch (err) {
      bridge.emit('error', err);
    }
  });
  await page.exposeFunction('cleanVpnWsReady', () => {
    bridge.emit('_chromeWsOpen');
  });
  await page.exposeFunction('cleanVpnWsClosed', () => {
    bridge.emit('close');
  });

  console.log('[clean-vpn] ws-chrome: данные через Puppeteer/CDP (медленный путь)');

  if (opts.pageMode === 'goto') {
    const url = opts.gotoUrl;
    if (!url) throw new Error('ws-chrome: пустой goto URL');
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 120000 });
  } else {
    await page.setContent(buildWsChromeCdpEmbeddedPageHtml(opts.wsUrl), {
      waitUntil: 'domcontentloaded',
    });
  }

  await new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('ws-chrome: таймаут WebSocket к exit')),
      120000,
    );
    bridge.once('_chromeWsOpen', () => {
      clearTimeout(to);
      resolve(undefined);
    });
    bridge.once('close', () => {
      clearTimeout(to);
      reject(new Error('ws-chrome: WebSocket закрыт до готовности'));
    });
  });

  bridge.send = (pkt) => {
    const bytes = Array.from(pkt);
    void page
      .evaluate((arr) => {
        if (typeof window.__cleanVpnSend === 'function') {
          window.__cleanVpnSend(new Uint8Array(arr));
        }
      }, bytes)
      .catch((e) => bridge.emit('error', e));
  };

  return { bridge, browser, page, localWss: null };
}

/**
 * Страница rtc-chrome: сигналинг WS + RTCPeerConnection + DataChannel + локальный WS к Node.
 */
function buildRtcChromeEmbeddedPageHtml(
  signalingWsUrl,
  localWsUrl,
  iceServers,
  iceTransportPolicy,
  allowHostCandidates,
  signalingPskBase64,
  signalingPskRequired,
) {
  const sig = JSON.stringify(signalingWsUrl);
  const loc = JSON.stringify(localWsUrl);
  const ice = JSON.stringify(iceServers);
  const pol = JSON.stringify(iceTransportPolicy);
  const allowHost = JSON.stringify(!!allowHostCandidates);
  const pskB64 = JSON.stringify(signalingPskBase64 || null);
  const pskReq = JSON.stringify(!!signalingPskRequired);
  const bindMsgType = JSON.stringify(SIGNALING_BIND_MSG_TYPE);
  const bindCtx = JSON.stringify(SIGNALING_BIND_CONTEXT);
  const bindWindowMs = JSON.stringify(SIGNALING_BIND_TS_WINDOW_MS);
  return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>
(function () {
  var OPEN = 1;
  var iceServers = ${ice};
  var iceTransportPolicy = ${pol};
  var allowHostCandidates = ${allowHost};
  var signalingPskBase64 = ${pskB64};
  var signalingPskRequired = ${pskReq};
  var BIND_MSG_TYPE = ${bindMsgType};
  var BIND_CTX = ${bindCtx};
  var BIND_TS_WINDOW_MS = ${bindWindowMs};
  // C-2: HMAC через Node (exposeFunction) — crypto.subtle недоступен в setContent (не secure context).
  async function signBind(fp, nonceHex, ts) {
    if (!signalingPskBase64) return null;
    if (typeof window.cleanVpnSignBind !== 'function') {
      if (window.cleanVpnRtcError) {
        window.cleanVpnRtcError('signBind: cleanVpnSignBind недоступен');
      }
      return null;
    }
    try {
      return await window.cleanVpnSignBind(fp, nonceHex, ts);
    } catch (e) {
      if (window.cleanVpnRtcError) {
        window.cleanVpnRtcError(String(e && e.message ? e.message : e));
      }
      return null;
    }
  }
  async function verifyBind(msg) {
    if (!signalingPskBase64) return 'no_key';
    if (typeof window.cleanVpnVerifyBind !== 'function') return 'no_bridge';
    try {
      var err = await window.cleanVpnVerifyBind(msg);
      return err || null;
    } catch (e) {
      return 'verify_err';
    }
  }
  function bufToHex(buf) {
    var v = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < v.length; i++) {
      var h = v[i].toString(16);
      if (h.length < 2) h = '0' + h;
      s += h;
    }
    return s;
  }
  function extractFp(sdp) {
    if (typeof sdp !== 'string') return null;
    var m = /^a=fingerprint:\\s*([^\\s]+)\\s+([0-9A-Fa-f:]+)\\s*$/m.exec(sdp);
    if (!m) return null;
    return m[1].toLowerCase() + ' ' + m[2].toUpperCase();
  }
  function fpEq(a, b) {
    if (!a || !b) return false;
    return String(a).trim().toLowerCase().replace(/\\s+/g, ' ') === String(b).trim().toLowerCase().replace(/\\s+/g, ' ');
  }
  function randomNonceHex() {
    var arr = new Uint8Array(8);
    crypto.getRandomValues(arr);
    return bufToHex(arr.buffer);
  }
  var expectedRemoteFp = null;
  var seenNonces = Object.create(null);
  // M-5 filter: drop typ host / typ prflx with private IPs (RFC1918 / loopback / link-local / IPv6 ULA)
  function parseIceCandidate(c) {
    if (!c) return null;
    var s = String(c).trim().replace(/^a=/i, '');
    var parts = s.split(/\\s+/);
    if (parts.length < 8) return null;
    var ti = parts.indexOf('typ');
    if (ti < 0 || ti + 1 >= parts.length) return null;
    return { ip: parts[4] || '', port: parts[5] || '', type: parts[ti + 1] || '' };
  }
  function isPrivateIp(ip) {
    if (!ip) return false;
    if (ip === '0.0.0.0' || ip === '::' || ip === '::1') return true;
    if (ip.indexOf('127.') === 0) return true;
    if (ip.indexOf('10.') === 0) return true;
    if (ip.indexOf('192.168.') === 0) return true;
    if (/^172\\.(1[6-9]|2[0-9]|3[01])\\./.test(ip)) return true;
    if (/^169\\.254\\./.test(ip)) return true;
    var lo = ip.toLowerCase();
    if (lo.indexOf('fc') === 0 || lo.indexOf('fd') === 0) return true;
    if (lo.indexOf('fe80:') === 0) return true;
    return false;
  }
  function shouldDropIce(c) {
    if (allowHostCandidates) return false;
    var f = parseIceCandidate(c);
    if (!f) return false;
    if (f.type === 'host' || f.type === 'prflx') return isPrivateIp(f.ip);
    return false;
  }
  var signalingWsUrl = ${sig};
  var localWs = new WebSocket(${loc});
  localWs.binaryType = 'arraybuffer';
  var sigWs = null;
  var pc = null;
  var vpnDc = null;
  var dcBuf = [];
  var localBuf = [];
  var didReady = false;
  var remoteOk = false;
  var candPend = [];
  var idleClosing = false;
  var webrtcUp = false;
  var sigHandleChain = Promise.resolve();

  function tryReady() {
    if (didReady) return;
    if (!vpnDc || vpnDc.readyState !== 'open') return;
    if (localWs.readyState !== OPEN) return;
    didReady = true;
    if (window.cleanVpnRtcReady) window.cleanVpnRtcReady();
  }

  function signalFatalClose() {
    if (window.cleanVpnRtcClosed) window.cleanVpnRtcClosed();
  }

  function webrtcTransportDown() {
    didReady = false;
    webrtcUp = false;
  }

  function flushDcToLocal() {
    while (dcBuf.length && localWs.readyState === OPEN && vpnDc && vpnDc.readyState === 'open') {
      localWs.send(dcBuf.shift());
    }
  }
  function flushLocalToDc() {
    while (localBuf.length && vpnDc && vpnDc.readyState === 'open') {
      try {
        vpnDc.send(localBuf.shift());
      } catch (e) {
        if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
        return;
      }
    }
  }

  function attachDcPipe() {
    if (!vpnDc) return;
    vpnDc.binaryType = 'arraybuffer';
    vpnDc.onopen = function () {
      flushLocalToDc();
      tryReady();
    };
    vpnDc.onmessage = function (ev) {
      var d = ev.data;
      if (localWs.readyState !== OPEN) {
        dcBuf.push(d);
        return;
      }
      localWs.send(d);
    };
    vpnDc.onclose = function () {
      if (idleClosing) {
        webrtcTransportDown();
        return;
      }
      signalFatalClose();
    };
    vpnDc.onerror = function () {};
    if (vpnDc.readyState === 'open') {
      flushLocalToDc();
      tryReady();
    }
  }

  localWs.onopen = function () {
    flushDcToLocal();
    tryReady();
  };
  localWs.onmessage = function (ev) {
    var d = ev.data;
    if (!vpnDc || vpnDc.readyState !== 'open') {
      localBuf.push(d);
      return;
    }
    try {
      vpnDc.send(d);
    } catch (e) {
      if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
    }
  };
  localWs.onclose = signalFatalClose;
  localWs.onerror = function () {};

  function flushCandPend() {
    if (!pc) return;
    var i;
    for (i = 0; i < candPend.length; i++) {
      var msg = candPend[i];
      if (!msg.candidate) continue;
      if (shouldDropIce(msg.candidate)) continue;
      pc.addIceCandidate({ candidate: msg.candidate, sdpMid: msg.mid || null }).catch(function () {});
    }
    candPend = [];
  }

  function rejectAndClose(reason) {
    if (window.cleanVpnRtcError) window.cleanVpnRtcError('signaling: ' + reason);
    try { if (sigWs) sigWs.close(1008, reason); } catch (e) {}
  }
  async function sendOwnBindForSdp(sdp) {
    if (!signalingPskBase64) {
      if (signalingPskRequired) {
        rejectAndClose('no_signaling_psk');
        return false;
      }
      return true;
    }
    var fp = extractFp(sdp);
    if (!fp) return true;
    var nonceHex = randomNonceHex();
    var ts = Date.now();
    var mac = await signBind(fp, nonceHex, ts);
    if (!mac) return true;
    if (sigWs && sigWs.readyState === OPEN) {
      sigWs.send(JSON.stringify({ type: BIND_MSG_TYPE, fingerprint: fp, nonce: nonceHex, ts: ts, mac: mac }));
    }
    return true;
  }
  async function handleSigMsg(msg) {
    if (!pc) return;
    try {
      if (msg.type === BIND_MSG_TYPE) {
        if (!signalingPskBase64) {
          if (signalingPskRequired) { rejectAndClose('no_psk'); return; }
          return;
        }
        var err = await verifyBind(msg);
        if (err) { rejectAndClose('bind_' + err); return; }
        if (seenNonces[msg.nonce]) { rejectAndClose('bind_nonce_replay'); return; }
        seenNonces[msg.nonce] = 1;
        expectedRemoteFp = msg.fingerprint;
        return;
      }
      if (msg.type === 'offer' || msg.type === 'answer') {
        if (signalingPskBase64) {
          if (!expectedRemoteFp) { rejectAndClose('bind_missing_before_sdp'); return; }
          var rfp = extractFp(msg.sdp);
          if (!fpEq(rfp, expectedRemoteFp)) { rejectAndClose('bind_sdp_fingerprint_mismatch'); return; }
        } else if (signalingPskRequired) {
          rejectAndClose('no_psk_for_sdp');
          return;
        }
      }
      if (msg.type === 'offer') {
        await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        remoteOk = true;
        flushCandPend();
        var ans = await pc.createAnswer();
        await pc.setLocalDescription(ans);
        if (!(await sendOwnBindForSdp(pc.localDescription.sdp))) return;
        if (sigWs && sigWs.readyState === OPEN) {
          sigWs.send(JSON.stringify({ type: 'answer', sdp: pc.localDescription.sdp }));
        }
      } else if (msg.type === 'answer') {
        await pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
        remoteOk = true;
        flushCandPend();
      } else if (msg.type === 'candidate') {
        if (!msg.candidate) return;
        if (shouldDropIce(msg.candidate)) return;
        if (!remoteOk) {
          candPend.push(msg);
          return;
        }
        await pc.addIceCandidate({ candidate: msg.candidate, sdpMid: msg.mid || null });
      }
    } catch (e) {
      if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
    }
  }

  function wireSigWsHandlers() {
    sigHandleChain = Promise.resolve();
    sigWs.onmessage = function (ev) {
      var msg;
      try {
        msg = JSON.parse(ev.data);
      } catch (e) {
        return;
      }
      sigHandleChain = sigHandleChain
        .then(function () { return handleSigMsg(msg); })
        .catch(function (e) {
          if (window.cleanVpnRtcError) {
            window.cleanVpnRtcError(String(e && e.message ? e.message : e));
          }
        });
    };
    sigWs.onclose = function () {
      if (idleClosing) {
        webrtcTransportDown();
        return;
      }
      signalFatalClose();
    };
    sigWs.onerror = function () {};
    sigWs.onopen = function () {
      try {
        sigWs.send(JSON.stringify({ type: 'clean-vpn-ready' }));
      } catch (e) {
        if (window.cleanVpnRtcError) window.cleanVpnRtcError(String(e && e.message ? e.message : e));
      }
    };
  }

  function teardownWebrtcOnly() {
    idleClosing = true;
    webrtcUp = false;
    didReady = false;
    remoteOk = false;
    try {
      if (vpnDc) {
        vpnDc.onclose = null;
        vpnDc.close();
      }
    } catch (e) {}
    try {
      if (pc) pc.close();
    } catch (e) {}
    try {
      if (sigWs) {
        sigWs.onclose = null;
        sigWs.close();
      }
    } catch (e) {}
    vpnDc = null;
    pc = null;
    sigWs = null;
    dcBuf = [];
    localBuf.length = 0;
    candPend = [];
    expectedRemoteFp = null;
    seenNonces = Object.create(null);
    sigHandleChain = Promise.resolve();
    idleClosing = false;
  }

  window.__cleanVpnRtcIdleTeardown = function () {
    teardownWebrtcOnly();
  };

  window.__cleanVpnRtcConnect = function () {
    teardownWebrtcOnly();
    webrtcUp = true;
    didReady = false;
    remoteOk = false;
    pc = new RTCPeerConnection({
      iceServers: iceServers,
      iceTransportPolicy: iceTransportPolicy,
      bundlePolicy: 'max-bundle',
    });
    pc.ondatachannel = function (ev) {
      var ch = ev.channel;
      if (ch.label !== 'clean-vpn') {
        try { ch.close(); } catch (e) {}
        return;
      }
      vpnDc = ch;
      attachDcPipe();
      tryReady();
    };
    pc.onicecandidate = function (e) {
      if (!e.candidate) return;
      if (!sigWs || sigWs.readyState !== OPEN) return;
      if (shouldDropIce(e.candidate.candidate)) return;
      try {
        sigWs.send(
          JSON.stringify({
            type: 'candidate',
            candidate: e.candidate.candidate,
            mid: e.candidate.sdpMid || '0',
          }),
        );
      } catch (err) {}
    };
    sigWs = new WebSocket(signalingWsUrl);
    wireSigWsHandlers();
  };
})();
</script></body></html>`;
}

/**
 * Долгоживущая сессия rtc-chrome: Chrome + локальный WS один раз; keep-alive рвёт только WebRTC к exit.
 * @param {{
 *   signalingWsUrl: string,
 *   iceServers: Array<{ urls: string|string[], username?: string, credential?: string }>,
 *   iceMode: string,
 *   executablePath?: string|null,
 *   signalingPsk?: Buffer|null,
 *   signalingPskBase64?: string|null,
 *   signalingPskRequired?: boolean,
 *   allowHostCandidates?: boolean,
 * }} opts
 */
async function createRtcChromeClientSession(opts) {
  const localWss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await awaitWebSocketServerListening(localWss);
  const ad = localWss.address();
  if (!ad || typeof ad === 'string') {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('rtc-chrome: не удалось получить адрес локального WSS');
  }
  const localSecret = randomBytes(16).toString('hex');
  const localWsUrl = `ws://127.0.0.1:${ad.port}/?t=${localSecret}`;

  let puppeteerMod;
  try {
    puppeteerMod = await import('puppeteer');
  } catch (e) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error('Для --type=rtc-chrome установите: npm install puppeteer', { cause: e });
  }
  const puppeteer = puppeteerMod.default ?? puppeteerMod;
  const { launchOpts } = buildPuppeteerLaunchOptions('rtc-chrome', opts.executablePath, puppeteer);
  console.log('[clean-vpn] rtc-chrome: запуск Chromium…');

  let browser;
  try {
    browser = await puppeteer.launch(launchOpts);
  } catch (launchErr) {
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
    throw new Error(
      `rtc-chrome: не удалось запустить браузер (${launchErr?.message || launchErr}). См. подсказки ws-chrome в шапке.`,
      { cause: launchErr },
    );
  }

  const page = await browser.newPage();
  page.on('pageerror', (err) => {
    console.error('[clean-vpn] rtc-chrome page error:', err?.message || err);
  });
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      console.error('[clean-vpn] rtc-chrome console:', msg.text());
    }
  });
  const lifecycle = new EventEmitter();
  let bridgeWs = null;
  let webrtcReady = false;
  /** @type {Promise<import('ws').WebSocket>|null} */
  let webrtcConnectPromise = null;
  let webrtcConnectGen = 0;
  /** @type {number|null} */
  let webrtcConnectStartedMs = null;
  const WEBRTC_CONNECT_TIMEOUT_MS = 45000;
  const WEBRTC_CONNECT_STALE_MS = 35000;

  console.log('[clean-vpn] rtc-chrome: Chrome запущен, локальный WS-мост 127.0.0.1');

  const bridgeWsPromise = new Promise((resolve, reject) => {
    const to = setTimeout(
      () => reject(new Error('rtc-chrome: таймаут локального WS моста')),
      180000,
    );
    localWss.on('connection', (ws, request) => {
      if (!localWsRequestHasSecret(request, localSecret)) {
        console.warn('[clean-vpn] rtc-chrome: локальный WS — отклонён без/с неверным ?t=… (H-4)');
        try {
          ws.close(1008, 'bad token');
        } catch {
          /* ignore */
        }
        try {
          request.socket?.destroy();
        } catch {
          /* ignore */
        }
        return;
      }
      if (bridgeWs) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        return;
      }
      clearTimeout(to);
      bridgeWs = ws;
      resolve(ws);
    });
  });

  await page.exposeFunction('cleanVpnRtcReady', () => {
    lifecycle.emit('_rtcReady');
  });
  await page.exposeFunction('cleanVpnRtcClosed', () => {
    lifecycle.emit('close');
  });
  await page.exposeFunction('cleanVpnRtcError', (msg) => {
    lifecycle.emit('error', new Error(String(msg)));
  });

  const pskBuf =
    opts.signalingPsk ||
    (opts.signalingPskBase64 ? Buffer.from(opts.signalingPskBase64, 'base64') : null);
  if (pskBuf?.length) {
    await page.exposeFunction('cleanVpnSignBind', (fp, nonceHex, ts) =>
      signSignalingBind(pskBuf, fp, nonceHex, ts),
    );
    await page.exposeFunction('cleanVpnVerifyBind', (msg) => verifySignalingBind(pskBuf, msg));
  }

  const iceTransportPolicy = opts.iceMode === 'relay' ? 'relay' : 'all';
  await page.setContent(
    buildRtcChromeEmbeddedPageHtml(
      opts.signalingWsUrl,
      localWsUrl,
      opts.iceServers,
      iceTransportPolicy,
      !!opts.allowHostCandidates,
      opts.signalingPskBase64 || null,
      !!opts.signalingPskRequired,
    ),
    { waitUntil: 'domcontentloaded' },
  );

  await bridgeWsPromise;
  console.log('[clean-vpn] rtc-chrome: Chrome подключился к локальному WS-мосту');

  const waitWebrtcReady = (gen) =>
    new Promise((resolve, reject) => {
      const to = setTimeout(
        () => reject(new Error('rtc-chrome: таймаут готовности WebRTC DataChannel')),
        WEBRTC_CONNECT_TIMEOUT_MS,
      );
      const done = () => clearTimeout(to);
      lifecycle.once('_rtcReady', () => {
        if (gen !== webrtcConnectGen) {
          done();
          reject(new Error('rtc-chrome: reconnect отменён'));
          return;
        }
        done();
        resolve(undefined);
      });
      lifecycle.once('close', () => {
        done();
        reject(new Error('rtc-chrome: локальный WS закрыт до готовности WebRTC'));
      });
      lifecycle.once('error', (err) => {
        done();
        reject(err);
      });
      lifecycle.once('_webrtcConnectAbort', () => {
        done();
        reject(new Error('rtc-chrome: reconnect отменён'));
      });
    });

  const ensureWebrtcReady = async () => {
    if (webrtcReady && bridgeWs && bridgeWs.readyState === WebSocket.OPEN) {
      return bridgeWs;
    }
    if (
      webrtcConnectPromise &&
      webrtcConnectStartedMs != null &&
      Date.now() - webrtcConnectStartedMs < WEBRTC_CONNECT_STALE_MS
    ) {
      return webrtcConnectPromise;
    }
    if (webrtcConnectPromise) {
      webrtcConnectGen++;
      lifecycle.emit('_webrtcConnectAbort');
      webrtcConnectPromise = null;
      webrtcConnectStartedMs = null;
    }

    const gen = webrtcConnectGen;
    webrtcConnectStartedMs = Date.now();
    webrtcConnectPromise = (async () => {
      lifecycle.removeAllListeners('_rtcReady');
      lifecycle.removeAllListeners('close');
      lifecycle.removeAllListeners('error');
      lifecycle.removeAllListeners('_webrtcConnectAbort');
      const readyWait = waitWebrtcReady(gen);
      await page.evaluate(() => window.__cleanVpnRtcConnect());
      await readyWait;
      if (gen !== webrtcConnectGen) {
        throw new Error('rtc-chrome: reconnect отменён');
      }
      webrtcReady = true;
      webrtcConnectPromise = null;
      webrtcConnectStartedMs = null;
      console.log('[clean-vpn] rtc-chrome: WebRTC DataChannel к exit готов');
      return bridgeWs;
    })().catch((e) => {
      if (gen === webrtcConnectGen) {
        webrtcConnectPromise = null;
        webrtcConnectStartedMs = null;
        webrtcReady = false;
      }
      throw e;
    });

    return webrtcConnectPromise;
  };

  const idleWebrtcTeardown = () => {
    webrtcConnectGen++;
    lifecycle.emit('_webrtcConnectAbort');
    webrtcReady = false;
    webrtcConnectPromise = null;
    webrtcConnectStartedMs = null;
    lifecycle.removeAllListeners('_rtcReady');
    lifecycle.removeAllListeners('close');
    lifecycle.removeAllListeners('error');
    lifecycle.removeAllListeners('_webrtcConnectAbort');
    void page.evaluate(() => window.__cleanVpnRtcIdleTeardown()).catch((e) => {
      console.warn('[clean-vpn] rtc-chrome idle teardown:', e?.message || e);
    });
  };

  const close = async () => {
    idleWebrtcTeardown();
    try {
      await browser.close();
    } catch {
      /* ignore */
    }
    try {
      localWss.close();
    } catch {
      /* ignore */
    }
  };

  return {
    bridgeWs: /** @type {import('ws').WebSocket} */ (bridgeWs),
    browser,
    page,
    localWss,
    isWebrtcReady: () => webrtcReady,
    ensureWebrtcReady,
    idleWebrtcTeardown,
    close,
  };
}

/** @deprecated используйте createRtcChromeClientSession */
async function createRtcChromeClientBridge(opts) {
  const session = await createRtcChromeClientSession(opts);
  await session.ensureWebrtcReady();
  return {
    bridge: session.bridgeWs,
    browser: session.browser,
    page: session.page,
    localWss: session.localWss,
  };
}

// =============================================================================
// === runExit: tun + NAT, затем ветки по --type ===
// =============================================================================

async function runExit({
  server,
  type,
  extIface,
  configPath,
  iceMode,
  quicCertsDir,
  quicExtCryptoKey,
  sharedHmacKey,
  tlsCertDir,
  tlsPublicName,
  tlsProbeTarget,
  tlsProbeMaxBytes,
  tlsProbeMaxSeconds,
  tlsProbeFullProxyPerIp,
  tlsServerName,
  tlsHttpVers,
  signaling,
  wsServer,
  punch,
  keepAliveSec,
  keepAliveReconnectCooldownSec,
  tlsLogJa3,
  ja3Verbose,
  allowHostCandidates,
  signalingPskRequired,
}) {
  const { host, port } = parseHostPort(server);
  const kaBridge = type === 'quic' || type === 'quic-ext' ? 0 : keepAliveSec ?? 0;
  const kaCooldown =
    type === 'quic' || type === 'quic-ext' ? 0 : keepAliveReconnectCooldownSec ?? 0;
  if (type === 'rtc-chrome') {
    throw new Error(
      '[clean-vpn] --type=rtc-chrome только для --role=client; на exit используйте --type=webrtc',
    );
  }
  const tunName = findFreeTunName();
  const { tun, name: ifname } = openTunNative(tunName);
  setupTunIp('exit', ifname);
  const nat = setupExitNat(ifname, extIface);

  /** @type {((exitCode?: number, reason?: string) => void) | null} */
  let shutdownFn = null;
  registerCleanVpnEmergencyShutdown(({ exitCode, reason }) => {
    if (shutdownFn) {
      shutdownFn(exitCode, reason);
      return;
    }
    safe(() => teardownExitNat(nat.tunName, nat.ext));
    safe(() => restoreExitSysctl(nat.prevIpForward));
    safe(() => tun.close());
    clearCleanVpnEmergencyShutdown();
    process.exit(exitCode);
  });

  /** @type {import('net').Socket|null} */
  let activeTcp = null;
  /** @type {import('ws').WebSocketServer|null} */
  let wss = null;
  /** @type {import('ws').WebSocket|null} */
  let exitOutboundWebsocket = null;
  /** @type {import('ws').WebSocket|null} */
  let exitWebrtcSigWs = null;
  /** @type {import('http').Server|null} */
  let httpChromeSrv = null;
  /** @type {import('net').Server|null} */
  let tcpSrv = null;
  /** @type {import('http2').Http2SecureServer|null} */
  let tlsExitHttp2Server = null;
  /** @type {import('dgram').Socket|null} */
  let udpSock = null;
  /** @type {import('ws').WebSocket|null} */
  let udpPunchLoopbackWs = null;
  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  /** @type {any} */
  let quicEndpoint = null;
  /** @type {any} */
  let quicSession = null;
  /** @type {any} */
  let quicExtServer = null;
  let shuttingDown = false;

  const attachInboundBridge = createInboundTunBridgeAttach(
    tun,
    BRIDGE_OPTS_EXIT,
    kaBridge,
    kaCooldown,
  );

  const startBridge = (sock, restBuf, transport) => {
    if (transport === 'tcp' && activeTcp && !activeTcp.destroyed) {
      if (activeTcp.readableEnded || activeTcp.writableEnded || activeTcp.writable === false) {
        resetTcpEndpoint(activeTcp);
      } else {
        void gracefulCloseTcpEndpoint(activeTcp);
      }
    }
    if (transport === 'tcp') activeTcp = sock;
    attachInboundBridge(transport, sock, () => {
      if (restBuf && restBuf.length && transport === 'tcp') {
        sock.emit('data', restBuf);
      }
    });
  };

  const shutdown = (exitCode = 0, reason = 'SIGINT') => {
    if (shuttingDown) return;
    shuttingDown = true;
    // Порядок закрытия: сигналинг/транспорт → QUIC → NAT/sysctl/tun → exit.
    safe(() => {
      if (webrtcPc) {
        webrtcPc.destroy();
        webrtcPc = null;
      }
    });
    safe(() => {
      if (udpPunchLoopbackWs) {
        try {
          udpPunchLoopbackWs.close();
        } catch {
          /* ignore */
        }
        udpPunchLoopbackWs = null;
      }
    });
    safe(() => {
      if (exitWebrtcSigWs) {
        exitWebrtcSigWs.close();
        exitWebrtcSigWs = null;
      }
    });
    safe(() => {
      if (exitOutboundWebsocket) {
        exitOutboundWebsocket.close();
        exitOutboundWebsocket = null;
      }
    });
    safe(() => {
      if (wss) {
        wss.close();
        wss = null;
      }
    });
    safe(() => {
      if (httpChromeSrv) {
        httpChromeSrv.close();
        httpChromeSrv = null;
      }
    });
    safe(() => {
      if (tcpSrv) {
        tcpSrv.close();
        tcpSrv = null;
      }
    });
    safe(() => {
      if (tlsExitHttp2Server) {
        try {
          tlsExitHttp2Server.close();
        } catch {
          /* ignore */
        }
        tlsExitHttp2Server = null;
      }
    });
    safe(() => {
      if (udpSock) {
        udpSock.close();
        udpSock = null;
      }
    });
    safe(() => {
      if (activeTcp && !activeTcp.destroyed) {
        activeTcp.destroy();
      }
    });
    safe(() => {
      if (quicSession) {
        quicSession.destroy();
        quicSession = null;
      }
    });
    safe(() => {
      if (quicEndpoint) {
        quicEndpoint.destroy();
        quicEndpoint = null;
      }
    });
    const finishExit = () => {
      teardownExitNat(nat.tunName, nat.ext);
      restoreExitSysctl(nat.prevIpForward);
      safe(() => tun.close());
      clearCleanVpnEmergencyShutdown();
      console.log(`[clean-vpn] exit: остановка (${reason})`);
      process.exit(exitCode);
    };
    let finishExitDeferred = false;
    safe(() => {
      if (quicExtServer) {
        const s = quicExtServer;
        quicExtServer = null;
        void s.stop({ isApp: true, force: true }).then(finishExit, finishExit);
        finishExitDeferred = true;
      }
    });
    if (finishExitDeferred) return;
    finishExit();
  };
  shutdownFn = shutdown;
  process.on('SIGINT', () => shutdown(0, 'SIGINT'));
  process.on('SIGTERM', () => shutdown(0, 'SIGTERM'));

  // --- runExit: --type=websocket ---
  if (type === 'websocket') {
    const wsListen = websocketVpnListens(wsServer);
    if (!wsListen) {
      assertOutboundWsHost(host, '--ws-server на стороне пира');
      const connectHost = net.isIP(host) === 0 ? await resolveHostToIpv4(host) : host;
      const url = `ws://${connectHost}:${port}/`;
      console.log(`[clean-vpn] exit WebSocket: исходящее подключение к ${url}`);
      if (kaBridge > 0) {
        console.log(
          `[clean-vpn] exit WebSocket: keep-alive ${kaBridge}s, TCP до первого IPv4 с TUN`,
        );
      }
      attachOutboundTunBridge(
        tun,
        'websocket',
        BRIDGE_OPTS_EXIT,
        async () => {
          exitOutboundWebsocket = new WebSocket(url);
          exitOutboundWebsocket.binaryType = 'nodebuffer';
          await new Promise((resolve, reject) => {
            exitOutboundWebsocket.once('open', resolve);
            exitOutboundWebsocket.once('error', reject);
          });
          console.log('[clean-vpn] exit WebSocket: соединение установлено');
          return exitOutboundWebsocket;
        },
        kaBridge,
        kaCooldown,
      );
      return;
    }
    wss = new WebSocketServer({ host, port });
    wss.on('listening', () => {
      console.log(
        `[clean-vpn] exit WebSocket (сервер) ws://${host === '0.0.0.0' ? '*' : host}:${port}/`,
      );
    });
    wss.on('connection', (ws) => {
      console.log('[clean-vpn] ws client connected');
      wss.clients.forEach((c) => {
        if (c !== ws) c.close();
      });
      attachInboundBridge('websocket', ws);
    });
    return;
  }

  // --- runExit: --type=ws-chrome (HTTP GET /clean-vpn-chrome + WebSocket upgrade на том же порту) ---
  if (type === 'ws-chrome') {
    if (!wsServer) {
      throw new Error(
        '[clean-vpn] exit ws-chrome: нужен флаг --ws-server (HTTP+WebSocket на --server); иначе используйте --type=websocket',
      );
    }
    const srv = http.createServer((req, res) => {
      if (
        req.method === 'GET' &&
        (req.url === '/clean-vpn-chrome' || req.url.startsWith('/clean-vpn-chrome?'))
      ) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(WS_CHROME_BRIDGE_PAGE_HTML);
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('clean-vpn ws-chrome: GET /clean-vpn-chrome');
    });
    wss = new WebSocketServer({ noServer: true });
    wss.on('connection', (ws) => {
      console.log('[clean-vpn] ws-chrome: WebSocket connected');
      wss.clients.forEach((c) => {
        if (c !== ws) c.close();
      });
      attachInboundBridge('websocket', ws);
    });
    srv.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });
    await new Promise((resolve, reject) => {
      srv.listen(port, host, () => resolve(undefined));
      srv.once('error', reject);
    });
    httpChromeSrv = srv;
    const h = host === '0.0.0.0' ? '*' : host;
    console.log(
      `[clean-vpn] exit ws-chrome http://${h}:${port}/clean-vpn-chrome + ws same port`,
    );
    return;
  }

  // --- runExit: --type=socket | --type=http | --type=transparent-tls ---
  if (type === 'socket' || type === 'http' || type === 'transparent-tls') {
    const ttlVpnSecretBuf =
      type === 'transparent-tls'
        ? ensureSharedHmacKey(
            resolveTlsCertsDir({ tlsCertDir, quicCertsDir }),
            sharedHmacKey,
            quicExtCryptoKey,
            { autoCreate: true, role: 'exit' },
          ).buffer
        : null;

    if (type === 'transparent-tls' && (!ttlVpnSecretBuf || ttlVpnSecretBuf.length < 8)) {
      throw new Error(
        '[clean-vpn] transparent-tls exit: нужен общий PSK (--tls-cert-dir с clean-vpn-hmac.key или --shared-hmac-key)',
      );
    }

    tcpSrv = net.createServer((sock) => {
      console.log('[clean-vpn] tcp connected', sock.remoteAddress);

      if (type === 'http') {
        sock.__isServer = true;
        handleHttpSocket(sock, (rest) => startBridge(sock, rest, 'tcp'));
        return;
      }
      if (type === 'transparent-tls') {
        const ttlPublicName = tlsPublicNamePrimary(tlsPublicName);
        if (!ttlPublicName) {
          throw new Error(
            '[clean-vpn] transparent-tls exit: --tls-public-name обязателен для enc-SNI HTTPS relay (BREAKING: обновите client и exit вместе)',
          );
        }
        peekDispatchExitTransparentTlsOrIpv4Sock(
          sock,
          /** @type {Buffer} */ (ttlVpnSecretBuf),
          ttlPublicName,
          startBridge,
          { tlsLogJa3: Boolean(tlsLogJa3), ja3Verbose: Boolean(ja3Verbose) },
        );
        return;
      }
      startBridge(sock, null, 'tcp');
    }).listen(port, host, () => {
      console.log(`[clean-vpn] exit ${type} listening ${host}:${port}`);
      if (
        type === 'transparent-tls' &&
        (Boolean(tlsLogJa3) || Boolean(ja3Verbose))
      ) {
        console.log(
          '[clean-vpn transparent-tls exit] JA3/JA4/SNI: логи по enc-SNI relay (ClientHello до/после restore к origin).\n[clean-vpn transparent-tls exit] Без `--tls-log-ja3` / `--ja3-verbose` на этой стороне логирования transparent-tls не будет.',
        );
      }
    });
    return;
  }

  // --- runExit: --type=combo-tls (enc-SNI relay + TLS mux одним listen TCP) ---
  if (type === 'combo-tls') {
    const comboPublicName = tlsPublicNamePrimary(tlsPublicName);
    if (!comboPublicName) {
      throw new Error(
        '[clean-vpn] combo-tls exit: --tls-public-name обязателен для enc-SNI HTTPS relay (BREAKING: обновите client и exit вместе)',
      );
    }
    if (tlsServerName) {
      console.warn(
        '[clean-vpn] --tls-server-name на exit не используется (только на client). Для цели passthrough задайте --tls-probe-target=host:port.',
      );
    }
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const creds = loadTlsServerCredentials(certsDir, {
      sanHosts: [tlsPublicName, host].filter(Boolean),
    });
    const ttlComboSecretBuf = ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
      autoCreate: true,
      role: 'exit',
    }).buffer;
    if (!ttlComboSecretBuf || ttlComboSecretBuf.length < 8) {
      throw new Error(
        '[clean-vpn] combo-tls exit: нужен общий PSK (--tls-cert-dir с clean-vpn-hmac.key или --shared-hmac-key)',
      );
    }
    const targetStr = tlsProbeTarget || DEFAULT_TLS_PROBE_TARGET;
    const { host: pHost, port: pPort } = parseHostPort(targetStr);
    const probeShortMaxBytes =
      tlsProbeMaxBytes != null && Number.isFinite(tlsProbeMaxBytes) && tlsProbeMaxBytes >= 0
        ? tlsProbeMaxBytes
        : DEFAULT_TLS_PROBE_MAX_BYTES;
    const probeMaxSeconds =
      tlsProbeMaxSeconds != null && Number.isFinite(tlsProbeMaxSeconds) && tlsProbeMaxSeconds > 0
        ? tlsProbeMaxSeconds
        : DEFAULT_TLS_PROBE_MAX_SECONDS;
    const probeFullProxyPerIp =
      tlsProbeFullProxyPerIp != null &&
      Number.isFinite(tlsProbeFullProxyPerIp) &&
      tlsProbeFullProxyPerIp >= 0
        ? tlsProbeFullProxyPerIp
        : DEFAULT_TLS_PROBE_FULL_PROXY_PER_IP;
    /** @type {Map<string, { day: number, fullCount: number }>} */
    const probeBudget = new Map();
    const tlsExitSecureContextCombo = tls.createSecureContext({
      cert: creds.cert,
      key: creds.key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ciphers: TLS_VPN_CIPHERS_1_3,
      ecdhCurve: TLS_VPN_ECDH_CURVES,
    });
    const vpnSecretCombo = ttlComboSecretBuf;
    if (tlsHttpVers === '1.1') {
      console.log(
        '[clean-vpn] tls: режим --http-vers=1.1 (принудительный HTTP/1.1, без h2)',
      );
    }
    const tlsAlpnOfferCombo = resolveTlsAlpnProtocols(tlsHttpVers ?? null).server;
    const tlsHttpModeCombo = tlsHttpVers === '1.1' ? 'force-1.1' : 'prefer-h2';
    tlsExitHttp2Server = http2.createSecureServer({
      allowHTTP1: false,
      cert: creds.cert,
      key: creds.key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ciphers: TLS_VPN_CIPHERS_1_3,
      ecdhCurve: TLS_VPN_ECDH_CURVES,
      ALPNProtocols: tlsAlpnOfferCombo,
      settings: resolveCleanVpnHttp2Settings(),
    });
    tlsExitHttp2Server.on('error', (err) => {
      console.error('[clean-vpn] tls HTTP/2 server:', err?.message || err);
    });
    const tlsCtxCombo = {
      startBridge,
      creds,
      tlsPublicName: tlsPublicName || null,
      probeTargetHost: pHost,
      probeTargetPort: pPort,
      probeShortMaxBytes,
      probeMaxSeconds,
      probeFullProxyPerIp,
      probeBudget,
      tlsExitSecureContext: tlsExitSecureContextCombo,
      vpnSecret: vpnSecretCombo,
      tlsHttpVers: tlsHttpVers ?? null,
      tlsExitHttp2Server,
      tlsLogJa3: Boolean(tlsLogJa3),
      ja3Verbose: Boolean(ja3Verbose),
    };
    const ttlLogOptsCombo = { tlsLogJa3: Boolean(tlsLogJa3), ja3Verbose: Boolean(ja3Verbose) };
    tcpSrv = net
      .createServer((sock) => {
        peekDispatchExitComboTlsSock(
          sock,
          ttlComboSecretBuf,
          comboPublicName,
          tlsCtxCombo,
          ttlLogOptsCombo,
        );
      })
      .listen(port, host, () => {
        console.log(
          `[clean-vpn] exit combo-tls ${host}:${port} (enc-SNI relay при SNI *.${comboPublicName}; иначе TLS mux: ${tlsHttpModeCombo}, ALPN ${tlsAlpnOfferCombo.join(',')}; probe → ${pHost}:${pPort})`,
        );
        if (Boolean(tlsLogJa3) || Boolean(ja3Verbose)) {
          console.log(
            '[clean-vpn combo-tls exit] JA3: по ветви tls — входящий ClientHello к mux (как --type=tls); по enc-SNI relay — см. `[clean-vpn transparent-tls exit]`. Включите `--tls-log-ja3` / `--ja3-verbose` на обеих сторонах.',
          );
        }
      });
    return;
  }

  // --- runExit: --type=tls ---
  if (isTlsLikeType(type)) {
    if (tlsServerName) {
      console.warn(
        '[clean-vpn] --tls-server-name на exit не используется (только на client). Для цели passthrough задайте --tls-probe-target=host:port.',
      );
    }
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const creds = loadTlsServerCredentials(certsDir, {
      sanHosts: [tlsPublicName, host].filter(Boolean),
    });
    const targetStr = tlsProbeTarget || DEFAULT_TLS_PROBE_TARGET;
    const { host: pHost, port: pPort } = parseHostPort(targetStr);
    const probeShortMaxBytes =
      tlsProbeMaxBytes != null && Number.isFinite(tlsProbeMaxBytes) && tlsProbeMaxBytes >= 0
        ? tlsProbeMaxBytes
        : DEFAULT_TLS_PROBE_MAX_BYTES;
    const probeMaxSeconds =
      tlsProbeMaxSeconds != null && Number.isFinite(tlsProbeMaxSeconds) && tlsProbeMaxSeconds > 0
        ? tlsProbeMaxSeconds
        : DEFAULT_TLS_PROBE_MAX_SECONDS;
    const probeFullProxyPerIp =
      tlsProbeFullProxyPerIp != null &&
      Number.isFinite(tlsProbeFullProxyPerIp) &&
      tlsProbeFullProxyPerIp >= 0
        ? tlsProbeFullProxyPerIp
        : DEFAULT_TLS_PROBE_FULL_PROXY_PER_IP;
    /** @type {Map<string, { day: number, fullCount: number }>} */
    const probeBudget = new Map();
    const tlsExitSecureContext = tls.createSecureContext({
      cert: creds.cert,
      key: creds.key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ciphers: TLS_VPN_CIPHERS_1_3,
      ecdhCurve: TLS_VPN_ECDH_CURVES,
    });
    const vpnSecret = ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
      autoCreate: true,
      role: 'exit',
    }).buffer;
    if (tlsHttpVers === '1.1') {
      console.log(
        '[clean-vpn] tls: режим --http-vers=1.1 (принудительный HTTP/1.1, без h2)',
      );
    }
    const tlsAlpnOffer = resolveTlsAlpnProtocols(tlsHttpVers ?? null).server;
    const tlsHttpMode = tlsHttpVers === '1.1' ? 'force-1.1' : 'prefer-h2';
    tlsExitHttp2Server = http2.createSecureServer({
      allowHTTP1: false,
      cert: creds.cert,
      key: creds.key,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ciphers: TLS_VPN_CIPHERS_1_3,
      ecdhCurve: TLS_VPN_ECDH_CURVES,
      ALPNProtocols: tlsAlpnOffer,
      settings: resolveCleanVpnHttp2Settings(),
    });
    tlsExitHttp2Server.on('error', (err) => {
      console.error('[clean-vpn] tls HTTP/2 server:', err?.message || err);
    });
    const tlsCtx = {
      startBridge,
      creds,
      tlsPublicName: tlsPublicName || null,
      probeTargetHost: pHost,
      probeTargetPort: pPort,
      probeShortMaxBytes,
      probeMaxSeconds,
      probeFullProxyPerIp,
      probeBudget,
      tlsExitSecureContext,
      vpnSecret,
      tlsHttpVers: tlsHttpVers ?? null,
      tlsExitHttp2Server,
      tlsLogJa3: Boolean(tlsLogJa3),
      ja3Verbose: Boolean(ja3Verbose),
    };
    tcpSrv = net
      .createServer((sock) => {
        handleTlsExitInbound(sock, tlsCtx);
      })
      .listen(port, host, () => {
        console.log(
          `[clean-vpn] exit TLS ${host}:${port} (TLS 1.3, tls-http=${tlsHttpMode}, ALPN ${tlsAlpnOffer.join(',')}; публичный SNI: ${tlsPublicName || '—'}; маршрутизация по HTTP + Bearer; probe → ${pHost}:${pPort}; short ≤${probeShortMaxBytes} B, ≤${probeMaxSeconds}s; full-proxy/(IP·сутки): ${probeFullProxyPerIp})`,
        );
      });
    return;
  }

  // --- runExit: --type=udp ---
  if (type === 'udp') {
    if (punch && !signaling) {
      throw new Error(
        '[clean-vpn] exit + --punch: поддерживается только вместе с --signaling (UDP + сигналинг ws://HOST:(PORT+1) в том же процессе).',
      );
    }
    const sigPort = port + 1;
    if (sigPort > 65535) {
      throw new Error('[clean-vpn] udp: PORT+1 для сигналинга выходит за 65535');
    }
    const iceForPunch = signaling && punch ? loadUdpPunchIceFromConfig(configPath, iceMode) : null;
    /** C-2 PSK для udp punch (только при signaling+punch). */
    const udpSigPsk =
      signaling && punch
        ? loadSignalingPskOrWarn(
            resolveTlsCertsDir({ tlsCertDir, quicCertsDir }),
            sharedHmacKey,
            quicExtCryptoKey,
            signalingPskRequired,
            'udp punch exit',
          )
        : null;

    if (signaling && punch) {
      udpSock = dgram.createSocket('udp4');
      udpSock.on('error', (err) => {
        console.error('[clean-vpn] udp socket error:', err.message);
      });
      await new Promise((resolve, reject) => {
        udpSock.once('error', reject);
        udpSock.bind(port, host, () => {
          udpSock.off('error', reject);
          resolve(undefined);
        });
      });
      const exitMappedReflexive = await discoverUdpPunchReflexive(
        udpSock,
        /** @type {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} */ (iceForPunch).ndcIceServers,
        4000,
        { fixedListenPort: true },
      );
      console.log(
        `[clean-vpn] exit UDP punch: reflexive ${exitMappedReflexive.address}:${exitMappedReflexive.port} (STUN до client)`,
      );
      console.log(
        `[clean-vpn] exit UDP ${host}:${port} + сигналинг (punch) ws://${host === '0.0.0.0' ? '*' : host}:${sigPort}/`,
      );
      wss = new WebSocketServer({ host, port: sigPort });
      await awaitWebSocketServerListening(wss);
      /** Inbox на remote client WS с момента connect (до relay wire). */
      /** @type {WeakMap<import('ws').WebSocket, ReturnType<typeof attachSignalingInbox>>} */
      const exitRemotePunchInboxes = new WeakMap();
      wss.on('connection', (ws) => {
        const ra = String(ws?._socket?.remoteAddress || '');
        if (!isWsRemoteLoopback(ra) && !exitRemotePunchInboxes.has(ws)) {
          exitRemotePunchInboxes.set(ws, attachSignalingInbox(ws));
        }
      });
      let exitUdpPunchStarted = false;
      attachRtcChromeSignalingRelay(wss, (remotePeerWs) => {
        const ra = String(remotePeerWs?._socket?.remoteAddress || '');
        if (isWsRemoteLoopback(ra)) {
          console.warn('[clean-vpn] exit UDP punch: onPaired без remote client — punch пропущен');
          return;
        }
        if (exitUdpPunchStarted) return;
        exitUdpPunchStarted = true;
        const punchInbox =
          exitRemotePunchInboxes.get(remotePeerWs) ?? attachSignalingInbox(remotePeerWs);
        if (process.env.CLEAN_VPN_UDP_PUNCH_DEBUG === '1') {
          console.warn(
            `[clean-vpn] exit UDP punch: сигналинг напрямую с ${ra} (server-side WS)`,
          );
        }
        void (async () => {
          try {
            console.log('[clean-vpn] exit UDP punch: client на сигналинге, hole punch…');
            const peerEp = await runUdpPunchAsPeer({
              udpSock,
              sigWs: remotePeerWs,
              sigInbox: punchInbox,
              ice: /** @type {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} */ (iceForPunch),
              logPrefix: 'exit',
              fixedListenPort: true,
              mappedReflexive: exitMappedReflexive,
              signalingPsk: udpSigPsk,
              signalingPskRequired: !!signalingPskRequired,
            });
            const udpEp = {
              sock: udpSock,
              peer: { address: peerEp.address, port: peerEp.port },
            };
            console.log(
              `[clean-vpn] exit UDP punch: зафиксирован пир ${peerEp.address}:${peerEp.port}`,
            );
            attachTunBridge(
              tun,
              'udp-server',
              udpEp,
              withKeepalive(BRIDGE_OPTS_EXIT, kaBridge, kaCooldown),
            );
          } catch (e) {
            console.error('[clean-vpn] exit UDP punch:', e?.message || e);
            punchInbox.detach();
            exitUdpPunchStarted = false;
          }
        })();
      });
      udpPunchLoopbackWs = new WebSocket(`ws://127.0.0.1:${sigPort}/`);
      await new Promise((resolve, reject) => {
        udpPunchLoopbackWs.once('open', resolve);
        udpPunchLoopbackWs.once('error', reject);
      });
      console.log(
        `[clean-vpn] exit UDP punch: слушаем UDP :${port}, сигналинг ws://*:${sigPort}/ — ждём client (--type=udp --punch)`,
      );
      return;
    }

    if (signaling && !punch) {
      udpSock = dgram.createSocket('udp4');
      udpSock.on('error', (err) => {
        console.error('[clean-vpn] udp socket error:', err.message);
      });
      await new Promise((resolve, reject) => {
        udpSock.once('error', reject);
        udpSock.bind(port, host, () => {
          udpSock.off('error', reject);
          resolve(undefined);
        });
      });
      wss = new WebSocketServer({ host, port: sigPort });
      await awaitWebSocketServerListening(wss);
      wss.on('connection', (ws) => {
        try {
          ws.close(1008, 'udp: сигналинг только с --punch');
        } catch {
          /* ignore */
        }
      });
      console.log(
        `[clean-vpn] exit UDP ${host}:${port} + сигналинг ws://${host === '0.0.0.0' ? '*' : host}:${sigPort}/ (ожидание пиров с --punch; без punch клиенты подключаются только по UDP)`,
      );
      const udpEp = { sock: udpSock, peer: undefined };
      attachTunBridge(tun, 'udp-server', udpEp, withKeepalive(BRIDGE_OPTS_EXIT, kaBridge, kaCooldown));
      return;
    }

    udpSock = dgram.createSocket('udp4');
    udpSock.on('error', (err) => {
      console.error('[clean-vpn] udp socket error:', err.message);
    });
    const udpEp = { sock: udpSock, peer: undefined };
    udpSock.bind(port, host, () => {
      console.log(`[clean-vpn] exit UDP ${host}:${port} (один peer по первому пакету)`);
    });
    attachTunBridge(tun, 'udp-server', udpEp, withKeepalive(BRIDGE_OPTS_EXIT, kaBridge, kaCooldown));
    return;
  }

  // --- runExit: --type=webrtc ---
  if (type === 'webrtc') {
    await ensureNodeDatachannelLoaded();
    const ice = loadWebrtcIceFromConfig(configPath, iceMode);
    const sigListen = webrtcSignalingListens(signaling);
    /** C-2: загрузить общий PSK для подписи сигналинга. */
    const certsDirSig = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const signalingPsk = loadSignalingPskOrWarn(
      certsDirSig,
      sharedHmacKey,
      quicExtCryptoKey,
      signalingPskRequired,
      'webrtc exit',
    );
    console.log(
      `[clean-vpn] webrtc exit: ICE mode=${ice.iceMode}, серверов=${ice.ndcIceServers.length}, конфиг=${ice.configPath}; сигналинг=${sigListen ? 'сервер' : 'клиент'}`,
    );
    for (const s of ice.ndcIceServers) {
      console.log(`[clean-vpn]   - ${s.replace(/:[^:@]+@/, ':***@')}`);
    }
    const exitWebrtcPcRef = {
      setActive(pc) {
        webrtcPc = pc;
      },
      clearIfStill(pc) {
        if (webrtcPc === pc) webrtcPc = null;
      },
    };
    if (sigListen) {
      wss = new WebSocketServer({ host, port });
      wss.on('listening', () => {
        console.log(
          `[clean-vpn] exit webrtc сигналинг (сервер) ws://${host === '0.0.0.0' ? '*' : host}:${port}/ (ждём clean-vpn-ready)`,
        );
      });
      wss.on('connection', (ws) => {
        wss.clients.forEach((c) => {
          if (c !== ws) c.close();
        });
        if (webrtcPc) {
          try {
            webrtcPc.destroy();
          } catch {
            /* ignore */
          }
          webrtcPc = null;
        }
        attachCleanVpnWebrtcExitSignaling(
          ws,
          tun,
          ice,
          exitWebrtcPcRef,
          withKeepalive(BRIDGE_OPTS_EXIT, kaBridge, kaCooldown),
          {
            allowHostCandidates,
            signalingPsk,
            signalingPskRequired: !!signalingPskRequired,
          },
        );
      });
      return;
    }
    assertOutboundWsHost(host, '--signaling на стороне пира или реальный HOST:PORT в --server');
    const connectHost = await resolveHostToIpv4(host);
    const url = `ws://${connectHost}:${port}/`;
    exitWebrtcSigWs = new WebSocket(url);
    await new Promise((resolve, reject) => {
      exitWebrtcSigWs.once('open', resolve);
      exitWebrtcSigWs.once('error', reject);
    });
    console.log('[clean-vpn] exit webrtc: исходящий сигналинг подключён');
    attachCleanVpnWebrtcExitSignaling(
      exitWebrtcSigWs,
      tun,
      ice,
      exitWebrtcPcRef,
      withKeepalive(BRIDGE_OPTS_EXIT, kaBridge, kaCooldown),
      {
        allowHostCandidates,
        signalingPsk,
        signalingPskRequired: !!signalingPskRequired,
      },
    );
    return;
  }

  // --- runExit: --type=quic (node:quic) ---
  if (type === 'quic') {
    assertQuicNodeVersion();
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir, {
      sanHosts: [tlsPublicName, host].filter(Boolean),
    });
    const keyObj = createPrivateKey(fs.readFileSync(tlsPaths.keyPath));
    const certBuf = fs.readFileSync(tlsPaths.certPath);
    const quicNs = await importNodeQuic();
    const listen = quicNs.listen ?? quicNs.default?.listen;
    if (typeof listen !== 'function') {
      throw new Error('node:quic: отсутствует listen()');
    }
    quicEndpoint = await listen(
      (session) => {
        try {
          if (quicSession) {
            quicSession.destroy();
          }
        } catch {
          /* ignore */
        }
        quicSession = session;
        let bidiAttached = false;
        session.onstream = (stream) => {
          if (stream.direction !== 'bidi') {
            try {
              stream.destroy();
            } catch {
              /* ignore */
            }
            return;
          }
          if (bidiAttached) {
            try {
              stream.destroy();
            } catch {
              /* ignore */
            }
            return;
          }
          bidiAttached = true;
          console.log('[clean-vpn] QUIC: входящий bidi stream');
          try {
            const sock = quicBidiToSocketLike(stream);
            startBridge(sock, null, 'tcp');
          } catch (e) {
            console.error('[clean-vpn] QUIC stream:', e?.message || e);
          }
        };
      },
      {
        endpoint: { address: `${host}:${port}` },
        alpn: QUIC_ALPN,
        keys: keyObj,
        certs: [certBuf],
      },
    );
    console.log(
      `[clean-vpn] exit QUIC UDP ${host}:${port} (ALPN ${QUIC_ALPN}, TLS из ${certsDir})`,
    );
    return;
  }

  // --- runExit: --type=quic-ext (@infisical/quic) ---
  if (type === 'quic-ext') {
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir, {
      sanHosts: [tlsPublicName, host].filter(Boolean),
    });
    const hmacKey = bufferToArrayBuffer(
      ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
        autoCreate: true,
        role: 'exit',
      }).buffer,
    );
    const logger = createQuicExtLogger();
    const { QUICServer, events } = await importQuicExt();
    quicExtServer = new QUICServer({
      crypto: {
        key: hmacKey,
        ops: { sign: quicExtSignHMAC, verify: quicExtVerifyHMAC },
      },
      config: {
        key: fs.readFileSync(tlsPaths.keyPath, 'utf8'),
        cert: fs.readFileSync(tlsPaths.certPath, 'utf8'),
        verifyPeer: false,
        applicationProtos: [QUIC_EXT_ALPN],
      },
      logger,
    });

    /** @type {any} */
    let quicExtServerConn = null;
    quicExtServer.addEventListener(events.EventQUICServerConnection.name, (evt) => {
      const connection = evt.detail;
      if (quicExtServerConn && quicExtServerConn !== connection) {
        void quicExtServerConn.stop({ isApp: true, force: true }).catch(() => {});
      }
      quicExtServerConn = connection;
      let bidiAttached = false;
      const onStream = (ev) => {
        const stream = ev.detail;
        if (stream.type !== 'bidi') return;
        if (bidiAttached) {
          void stream.destroy({ force: true });
          return;
        }
        bidiAttached = true;
        console.log('[clean-vpn] QUIC-EXT: входящий bidi stream');
        try {
          const sock = quicBidiToSocketLike(stream);
          startBridge(sock, null, 'tcp');
        } catch (e) {
          console.error('[clean-vpn] QUIC-EXT stream:', e?.message || e);
        }
      };
      connection.addEventListener(events.EventQUICConnectionStream.name, onStream);
      connection.addEventListener(
        events.EventQUICConnectionStopped.name,
        () => {
          connection.removeEventListener(events.EventQUICConnectionStream.name, onStream);
          if (quicExtServerConn === connection) quicExtServerConn = null;
        },
        { once: true },
      );
    });

    await quicExtServer.start({ host, port });
    console.log(
      `[clean-vpn] exit QUIC-EXT UDP ${host}:${port} (ALPN ${QUIC_EXT_ALPN}, @infisical/quic; TLS и ${SHARED_HMAC_FILE} в ${certsDir})`,
    );
    return;
  }

  throw new Error(`Неизвестный --type=${type}`);
}

// =============================================================================
// === runClient: tun + маршруты, затем ветки по --type ===
// =============================================================================

async function runClient({
  server,
  type,
  splitDefault,
  clientLanSubnet,
  transparentTlsLanBind,
  boringTlsHelper,
  boringTlsProfile,
  boringTlsClienthelloProfile,
  boringTlsJa3Strict,
  configPath,
  iceMode,
  quicCertsDir,
  quicExtCryptoKey,
  sharedHmacKey,
  tlsCertDir,
  tlsServerName,
  tlsClientSni,
  tlsPublicName,
  tlsHttpVers,
  wsChromeExecutable,
  wsChromeWsUrl,
  wsChromeUrl,
  wsChromeExitPage,
  wsChromeCdpData,
  rtcChromeExecutable,
  tunnelPeer,
  signaling,
  wsServer,
  punch,
  keepAliveSec,
  keepAliveReconnectCooldownSec,
  tlsLogJa3,
  ja3Verbose,
  allowHostCandidates,
  signalingPskRequired,
}) {
  const { host, port } = parseHostPort(server);
  const kaBridge = type === 'quic' || type === 'quic-ext' ? 0 : keepAliveSec ?? 0;
  const kaCooldown =
    type === 'quic' || type === 'quic-ext' ? 0 : keepAliveReconnectCooldownSec ?? 0;
  const wsListenCli = type === 'websocket' ? websocketVpnListens(wsServer) : false;
  const webrtcSigListenClient = type === 'webrtc' && webrtcSignalingListens(signaling);
  const rtcChromeSigListen = type === 'rtc-chrome' && webrtcSignalingListens(signaling);
  const udpSigListenClient = type === 'udp' && webrtcSignalingListens(signaling);
  const deferWsPeerBypass =
    type === 'websocket' && !tunnelPeer && wsListenCli && host === '0.0.0.0';
  const deferWebrtcPeerBypass =
    type === 'webrtc' && !tunnelPeer && webrtcSigListenClient && host === '0.0.0.0';
  const deferRtcChromeSigBypass =
    type === 'rtc-chrome' && !tunnelPeer && rtcChromeSigListen && host === '0.0.0.0';
  const deferUdpPeerBypass =
    type === 'udp' && !tunnelPeer && udpSigListenClient && host === '0.0.0.0';
  const routeHost =
    (type === 'websocket' && tunnelPeer) ||
    (type === 'webrtc' && tunnelPeer) ||
    (type === 'rtc-chrome' && tunnelPeer) ||
    (type === 'udp' && tunnelPeer)
      ? tunnelPeer
      : host;

  /** Outbound udp --punch: STUN до tun0/routes/iptables — иначе на части ARM/Linux dgram не получает ответ. */
  /** @type {{ udp: import('dgram').Socket, mappedReflexive: { address: string, port: number }, ice: Awaited<ReturnType<typeof loadWebrtcIceFromConfig>> } | null} */
  let udpPunchPrepared = null;
  if (type === 'udp' && punch && !udpSigListenClient) {
    console.log('[clean-vpn] UDP punch: STUN до поднятия TUN (чистый uplink)');
    const iceEarly = loadUdpPunchIceFromConfig(configPath, iceMode);
    const udpEarly = createUdpPunchSocket();
    udpEarly.on('error', (err) => {
      console.error('[clean-vpn] udp socket error:', err.message);
    });
    await bindUdpPunchClientAsync(udpEarly);
    const mappedReflexive = await discoverUdpPunchReflexive(udpEarly, iceEarly.ndcIceServers, 4000, {
      fixedListenPort: false,
    });
    console.log(
      `[clean-vpn] UDP punch (client): reflexive ${mappedReflexive.address}:${mappedReflexive.port} (STUN до TUN)`,
    );
    udpPunchPrepared = { udp: udpEarly, mappedReflexive, ice: iceEarly };
  }

  const tunName = findFreeTunName();
  const { tun, name: ifname } = openTunNative(tunName);
  setupTunIp('client', ifname);
  const deferSigBypass =
    deferWsPeerBypass || deferWebrtcPeerBypass || deferRtcChromeSigBypass || deferUdpPeerBypass;
  const deferPeerKindForSetup =
    deferWebrtcPeerBypass || deferRtcChromeSigBypass ? 'webrtc' : 'ws-listen';
  // ws-chrome + keep-alive: split-default сразу — иначе lazyConnect ждёт IPv4 с TUN, а маршрутов в TUN нет.
  // udp --punch / webrtc / rtc-chrome: STUN и сигналинг до поднятого туннеля — split-default откладываем.
  const deferSplitDefaultUntilTunnel =
    splitDefault &&
    (type === 'rtc-chrome' ||
      (type === 'ws-chrome' && kaBridge <= 0) ||
      (type === 'udp' && punch) ||
      (type === 'webrtc' && !webrtcSigListenClient));
  const routeCtx = await setupClientRoutesAsync(ifname, routeHost, splitDefault, {
    deferPeerBypass: deferSigBypass,
    deferPeerKind: deferPeerKindForSetup,
    websocketListenNoSplitDefault: type === 'websocket' && wsServer && !splitDefault,
    deferSplitDefault: deferSplitDefaultUntilTunnel,
    iceInfraBypass: splitDefault && clientNeedsIceInfraBypass(type, punch),
    configPath,
    iceMode,
  });

  /** @type {((exitCode?: number, reason?: string) => void) | null} */
  let shutdownFn = null;
  registerCleanVpnEmergencyShutdown(({ exitCode, reason }) => {
    if (shutdownFn) {
      shutdownFn(exitCode, reason);
      return;
    }
    safe(() => teardownClientRoutes(routeCtx));
    safe(() => tun.close());
    clearCleanVpnEmergencyShutdown();
    process.exit(exitCode);
  });

  if (clientLanSubnet && !(type === 'udp' && punch)) {
    setupClientLanGateway(routeCtx, clientLanSubnet);
  }

  /** @type {import('node-datachannel').PeerConnection|null} */
  let webrtcPc = null;
  /** @type {import('ws').WebSocket|null} */
  let webrtcSigWs = null;
  /** @type {any} */
  let quicClientSession = null;
  /** @type {any} */
  let quicExtClient = null;
  /** @type {import('tls').TLSSocket|null} */
  let tlsVpnSocket = null;
  /** @type {import('net').Server|null} */
  let ttlHttpsInterceptSrv = null;
  /** @type {import('net').Server|null} */
  let ttlHttpsInterceptLanSrv = null;
  /** @type {(() => void) | null} */
  let ttlHttpsRedirectUndo = null;
  /** @type {(() => void) | null} */
  let ttlPreroutingLanHttpsUndo = null;
  /** @type {(() => void) | null} */
  let ttlInputInterceptUndo = null;
  /** @type {any} */
  let wsChromeBrowser = null;
  /** @type {import('ws').WebSocketServer|null} */
  let wsChromeLocalWss = null;
  /** @type {import('ws').WebSocketServer|null} */
  let clientReverseWss = null;
  /** @type {import('ws').WebSocketServer|null} */
  let clientWebrtcSigWss = null;
  /** @type {import('ws').WebSocketServer|null} */
  let clientRtcChromeSigWss = null;
  /** @type {import('ws').WebSocketServer|null} */
  let clientUdpSigWss = null;
  /** @type {import('ws').WebSocket|null} */
  let clientUdpPunchLoopbackWs = null;

  let shuttingDown = false;
  const shutdown = (exitCode = 0, reason = 'SIGINT') => {
    if (shuttingDown) return;
    shuttingDown = true;
    // Порядок: WebRTC/QUIC client → сигналинг WSS → Puppeteer/quic-ext (async finish) → TLS → маршруты/tun.
    safe(() => {
      if (webrtcPc) {
        webrtcPc.destroy();
        webrtcPc = null;
      }
    });
    safe(() => {
      if (clientUdpPunchLoopbackWs) {
        try {
          clientUdpPunchLoopbackWs.close();
        } catch {
          /* ignore */
        }
        clientUdpPunchLoopbackWs = null;
      }
    });
    safe(() => {
      if (webrtcSigWs) {
        webrtcSigWs.close();
        webrtcSigWs = null;
      }
    });
    safe(() => {
      if (quicClientSession) {
        quicClientSession.destroy();
        quicClientSession = null;
      }
    });
    const finishClient = () => {
      teardownClientRoutes(routeCtx);
      safe(() => tun.close());
      clearCleanVpnEmergencyShutdown();
      console.log(`[clean-vpn] client: остановка (${reason})`);
      process.exit(exitCode);
    };
    safe(() => {
      if (clientUdpSigWss) {
        const w = clientUdpSigWss;
        clientUdpSigWss = null;
        safe(() => w.close());
      }
    });
    safe(() => {
      if (clientWebrtcSigWss) {
        const w = clientWebrtcSigWss;
        clientWebrtcSigWss = null;
        safe(() => w.close());
      }
    });
    safe(() => {
      if (clientRtcChromeSigWss) {
        const w = clientRtcChromeSigWss;
        clientRtcChromeSigWss = null;
        safe(() => w.close());
      }
    });
    safe(() => {
      if (clientReverseWss) {
        const w = clientReverseWss;
        clientReverseWss = null;
        safe(() => w.close());
      }
    });
    safe(() => {
      if (wsChromeLocalWss) {
        const w = wsChromeLocalWss;
        wsChromeLocalWss = null;
        safe(() => w.close());
      }
    });
    let finishClientDeferred = false;
    safe(() => {
      if (wsChromeBrowser) {
        const b = wsChromeBrowser;
        wsChromeBrowser = null;
        void b.close().then(finishClient, finishClient);
        finishClientDeferred = true;
      }
    });
    if (finishClientDeferred) return;
    safe(() => {
      if (ttlHttpsRedirectUndo) {
        try {
          ttlHttpsRedirectUndo();
        } catch (e) {
          console.warn('[clean-vpn] transparent-tls: откат iptables OUTPUT:', e?.message ?? e);
        }
        ttlHttpsRedirectUndo = null;
      }
    });
    safe(() => {
      if (ttlPreroutingLanHttpsUndo) {
        try {
          ttlPreroutingLanHttpsUndo();
        } catch (e) {
          console.warn('[clean-vpn] transparent-tls: откат iptables PREROUTING LAN 443:', e?.message ?? e);
        }
        ttlPreroutingLanHttpsUndo = null;
      }
    });
    safe(() => {
      if (ttlInputInterceptUndo) {
        try {
          ttlInputInterceptUndo();
        } catch (e) {
          console.warn('[clean-vpn] transparent-tls: откат iptables INPUT интерсепт:', e?.message ?? e);
        }
        ttlInputInterceptUndo = null;
      }
    });
    safe(() => {
      if (ttlHttpsInterceptLanSrv) {
        try {
          ttlHttpsInterceptLanSrv.close();
        } catch {
          /* ignore */
        }
        ttlHttpsInterceptLanSrv = null;
      }
    });
    safe(() => {
      if (ttlHttpsInterceptSrv) {
        try {
          ttlHttpsInterceptSrv.close();
        } catch {
          /* ignore */
        }
        ttlHttpsInterceptSrv = null;
      }
    });
    safe(() => {
      if (quicExtClient) {
        const c = quicExtClient;
        quicExtClient = null;
        void c.destroy({ isApp: true, force: true }).then(finishClient, finishClient);
        finishClientDeferred = true;
      }
    });
    if (finishClientDeferred) return;
    safe(() => {
      if (tlsVpnSocket) {
        tlsVpnSocket.destroy();
        tlsVpnSocket = null;
      }
    });
    finishClient();
  };
  shutdownFn = shutdown;
  process.on('SIGINT', () => shutdown(0, 'SIGINT'));
  process.on('SIGTERM', () => shutdown(0, 'SIGTERM'));

  const attachInboundBridge = createInboundTunBridgeAttach(
    tun,
    BRIDGE_OPTS_CLIENT,
    kaBridge,
    kaCooldown,
  );

  // --- runClient: --type=websocket ---
  if (type === 'websocket') {
    if (wsListenCli) {
      clientReverseWss = new WebSocketServer({ host, port });
      await awaitWebSocketServerListening(clientReverseWss);
      console.log(
        `[clean-vpn] client WebSocket (сервер) ws://${host === '0.0.0.0' ? '*' : host}:${port}/ (--ws-server)`,
      );
      clientReverseWss.on('connection', (w) => {
        console.log('[clean-vpn] client WebSocket: пир подключился');
        clientReverseWss.clients.forEach((c) => {
          if (c !== w) c.close();
        });
        w.binaryType = 'nodebuffer';
        if (deferWsPeerBypass && splitDefault) {
          try {
            const peerIp = normalizePeerIpv4(w._socket?.remoteAddress);
            addClientWsPeerBypass(routeCtx, peerIp);
          } catch (e) {
            console.warn('[clean-vpn] client ws bypass пира:', e?.message || e);
          }
        }
        attachInboundBridge('websocket', w);
      });
      return;
    }
    assertOutboundWsHost(host, '--ws-server');
    const url = `ws://${host}:${port}/`;
    if (kaBridge > 0) {
      console.log(
        `[clean-vpn] client WebSocket: keep-alive ${kaBridge}s, подключение к ${url} после первого IPv4 с TUN`,
      );
    }
    attachOutboundTunBridge(
      tun,
      'websocket',
      BRIDGE_OPTS_CLIENT,
      async () => {
        const ws = new WebSocket(url);
        ws.binaryType = 'nodebuffer';
        await new Promise((resolve, reject) => {
          ws.once('open', resolve);
          ws.once('error', reject);
        });
        console.log('[clean-vpn] WebSocket connected');
        return ws;
      },
      kaBridge,
      kaCooldown,
    );
    return;
  }

  // --- runClient: --type=ws-chrome (Puppeteer + WebSocket в Chrome) ---
  if (type === 'ws-chrome') {
    if (wsServer) {
      throw new Error(
        '[clean-vpn] client ws-chrome: флаг --ws-server не поддерживается (Chrome только подключается к exit)',
      );
    }
    const wsUrl = wsChromeWsUrl || `ws://${host}:${port}/`;
    const exe = wsChromeExecutable || process.env.PUPPETEER_EXECUTABLE_PATH || null;
    const forceCdp =
      process.env.CLEAN_VPN_WS_CHROME_CDP_DATA === '1' || wsChromeCdpData;
    const useLocalBridge = !forceCdp && !wsChromeUrl;

    let pageMode = 'embedded';
    /** @type {string|null} */
    let gotoUrl = null;
    if (wsChromeUrl) {
      pageMode = 'goto';
      gotoUrl = wsChromeUrl;
    } else if (wsChromeExitPage && forceCdp) {
      pageMode = 'goto';
      gotoUrl = `http://${host}:${port}/clean-vpn-chrome`;
    }

    const wsChromeOpts = {
      wsUrl,
      executablePath: exe,
      pageMode,
      gotoUrl,
      useLocalBridge,
    };
    const setupWsChromeBridgeHandlers = (bridge) => {
      bridge.on('close', () => {
        console.warn(
          '[clean-vpn] ws-chrome: мост закрыт (idle/пир/сеть); следующий пакет с TUN поднимет новый Chrome (дорого)',
        );
      });
      bridge.on('error', (e) => {
        console.error('[clean-vpn] ws-chrome:', e?.message || e);
      });
    };

    if (kaBridge > 0 && useLocalBridge) {
      console.log(
        `[clean-vpn] ws-chrome: keep-alive ${kaBridge}s — Chrome сразу; WS к exit по TCP SYN с TUN`,
      );
      const wsSession = await createWsChromeClientSession({
        ...wsChromeOpts,
        lazyExitConnect: true,
      });
      wsChromeBrowser = wsSession.browser;
      wsChromeLocalWss = wsSession.localWss;

      wsSession.bridgeWs.on('close', () => {
        console.error('[clean-vpn] ws-chrome: локальный WS закрыт (Chrome упал?)');
        shutdown();
      });
      wsSession.bridgeWs.on('error', (e) => {
        console.error('[clean-vpn] ws-chrome:', e?.message || e);
      });

      attachTunBridge(tun, 'websocket', wsSession.bridgeWs, {
        ...withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown),
        softKeepAliveIdleKeepsWire: true,
        softKeepAliveIdle: () => {
          console.log(
            `[clean-vpn] ws-chrome: keep-alive ${kaBridge}s — WS к exit сброшен, Chrome остаётся (reconnect: только TCP SYN)`,
          );
          wsSession.idleExitTeardown();
        },
        onTunOutbound: (pkt) => {
          if (wsSession.isExitWsReady()) return;
          if (!ipv4TriggersExitLazyConnect(pkt)) return;
          void wsSession
            .ensureExitWsReady()
            .then(() =>
              applyDeferredClientSplitDefault(routeCtx).catch((e) => {
                console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
              }),
            )
            .catch((e) => {
              console.error('[clean-vpn] ws-chrome: lazy WS reconnect:', e?.message || e);
            });
        },
        tunOutboundSendIf: (pkt) => wsSession.isExitWsReady() || ipv4TriggersExitLazyConnect(pkt),
        shouldCountKeepaliveActivity: () => wsSession.isExitWsReady(),
      });
      return;
    }

    if (kaBridge > 0) {
      console.log(
        `[clean-vpn] ws-chrome: keep-alive ${kaBridge}s — Chrome/WS к exit после первого IPv4 с TUN`,
      );
    }
    attachOutboundTunBridge(
      tun,
      'websocket',
      BRIDGE_OPTS_CLIENT,
      async () => {
        safe(() => {
          if (wsChromeBrowser) void wsChromeBrowser.close();
          wsChromeBrowser = null;
        });
        safe(() => {
          if (wsChromeLocalWss) {
            try {
              wsChromeLocalWss.close();
            } catch {
              /* ignore */
            }
            wsChromeLocalWss = null;
          }
        });
        const { bridge, browser, localWss } = await createWsChromeClientBridge(wsChromeOpts);
        wsChromeBrowser = browser;
        if (localWss) wsChromeLocalWss = localWss;
        setupWsChromeBridgeHandlers(bridge);
        void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
          console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
        });
        console.log('[clean-vpn] ws-chrome: готово (Puppeteer → WebSocket → exit)');
        return bridge;
      },
      kaBridge,
      kaCooldown,
    );
    return;
  }

  // --- runClient: --type=rtc-chrome (Puppeteer + WebRTC DC + локальный WS) ---
  if (type === 'rtc-chrome') {
    const ice = loadWebrtcBrowserIceFromConfig(configPath, iceMode);
    /** C-2: PSK для подписи сигналинга — прокидывается в Chrome через template literal. */
    const certsDirSig = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const signalingPsk = loadSignalingPskOrWarn(
      certsDirSig,
      sharedHmacKey,
      quicExtCryptoKey,
      signalingPskRequired,
      'rtc-chrome client',
    );
    console.log(
      `[clean-vpn] rtc-chrome client: ICE mode=${ice.iceMode}, конфиг=${ice.configPath}; сигналинг=${rtcChromeSigListen ? 'сервер+relay' : 'клиент'}`,
    );
    let signalingWsUrl = `ws://${host}:${port}/`;
    if (rtcChromeSigListen) {
      clientRtcChromeSigWss = new WebSocketServer({ host, port });
      attachRtcChromeSignalingRelay(clientRtcChromeSigWss, (exitSideWs) => {
        if (deferRtcChromeSigBypass && splitDefault) {
          try {
            const peerIp = normalizePeerIpv4(exitSideWs._socket?.remoteAddress);
            addClientWsPeerBypass(routeCtx, peerIp);
          } catch (e) {
            console.warn('[clean-vpn] rtc-chrome bypass пира:', e?.message || e);
          }
        }
      });
      await awaitWebSocketServerListening(clientRtcChromeSigWss);
      if (host === '0.0.0.0') {
        signalingWsUrl = `ws://127.0.0.1:${port}/`;
        console.warn(
          '[clean-vpn] rtc-chrome + --signaling: Chrome подключается к ws://127.0.0.1 (второй пир — exit webrtc на публичный IP этого порта)',
        );
      }
      console.log(
        `[clean-vpn] rtc-chrome: сигналинг (сервер) ws://${host === '0.0.0.0' ? '*' : host}:${port}/`,
      );
    }
    const exe = rtcChromeExecutable || process.env.PUPPETEER_EXECUTABLE_PATH || null;
    const rtcChromeOpts = {
      signalingWsUrl,
      iceServers: ice.iceServers,
      iceMode: ice.iceMode,
      executablePath: exe,
      allowHostCandidates: !!allowHostCandidates,
      signalingPsk,
      signalingPskBase64: signalingPsk ? signalingPsk.toString('base64') : null,
      signalingPskRequired: !!signalingPskRequired,
    };

    console.log('[clean-vpn] rtc-chrome: запуск Chrome (WebRTC к exit — отдельно, keep-alive не закрывает браузер)');
    const rtcSession = await createRtcChromeClientSession(rtcChromeOpts);
    wsChromeBrowser = rtcSession.browser;
    wsChromeLocalWss = rtcSession.localWss;

    rtcSession.bridgeWs.on('close', () => {
      console.error('[clean-vpn] rtc-chrome: локальный WS закрыт (Chrome упал?)');
      shutdown();
    });
    rtcSession.bridgeWs.on('error', (e) => {
      console.error('[clean-vpn] rtc-chrome:', e?.message || e);
    });

    attachTunBridge(tun, 'websocket', rtcSession.bridgeWs, {
      ...withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown),
      softKeepAliveIdleKeepsWire: true,
      softKeepAliveIdle: () => {
        console.log(
          `[clean-vpn] rtc-chrome: keep-alive ${kaBridge}s — WebRTC к exit сброшен, Chrome остаётся (reconnect: только TCP SYN)`,
        );
        rtcSession.idleWebrtcTeardown();
      },
      onTunOutbound: (pkt) => {
        if (rtcSession.isWebrtcReady()) return;
        if (!ipv4TriggersExitLazyConnect(pkt)) return;
        void rtcSession.ensureWebrtcReady().catch((e) => {
          console.error('[clean-vpn] rtc-chrome: lazy WebRTC reconnect:', e?.message || e);
        });
      },
      tunOutboundSendIf: (pkt) =>
        rtcSession.isWebrtcReady() || ipv4TriggersExitLazyConnect(pkt),
      shouldCountKeepaliveActivity: () => rtcSession.isWebrtcReady(),
    });

    void rtcSession
      .ensureWebrtcReady()
      .then(() => {
        void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
          console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
        });
        console.log('[clean-vpn] rtc-chrome: готово (Chrome WebRTC → exit webrtc, TUN ↔ localhost WS)');
      })
      .catch((e) => {
        console.error('[clean-vpn] rtc-chrome: начальный WebRTC connect:', e?.message || e);
      });
    console.log('[clean-vpn] rtc-chrome: TUN ↔ localhost WS активен; WebRTC к exit поднимается…');
    return;
  }

  // --- runClient: --type=udp ---
  if (type === 'udp') {
    const sigPort = port + 1;
    if (sigPort > 65535) {
      throw new Error('[clean-vpn] udp: PORT+1 для сигналинга выходит за 65535');
    }
    const iceForPunch = punch ? loadUdpPunchIceFromConfig(configPath, iceMode) : null;
    /** C-2 PSK для udp punch client. */
    const udpSigPsk =
      signaling && punch
        ? loadSignalingPskOrWarn(
            resolveTlsCertsDir({ tlsCertDir, quicCertsDir }),
            sharedHmacKey,
            quicExtCryptoKey,
            signalingPskRequired,
            'udp punch client (sig)',
          )
        : punch
          ? loadSignalingPskOrWarn(
              resolveTlsCertsDir({ tlsCertDir, quicCertsDir }),
              sharedHmacKey,
              quicExtCryptoKey,
              signalingPskRequired,
              'udp punch client',
            )
          : null;

    if (signaling && punch) {
      const udp = dgram.createSocket('udp4');
      udp.on('error', (err) => {
        console.error('[clean-vpn] udp socket error:', err.message);
      });
      await new Promise((resolve, reject) => {
        udp.once('error', reject);
        udp.bind(port, host, () => {
          udp.off('error', reject);
          resolve(undefined);
        });
      });
      clientUdpSigWss = new WebSocketServer({ host, port: sigPort });
      await awaitWebSocketServerListening(clientUdpSigWss);
      attachRtcChromeSignalingRelay(clientUdpSigWss, (peerWs) => {
        if (deferUdpPeerBypass && splitDefault) {
          try {
            const peerIp = normalizePeerIpv4(peerWs._socket?.remoteAddress);
            addClientWsPeerBypass(routeCtx, peerIp);
          } catch (e) {
            console.warn('[clean-vpn] udp punch bypass пира:', e?.message || e);
          }
        }
      });
      console.log(
        `[clean-vpn] client UDP ${host}:${port} + сигналинг (punch) ws://${host === '0.0.0.0' ? '*' : host}:${sigPort}/`,
      );
      clientUdpPunchLoopbackWs = new WebSocket(`ws://127.0.0.1:${sigPort}/`);
      await new Promise((resolve, reject) => {
        clientUdpPunchLoopbackWs.once('open', resolve);
        clientUdpPunchLoopbackWs.once('error', reject);
      });
      const clientSigInbox = attachSignalingInbox(clientUdpPunchLoopbackWs);
      const peerEp = await runUdpPunchAsPeer({
        udpSock: udp,
        sigWs: /** @type {import('ws').WebSocket} */ (clientUdpPunchLoopbackWs),
        sigInbox: clientSigInbox,
        ice: /** @type {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} */ (iceForPunch),
        logPrefix: 'client',
        signalingPsk: udpSigPsk,
        signalingPskRequired: !!signalingPskRequired,
      });
      await new Promise((resolve, reject) => {
        udp.once('error', reject);
        udp.connect(peerEp.port, peerEp.address, () => {
          udp.off('error', reject);
          console.log(`[clean-vpn] UDP punch: соединение с пиром ${peerEp.address}:${peerEp.port}`);
          resolve(undefined);
        });
      });
      void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
        console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
      });
      attachTunBridge(tun, 'udp-client', udp, withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown));
      return;
    }

    if (signaling && !punch) {
      throw new Error(
        '[clean-vpn] client udp: --signaling без --punch не поддерживается (TUN требует соединённый UDP); уберите --signaling или добавьте --punch.',
      );
    }

    if (punch) {
      const udp = udpPunchPrepared?.udp ?? createUdpPunchSocket();
      if (!udpPunchPrepared) {
        udp.on('error', (err) => {
          console.error('[clean-vpn] udp socket error:', err.message);
        });
        await bindUdpPunchClientAsync(udp);
      }
      const ice =
        udpPunchPrepared?.ice ??
        /** @type {Awaited<ReturnType<typeof loadWebrtcIceFromConfig>>} */ (iceForPunch);
      const mappedReflexive =
        udpPunchPrepared?.mappedReflexive ??
        (await discoverUdpPunchReflexive(udp, ice.ndcIceServers, 4000, {
          fixedListenPort: false,
        }));
      if (!udpPunchPrepared) {
        console.log(
          `[clean-vpn] UDP punch (client): reflexive ${mappedReflexive.address}:${mappedReflexive.port} (STUN)`,
        );
      }
      const connectHost = await resolveHostToIpv4(host);
      const sigUrl = `ws://${connectHost}:${sigPort}/`;
      console.log(`[clean-vpn] UDP punch: сигналинг ${sigUrl}`);
      const sigWs = new WebSocket(sigUrl);
      await new Promise((resolve, reject) => {
        sigWs.once('open', resolve);
        sigWs.once('error', reject);
      });
      const clientSigInbox = attachSignalingInbox(sigWs);
      const peerEp = await runUdpPunchAsPeer({
        udpSock: udp,
        sigWs,
        sigInbox: clientSigInbox,
        ice,
        logPrefix: 'client',
        mappedReflexive,
        signalingPsk: udpSigPsk,
        signalingPskRequired: !!signalingPskRequired,
      });
      await new Promise((resolve, reject) => {
        udp.once('error', reject);
        udp.connect(peerEp.port, peerEp.address, () => {
          udp.off('error', reject);
          console.log(`[clean-vpn] UDP punch: «connected» к ${peerEp.address}:${peerEp.port}`);
          resolve(undefined);
        });
      });
      void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
        console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
      });
      if (clientLanSubnet) {
        setupClientLanGateway(routeCtx, clientLanSubnet);
      }
      attachTunBridge(tun, 'udp-client', udp, withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown));
      return;
    }

    attachOutboundTunBridge(
      tun,
      'udp-client',
      BRIDGE_OPTS_CLIENT,
      async () => {
        const udp = dgram.createSocket('udp4');
        await new Promise((resolve, reject) => {
          udp.once('error', reject);
          udp.connect(port, host, () => {
            udp.off('error', reject);
            console.log(`[clean-vpn] UDP «connected» к ${host}:${port}`);
            resolve(undefined);
          });
        });
        return udp;
      },
      kaBridge,
      kaCooldown,
    );
    return;
  }

  // --- runClient: --type=webrtc ---
  if (type === 'webrtc') {
    await ensureNodeDatachannelLoaded();
    const ice = loadWebrtcIceFromConfig(configPath, iceMode);
    /** C-2: PSK для подписи сигналинга. */
    const certsDirSig = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const signalingPsk = loadSignalingPskOrWarn(
      certsDirSig,
      sharedHmacKey,
      quicExtCryptoKey,
      signalingPskRequired,
      'webrtc client',
    );
    console.log(
      `[clean-vpn] webrtc client: ICE mode=${ice.iceMode}, конфиг=${ice.configPath}; сигналинг=${webrtcSigListenClient ? 'сервер' : 'клиент'}`,
    );
    const cliWebrtcPcRef = {
      setActive(pc) {
        webrtcPc = pc;
      },
      clearIfStill(pc) {
        if (webrtcPc === pc) webrtcPc = null;
      },
    };
    const sigIceOpts = {
      allowHostCandidates,
      signalingPsk,
      signalingPskRequired: !!signalingPskRequired,
      routeCtx,
    };
    if (webrtcSigListenClient) {
      clientWebrtcSigWss = new WebSocketServer({ host, port });
      await awaitWebSocketServerListening(clientWebrtcSigWss);
      console.log(
        `[clean-vpn] webrtc client: сигналинг (сервер) ws://${host === '0.0.0.0' ? '*' : host}:${port}/`,
      );
      const ws = await new Promise((resolve, reject) => {
        clientWebrtcSigWss.once('connection', (w) => {
          console.log('[clean-vpn] webrtc client: пир сигналинга подключился');
          clientWebrtcSigWss.clients.forEach((c) => {
            if (c !== w) c.close();
          });
          resolve(w);
        });
        clientWebrtcSigWss.once('error', reject);
      });
      if (deferWebrtcPeerBypass && splitDefault) {
        const peerIp = normalizePeerIpv4(ws._socket?.remoteAddress);
        addClientWsPeerBypass(routeCtx, peerIp);
      }
      await ensureClientInfraBypass(routeCtx, routeCtx.iceConfigPath, routeCtx.iceMode);
      attachCleanVpnWebrtcClientSignaling(
        ws,
        tun,
        ice,
        cliWebrtcPcRef,
        {
          ...withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown),
          eagerWireOnStart: deferSplitDefaultUntilTunnel,
        },
        {
          ...sigIceOpts,
          onWireReady: () => {
            void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
              console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
            });
          },
        },
      );
      return;
    }
    assertOutboundWsHost(host, '--signaling');
    const url = `ws://${host}:${port}/`;
    webrtcSigWs = new WebSocket(url);
    await new Promise((resolve, reject) => {
      webrtcSigWs.once('open', resolve);
      webrtcSigWs.once('error', reject);
    });
    console.log('[clean-vpn] WebRTC сигналинг подключён');
    await ensureClientInfraBypass(routeCtx, routeCtx.iceConfigPath, routeCtx.iceMode);
    attachCleanVpnWebrtcClientSignaling(
      webrtcSigWs,
      tun,
      ice,
      cliWebrtcPcRef,
      {
        ...withKeepalive(BRIDGE_OPTS_CLIENT, kaBridge, kaCooldown),
        eagerWireOnStart: deferSplitDefaultUntilTunnel,
      },
      {
        ...sigIceOpts,
        onWireReady: () => {
          void applyDeferredClientSplitDefault(routeCtx).catch((e) => {
            console.error('[clean-vpn] split-default / infra bypass:', e?.message || e);
          });
        },
      },
    );
    return;
  }

  // --- runClient: --type=quic (node:quic) ---
  if (type === 'quic') {
    assertQuicNodeVersion();
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const caBuf = fs.readFileSync(tlsPaths.caPath);
    const connectHost = await resolveHostToIpv4(host);
    const quicNs = await importNodeQuic();
    const connect = quicNs.connect ?? quicNs.default?.connect;
    if (typeof connect !== 'function') {
      throw new Error('node:quic: отсутствует connect()');
    }
    quicClientSession = await connect(`${connectHost}:${port}`, {
      alpn: QUIC_ALPN,
      ca: caBuf,
      sni: 'clean-vpn',
    });
    console.log('[clean-vpn] QUIC session установлена');
    const stream = await quicClientSession.createBidirectionalStream();
    const sock = quicBidiToSocketLike(stream);
    attachTunBridge(tun, 'tcp', sock, { ...BRIDGE_OPTS_CLIENT, tcpWireRole: 'client' });
    return;
  }

  // --- runClient: --type=quic-ext (@infisical/quic) ---
  if (type === 'quic-ext') {
    const certsDir = quicCertsDir ? path.resolve(quicCertsDir) : DEFAULT_QUIC_CERTS_DIR;
    const tlsPaths = ensureQuicCerts(certsDir);
    const logger = createQuicExtLogger();
    const { QUICClient } = await importQuicExt();
    const connectHost = await resolveHostToIpv4(host);
    quicExtClient = await QUICClient.createQUICClient({
      host: connectHost,
      port,
      serverName: 'clean-vpn',
      crypto: { ops: { randomBytes: quicExtRandomBytes } },
      config: {
        ca: fs.readFileSync(tlsPaths.caPath, 'utf8'),
        verifyPeer: true,
        applicationProtos: [QUIC_EXT_ALPN],
      },
      logger,
    });
    console.log('[clean-vpn] QUIC-EXT (@infisical/quic) соединение установлено');
    const stream = quicExtClient.connection.newStream('bidi');
    const sock = quicBidiToSocketLike(stream);
    attachTunBridge(tun, 'tcp', sock, { ...BRIDGE_OPTS_CLIENT, tcpWireRole: 'client' });
    return;
  }

  // --- runClient: --type=tls | --type=boring-tls ---
  if (isTlsLikeType(type)) {
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const ca = loadTlsClientCaPem(certsDir);
    const verifyName = resolveTlsClientCertVerifyName({
      tlsServerName,
      tlsPublicName,
      host,
      certsDir,
    });
    const clientHelloSni = resolveTlsClientHelloSni({ tlsClientSni, verifyName });
    if (type === 'boring-tls') {
      console.log(
        '[clean-vpn] boring-tls: TLS через boring-tls-helper (BoringSSL), см. scripts/boring-tls-plan.md',
      );
    }
    if (tlsHttpVers === '1.1') {
      console.log(
        '[clean-vpn] tls: режим --http-vers=1.1 (принудительный HTTP/1.1, без h2)',
      );
    }
    if (type === 'tls' && tlsLogJa3) {
      console.log(
        '[clean-vpn] tls ja3: для `--type=tls` отпечаток ClientHello в этом процессе не считается; на exit включите `--tls-log-ja3` / `CLEAN_VPN_TLS_LOG_JA3=1`, либо на клиенте используйте `--type=boring-tls` (stderr helper).',
      );
    }
    const vpnSecret = ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
      autoCreate: false,
      role: 'client',
    }).buffer;
    const tlsConnectOpts = {
      host,
      port,
      ca,
      servername: clientHelloSni,
      verifyServername: verifyName,
      vpnSecret,
      tlsHttpVers: tlsHttpVers ?? null,
      tlsLogJa3: Boolean(tlsLogJa3),
      ja3Verbose: Boolean(ja3Verbose),
      ...(type === 'boring-tls'
        ? {
            boringTlsHelperPath: boringTlsHelper,
            boringTlsProfile: boringTlsProfile,
            boringTlsClienthelloProfilePath: boringTlsClienthelloProfile || null,
            boringTlsJa3Strict: Boolean(boringTlsJa3Strict),
          }
        : {}),
    };
    const connectTlsVpn =
      type === 'boring-tls' ? connectCleanVpnBoringTlsClient : connectCleanVpnTlsClient;
    if (tlsLogBearerEnabled() && kaBridge > 0) {
      console.log(
        `[clean-vpn] tls-log-bearer: --keep-alive=${kaBridge} — Bearer/exporter в логах после первого connect (TCP SYN/DNS или eager при ka=0)`,
      );
    }
    attachOutboundTunBridge(
      tun,
      'tcp',
      BRIDGE_OPTS_CLIENT,
      async () => {
        const sock = await connectTlsVpn(tlsConnectOpts);
        tlsVpnSocket = sock;
        return sock;
      },
      kaBridge,
      kaCooldown,
      shouldEagerOutboundTunConnect(type, splitDefault, kaBridge),
    );
    return;
  }

  // --- runClient: --type=combo-tls (TUN через boring-tls + HTTPS :443 как transparent-tls) ---
  if (type === 'combo-tls') {
    if (!splitDefault) {
      throw new Error(
        '[clean-vpn] combo-tls на client требует --split-default (TUN через boring-tls к exit; параллельно tcp/443 как у transparent-tls).',
      );
    }
    const comboClientPublicName = tlsPublicNamePrimary(tlsPublicName);
    if (!comboClientPublicName) {
      throw new Error(
        '[clean-vpn] combo-tls client: --tls-public-name обязателен для enc-SNI HTTPS relay (BREAKING: обновите client и exit вместе)',
      );
    }
    console.log(
      '[clean-vpn] combo-tls: TUN через boring-tls ↔ exit `--type=combo-tls` (внутренняя ветка TLS как type=tls); HTTPS :443 через enc-SNI relay (raw TCP, без CVPTX).',
    );
    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const ca = loadTlsClientCaPem(certsDir);
    const verifyName = resolveTlsClientCertVerifyName({
      tlsServerName,
      tlsPublicName,
      host,
      certsDir,
    });
    const clientHelloSniCombo = resolveTlsClientHelloSni({ tlsClientSni, verifyName });
    console.log(
      '[clean-vpn] combo-tls: мост TUN — boring-tls-helper (как `--type=boring-tls`).',
    );
    if (tlsHttpVers === '1.1') {
      console.log('[clean-vpn] tls: режим --http-vers=1.1 (принудительный HTTP/1.1, без h2)');
    }
    const vpnSecretBuf = ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
      autoCreate: false,
      role: 'client',
    }).buffer;
    const tlsConnectOptsCombo = {
      host,
      port,
      ca,
      servername: clientHelloSniCombo,
      verifyServername: verifyName,
      vpnSecret: vpnSecretBuf,
      tlsHttpVers: tlsHttpVers ?? null,
      tlsLogJa3: Boolean(tlsLogJa3),
      ja3Verbose: Boolean(ja3Verbose),
      boringTlsHelperPath: boringTlsHelper,
      boringTlsProfile: boringTlsProfile,
      boringTlsClienthelloProfilePath: boringTlsClienthelloProfile || null,
      boringTlsJa3Strict: Boolean(boringTlsJa3Strict),
    };
    if (tlsLogBearerEnabled() && kaBridge > 0) {
      console.log(
        `[clean-vpn] tls-log-bearer: --keep-alive=${kaBridge} — Bearer/exporter в логах после первого connect TUN (TCP SYN/DNS)`,
      );
    }

    /** @type {{ address: string; port: number } | null} */
    let explicitDestination = null;
    const tpPeerCombo = tunnelPeer?.trim?.();
    if (tpPeerCombo) {
      explicitDestination = parseTransparentTlsTunnelPeerIpv4(tpPeerCombo);
      console.log(
        `[clean-vpn] combo-tls: --tunnel-peer=${explicitDestination.address}:${explicitDestination.port} — только этот HTTPS-апстрим (без iptables REDIRECT).`,
      );
    }

    const logComboTunUp = () => {
      logComboTlsClientBranch(
        'boring-tls',
        `TCP→exit ${host}:${port} (TUN IPv4 через boring-tls-helper, не HTTPS intercept)`,
      );
    };

    attachOutboundTunBridge(
      tun,
      'tcp',
      BRIDGE_OPTS_CLIENT,
      async () => {
        const sock = await connectCleanVpnBoringTlsClient(tlsConnectOptsCombo);
        tlsVpnSocket = sock;
        logComboTunUp();
        return sock;
      },
      kaBridge,
      kaCooldown,
      shouldEagerOutboundTunConnect('combo-tls', splitDefault, kaBridge),
    );

    const ttlLogOptsCombo = { tlsLogJa3: Boolean(tlsLogJa3), ja3Verbose: Boolean(ja3Verbose) };
    if (ttlLogOptsCombo.tlsLogJa3 || ttlLogOptsCombo.ja3Verbose) {
      console.log(
        `[clean-vpn combo-tls client] JA3/JA4: HTTPS-сессии (tcp/443) — как transparent-tls.${clientLanSubnet ? ` С --client-lan-subnet: PREROUTING DNAT + второй слушатель. ` : ''} TUN-путь — stderr boring-tls-helper (как --type=boring-tls).`,
      );
    }

    /** @type {string|null} */
    let ttlLanGwHttps = null;

    const onInterceptHttpsSock = /** @type {(sock: import('net').Socket) => void} */ ((sock) => {
      sock.on('error', () => {});
      logComboTlsClientBranch(
        'transparent',
        `accept HTTPS-intercept local=${sock.localAddress ?? '?'}:${sock.localPort ?? '?'} peer=${sock.remoteAddress ?? '?'}:${sock.remotePort ?? '?'}`,
      );
      attachTransparentTlsClientSession(sock, {
        upstreamHost: host,
        upstreamPort: port,
        vpnSecretBuf,
        publicName: comboClientPublicName,
        explicitDestination,
        logOpts: ttlLogOptsCombo,
        modeTag: 'combo-tls',
      }).catch((err) => {
        console.error('[clean-vpn combo-tls https]', err?.message ?? err);
        sock.destroy();
      });
    });

    ttlHttpsInterceptSrv = net.createServer(onInterceptHttpsSock);

    await new Promise((resolve, reject) => {
      ttlHttpsInterceptSrv.listen(TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT, '127.0.0.1', () =>
        resolve(undefined),
      );
      ttlHttpsInterceptSrv.once('error', reject);
    });
    console.log(
      `[clean-vpn] combo-tls: HTTPS intercept 127.0.0.1:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} (OUTPUT REDIRECT :443 как у transparent-tls).`,
    );

    if (!explicitDestination && clientLanSubnet) {
      if (transparentTlsLanBind?.trim()) {
        const manual = transparentTlsLanBind.trim();
        if (!net.isIPv4(manual)) {
          throw new Error('[clean-vpn] --transparent-tls-lan-bind должен быть IPv4');
        }
        const uh = ipv4StringToUint32(manual);
        if (Number.isFinite(uh) && ipv4HostContainedInNormalizedCidr(uh, clientLanSubnet)) {
          ttlLanGwHttps = manual;
          console.log(
            `[clean-vpn] combo-tls: LAN bind явно ${ttlLanGwHttps} (--transparent-tls-lan-bind).`,
          );
        } else {
          throw new Error(
            `[clean-vpn] --transparent-tls-lan-bind=${manual} должен входить в --client-lan-subnet=${clientLanSubnet}`,
          );
        }
      } else {
        ttlLanGwHttps = detectIpv4LanGatewayOwnAddress(clientLanSubnet);
      }
      if (!ttlLanGwHttps) {
        safe(() => ttlHttpsInterceptSrv?.close());
        ttlHttpsInterceptSrv = null;
        throw new Error(
          `[clean-vpn] combo-tls: IPv4 шлюза в ${clientLanSubnet} не найден (исключены lo/tun*) — см. transparent-tls / --transparent-tls-lan-bind.`,
        );
      }
      ttlHttpsInterceptLanSrv = net.createServer(onInterceptHttpsSock);
      await new Promise((resolve, reject) => {
        ttlHttpsInterceptLanSrv.listen(
          TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
          ttlLanGwHttps,
          () => resolve(undefined),
        );
        ttlHttpsInterceptLanSrv.once('error', reject);
      });
      console.log(
        `[clean-vpn] combo-tls: HTTPS intercept ${ttlLanGwHttps}:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} для PREROUTING с LAN.`,
      );
    }

    if (!explicitDestination) {
      const serverExCombo = routeCtx.serverIp && net.isIPv4(routeCtx.serverIp) ? routeCtx.serverIp : null;
      try {
        ttlInputInterceptUndo = installFilterInputAcceptTransparentTlsInterceptIpv4(
          TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
          {
            commentMarker: TRANSPARENT_TLS_IPT_COMMENT,
            lanGatewayIpv4: ttlLanGwHttps ?? undefined,
            lanSourceCidr: clientLanSubnet ?? undefined,
          },
        );
        console.log(
          `[clean-vpn] combo-tls: filter INPUT — ACCEPT на интерсепт :${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT}.`,
        );

        if (clientLanSubnet && ttlLanGwHttps) {
          ttlPreroutingLanHttpsUndo = installPreroutingDnatForwardedHttpsLanToGatewayIpv4(
            clientLanSubnet,
            ttlLanGwHttps,
            TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
            {
              vpnServerIpv4Exclude: serverExCombo,
              commentMarker: TRANSPARENT_TLS_IPT_COMMENT,
            },
          );
          console.log(
            `[clean-vpn] combo-tls: PREROUTING HTTPS с LAN → DNAT ${ttlLanGwHttps}:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT}.`,
          );
        }

        ttlHttpsRedirectUndo = installOutputRedirectHttpsToLocalIpv4(TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT, {
          vpnServerIpv4Exclude: serverExCombo,
          commentMarker: TRANSPARENT_TLS_IPT_COMMENT,
        });
        console.log(
          `[clean-vpn] combo-tls: OUTPUT REDIRECT ipv4/https → 127.0.0.1:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT}.`,
        );
      } catch (e) {
        safe(() => ttlHttpsRedirectUndo?.());
        ttlHttpsRedirectUndo = null;
        safe(() => ttlPreroutingLanHttpsUndo?.());
        ttlPreroutingLanHttpsUndo = null;
        safe(() => ttlInputInterceptUndo?.());
        ttlInputInterceptUndo = null;
        safe(() => ttlHttpsInterceptLanSrv?.close());
        ttlHttpsInterceptLanSrv = null;
        safe(() => ttlHttpsInterceptSrv?.close());
        ttlHttpsInterceptSrv = null;
        throw e;
      }
    }

    return;
  }

  // --- runClient: --type=transparent-tls (tun как socket + параллельно HTTPS-сессии со сменой SNI) ---
  if (type === 'transparent-tls') {
    if (!splitDefault) {
      throw new Error(
        '[clean-vpn] transparent-tls на client требует --split-default (tun и IPv4-пакеты в exit — как `--type=socket`; tcp/443 к сайтам дополнительно уходит вторым транспортом к тому же exit).',
      );
    }
    const ttlClientPublicName = tlsPublicNamePrimary(tlsPublicName);
    if (!ttlClientPublicName) {
      throw new Error(
        '[clean-vpn] transparent-tls client: --tls-public-name обязателен для enc-SNI HTTPS relay (BREAKING: обновите client и exit вместе)',
      );
    }

    const certsDir = resolveTlsCertsDir({ tlsCertDir, quicCertsDir });
    const vpnSecretBuf = ensureSharedHmacKey(certsDir, sharedHmacKey, quicExtCryptoKey, {
      autoCreate: false,
      role: 'client',
    }).buffer;

    /** @type {{ address: string; port: number } | null} */
    let explicitDestination = null;
    const tpPeer = tunnelPeer?.trim?.();
    if (tpPeer) {
      explicitDestination = parseTransparentTlsTunnelPeerIpv4(tpPeer);
      console.log(
        `[clean-vpn] transparent-tls: --tunnel-peer=${explicitDestination.address}:${explicitDestination.port} — только этот апстрим, без iptables REDIRECT.`,
      );
    }

    const connectIpv4Mux = () =>
      new Promise((resolve, reject) => {
        const sock = net.connect(port, host, () => {
          console.log(
            `[clean-vpn transparent-tls client] route=non-tls (TUN IPv4) upstream=${host}:${port} транспорт=IPv4 mux (кадры uint32+pkt, как --type=socket)`,
          );
          tlsVpnSocket = sock;
          resolve(sock);
        });
        sock.on('error', reject);
      });

    const ttlLogOpts = { tlsLogJa3: Boolean(tlsLogJa3), ja3Verbose: Boolean(ja3Verbose) };
    if (ttlLogOpts.tlsLogJa3 || ttlLogOpts.ja3Verbose) {
      console.log(
        `[clean-vpn transparent-tls client] JA3/JA4/SNI: логируется только HTTPS (tcp/443).${clientLanSubnet ? ` С --client-lan-subnet: PREROUTING DNAT → IPv4 этого шлюза в LAN (+ второй локальный слушатель), без route_localnet к 127. ` : ''} На exit нужны те же флаги. Пример: curl -4 https://example.com`,
      );
    }

    attachOutboundTunBridge(
      tun,
      'tcp',
      BRIDGE_OPTS_CLIENT,
      async () => {
        await connectIpv4Mux();
        return /** @type {import('net').Socket} */ (tlsVpnSocket);
      },
      kaBridge,
      kaCooldown,
      shouldEagerOutboundTunConnect('transparent-tls', splitDefault, kaBridge),
    );

    /** @type {string|null} */
    let ttlLanGwHttps = null;

    const onInterceptHttpsSock = /** @type {(sock: import('net').Socket) => void} */ ((sock) => {
      sock.on('error', () => {});
      console.log(
        `[clean-vpn transparent-tls client] route=transparent (HTTPS intercept) accept local=${sock.localAddress ?? '?'}:${sock.localPort ?? '?'} peer=${sock.remoteAddress ?? '?'}:${sock.remotePort ?? '?'}`,
      );
      attachTransparentTlsClientSession(sock, {
        upstreamHost: host,
        upstreamPort: port,
        vpnSecretBuf,
        publicName: ttlClientPublicName,
        explicitDestination,
        logOpts: ttlLogOpts,
        modeTag: 'transparent-tls',
      }).catch((err) => {
        console.error('[clean-vpn transparent-tls https]', err?.message ?? err);
        sock.destroy();
      });
    });

    ttlHttpsInterceptSrv = net.createServer(onInterceptHttpsSock);

    await new Promise((resolve, reject) => {
      ttlHttpsInterceptSrv.listen(TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT, '127.0.0.1', () =>
        resolve(undefined),
      );
      ttlHttpsInterceptSrv.once('error', reject);
    });
    console.log(
      `[clean-vpn] transparent-tls: HTTPS intercept слушает 127.0.0.1:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} (процессы на этом хосте, OUTPUT REDIRECT)`,
    );

    if (!explicitDestination && clientLanSubnet) {
      if (transparentTlsLanBind?.trim()) {
        const manual = transparentTlsLanBind.trim();
        if (!net.isIPv4(manual)) {
          throw new Error('[clean-vpn] --transparent-tls-lan-bind должен быть IPv4');
        }
        const uh = ipv4StringToUint32(manual);
        if (
          Number.isFinite(uh) &&
          ipv4HostContainedInNormalizedCidr(uh, clientLanSubnet)
        ) {
          ttlLanGwHttps = manual;
          console.log(
            `[clean-vpn] transparent-tls: HTTPS DNAT/listen LAN-IP задан явно: ${ttlLanGwHttps} (--transparent-tls-lan-bind).`,
          );
        } else {
          throw new Error(
            `[clean-vpn] --transparent-tls-lan-bind=${manual} должен входить в --client-lan-subnet=${clientLanSubnet}`,
          );
        }
      } else {
        ttlLanGwHttps = detectIpv4LanGatewayOwnAddress(clientLanSubnet);
      }
      if (!ttlLanGwHttps) {
        safe(() => ttlHttpsInterceptSrv?.close());
        ttlHttpsInterceptSrv = null;
        throw new Error(
          `[clean-vpn] transparent-tls: IPv4 этого шлюза в подсети ${clientLanSubnet} не найден на интерфейсах (кроме lo/tun*) — см. описание режима ниже.`,
        );
      }
      ttlHttpsInterceptLanSrv = net.createServer(onInterceptHttpsSock);
      await new Promise((resolve, reject) => {
        ttlHttpsInterceptLanSrv.listen(
          TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
          ttlLanGwHttps,
          () => resolve(undefined),
        );
        ttlHttpsInterceptLanSrv.once('error', reject);
      });
      console.log(
        `[clean-vpn] transparent-tls: HTTPS intercept на ${ttlLanGwHttps}:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} для PREROUTING DNAT с LAN`,
      );
    }

    if (!explicitDestination) {
      const serverEx = routeCtx.serverIp && net.isIPv4(routeCtx.serverIp) ? routeCtx.serverIp : null;
      try {
        ttlInputInterceptUndo = installFilterInputAcceptTransparentTlsInterceptIpv4(
          TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
          {
            commentMarker: TRANSPARENT_TLS_IPT_COMMENT,
            lanGatewayIpv4: ttlLanGwHttps ?? undefined,
            lanSourceCidr: clientLanSubnet ?? undefined,
          },
        );
        console.log(
          `[clean-vpn] transparent-tls: filter INPUT — разрешена доставка TCP на интерсепт (loopback ± LAN→шлюз:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT}).`,
        );

        if (clientLanSubnet && ttlLanGwHttps) {
          ttlPreroutingLanHttpsUndo = installPreroutingDnatForwardedHttpsLanToGatewayIpv4(
            clientLanSubnet,
            ttlLanGwHttps,
            TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT,
            { vpnServerIpv4Exclude: serverEx, commentMarker: TRANSPARENT_TLS_IPT_COMMENT },
          );
          console.log(
            `[clean-vpn] transparent-tls: nat PREROUTING ipv4/https с ${clientLanSubnet} → DNAT ${ttlLanGwHttps}:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} (откат при выходе).`,
          );
        }

        ttlHttpsRedirectUndo = installOutputRedirectHttpsToLocalIpv4(TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT, {
          vpnServerIpv4Exclude: serverEx,
          commentMarker: TRANSPARENT_TLS_IPT_COMMENT,
        });
        console.log(
          `[clean-vpn] transparent-tls: nat OUTPUT ipv4/https → 127.0.0.1:${TRANSPARENT_TLS_LOCAL_INTERCEPT_PORT} (+ откат; частные и${serverEx ? ` VPS ${serverEx}` : ''} исключены).`,
        );
      } catch (e) {
        safe(() => ttlHttpsRedirectUndo?.());
        ttlHttpsRedirectUndo = null;
        safe(() => ttlPreroutingLanHttpsUndo?.());
        ttlPreroutingLanHttpsUndo = null;
        safe(() => ttlInputInterceptUndo?.());
        ttlInputInterceptUndo = null;
        safe(() => ttlHttpsInterceptLanSrv?.close());
        ttlHttpsInterceptLanSrv = null;
        safe(() => ttlHttpsInterceptSrv?.close());
        ttlHttpsInterceptSrv = null;
        throw e;
      }
    }

    return;
  }

  if (type !== 'socket' && type !== 'http') {
    throw new Error(
      `Неизвестный --type=${type} для client. Допускаются: tls, boring-tls, combo-tls, transparent-tls (см. документацию), socket, http, …`,
    );
  }

  // --- runClient: --type=socket | --type=http (TCP + опционально GET /clean-vpn) ---
  attachOutboundTunBridge(
    tun,
    'tcp',
    BRIDGE_OPTS_CLIENT,
    () =>
      new Promise((resolve, reject) => {
        const sock = net.connect(port, host, () => {
          console.log('[clean-vpn] TCP connected');
          if (type === 'socket') {
            resolve(sock);
            return;
          }
          sock.__isServer = false;
          handleHttpSocket(sock, (rest) => {
            if (rest && rest.length) {
              setImmediate(() => sock.emit('data', rest));
            }
            resolve(sock);
          });
          sock.write(
            `GET /clean-vpn HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\n\r\n`,
          );
        });
        sock.on('error', reject);
      }),
    kaBridge,
    kaCooldown,
  );
}

// =============================================================================
// === main: разбор argv, вызов runExit / runClient ===
// =============================================================================

async function main() {
  installCleanVpnFatalHandlers();
  const args = parseArgs(process.argv.slice(2));
  if (process.platform !== 'linux') {
    console.error('Только Linux (tun-helper-linux).');
    process.exit(1);
  }
  if (!args.role || !args.server || !args.type) {
    console.error(`Использование:
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=socket [--ext=eth0]
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=HOST:8765 --type=socket --split-default
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:8765 --type=transparent-tls --tls-public-name=vpn.example.com --ext=eth0
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=HOST:8765 --type=transparent-tls --split-default --tls-public-name=vpn.example.com
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=exit --server=0.0.0.0:443 --type=combo-tls --tls-public-name=vpn.example.com --ext=eth0
  sudo env PATH=$PATH node scripts/clean-vpn.js --role=client --server=HOST:443 --type=combo-tls --split-default --tls-public-name=vpn.example.com

--type: socket | http | websocket | ws-chrome | rtc-chrome | udp | webrtc | quic | quic-ext | tls | boring-tls | transparent-tls | combo-tls
--split-default: только client, IPv4 default через tun (0.0.0.0/1 + 128.0.0.0/1); RFC1918 через uplink; /32 bypass к --server и (только webrtc/rtc-chrome/ws-chrome/udp+punch) к IP STUN/TURN из --config. Plain --type=udp STUN не резолвит. IPv6 не в туннеле. Проверка: curl -4 https://ifconfig.me
--client-lan-subnet=CIDR: только client + --split-default — LAN/USB gadget за клиентом (адрес сети, напр. 192.168.7.0/24): ip_forward, SNAT в ${IP_CLIENT} через tun, FORWARD; иначе устройства за клиентом не попадают под NAT exit.
--transparent-tls-lan-bind=IPv4: с --type=transparent-tls или combo-tls + --client-lan-subnet — адрес этого шлюза для DNAT второго listener и PREROUTING (должен входить в CIDR), если автопоиск не нашёл нужный интерфейс (часто: на USB/etherнет нет адреса из 192.168.7.x).
--ext: только exit, интерфейс в интернет для NAT (иначе из default route)
--config=PATH: для --type=webrtc и rtc-chrome — JSON с iceServers/turnServers (по умолчанию config/default.json от корня репо)
--ice-mode=auto|relay|direct: для webrtc и rtc-chrome — перекрывает iceMode из --config
--allow-host-candidates: разрешить локальные ICE host/prflx-candidate'ы с приватными IP (RFC1918/loopback/link-local). По умолчанию (Phase 1 / M-5) такие candidate'ы отбрасываются и в исходящих, и во входящих сигналах — защита от утечки внутренних IP в STUN/SDP. srflx/relay не фильтруются. Опт-аут только для отладки в доверенной локальной сети.
--quic-certs-dir=DIR: для --type=quic и quic-ext — каталог с ca.pem, cert.pem, key.pem (иначе repo/certs; при отсутствии — openssl)
--shared-hmac-key=PATH: --type=tls | boring-tls | transparent-tls | combo-tls (обе стороны) и exit + --type=quic-ext — общий 32-байтовый HMAC PSK (иначе clean-vpn-hmac.key в --tls-cert-dir/--quic-certs-dir; на exit создаётся автоматически; legacy-имя файла quic-ext-hmac.key всё ещё читается). На client + --type=quic-ext не нужен.
--quic-ext-crypto-key=PATH: legacy alias для --shared-hmac-key=PATH (читается, рекомендуется заменить на --shared-hmac-key)
--type=quic: Node.js 25+, node --experimental-quic и бинарь с node_use_quic (см. шапку файла)
--type=quic-ext: npm install @infisical/quic (prebuild под платформу), Node 18+, см. шапку файла
--tls-cert-dir=DIR: для --type=tls, boring-tls (client), combo-tls и exit tls/combo — fullchain.pem+privkey.pem (LE) или ca/cert/key как у QUIC; здесь же лежит общий clean-vpn-hmac.key
--tls-server-name=HOST: только client + tls | boring-tls | combo-tls — проверка сертификата (CN/SAN); также ClientHello SNI для **TUN-туннеля** (boring-путь при combo), если не задан --tls-client-sni. Если --server — IP и оба не заданы, для проверки используется clean-vpn; при ошибочном --tls-server-name=www.google.com и IP тоже принудительно clean-vpn (маскировку SNI см. --tls-client-sni); на exit игнорируется
--tls-client-sni=HOST: только client + tls | boring-tls | combo-tls — явный SNI в ClientHello (TUN-путь boring); без флага при проверке cert=clean-vpn (часто IP без --tls-server-name) SNI по умолчанию www.google.com; иначе SNI = имя проверки. Маркера VPN в открытой части ClientHello нет — exit отличает VPN по Bearer внутри TLS (TLS 1.3; ALPN по умолчанию h2 + http/1.1; HTTP/1.1 → GET /clean-vpn, HTTP/2 → POST /clean-vpn на одном stream).
--tls-public-name=HOST[,HOST...]: **обязателен** для transparent-tls и combo-tls (enc-SNI v2 base62 relay). На exit + tls | combo-tls также SNI «честной» страницы It works! для VPN mux: любой из перечисленных имён в ClientHello → VPN; иначе passthrough.
--tls-probe-target=host:port: только exit + tls | combo-tls — куда TCP-прокси при passthrough (parse fail ClientHello или SNI ≠ --tls-public-name); default www.google.com:443
--tls-probe-max-bytes=N: короткий passthrough, лимит байт обоих направлений (default 49152)
--tls-probe-max-seconds=S: лимит времени passthrough-сессии (default 30)
--tls-probe-full-proxy-per-ip=K: не более K «длинных» passthrough с одного IP за сутки (default 0 = только короткий)
--http-vers=1.1: с --type=tls, boring-tls (client) или combo-tls (client и exit); принудительный HTTP/1.1 без h2; совместно обновляйте код на обеих сторонах
--tls-log-ja3: … **transparent-tls/combo-tls HTTPS**: client — JA3/JA4 до и после enc-SNI rebuild ClientHello; exit — JA4 по mux до/после restore SNI к origin.
--tls-log-bearer: для проверки H-1/H-2 — полный Bearer token и exporter_b64 в логах client/exit (эквивалент env CLEAN_VPN_TLS_LOG_BEARER=1). Без флага при boring-tls/tls всё равно печатается краткое «channel-binding OK» / «bearer=v2 channel-bound».
--ja3-verbose: подробный JA3 (обе строки до MD5, поля GREASE-очищенные, hex префикса TCP); сам включает вывод JA3. Env при уже включённом CLEAN_VPN_TLS_LOG_JA3: CLEAN_VPN_JA3_VERBOSE=1.
--type=boring-tls: только client — TLS 1.3 через процесс boring-tls-helper (BoringSSL), см. scripts/boring-tls-plan.md; на exit используйте --type=tls (тот же сервер). Сборка: npm run build:boring-tls-helper (мало RAM на VPS: npm run build:boring-tls-helper-lowmem). Путь к бинарю: CLEAN_VPN_BORING_TLS_HELPER или --boring-tls-helper=PATH; строковый профиль (резерв): --boring-tls-profile=NAME.
--type=combo-tls: client и exit (**одно имя типа**, тот же порт, **BREAKING** enc-SNI v2 base62). Client: \`--split-default\` + \`--tls-public-name=…\` + boring-helper TUN + enc-SNI HTTPS intercept. Exit: SNI \`*.publicName\` + decrypt OK → relay; иначе — как \`--type=tls\`.
--boring-tls-clienthello-profile=PATH: только client + boring-tls | combo-tls — JSON профиля ClientHello/JA3 (scripts/lib/boring-tls-clienthello-profile.mjs schema v1; см. ja3-snif-server --profile-save-path). Файл перечитывается перед каждым **TUN TLS** к exit. Env: CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE.
--boring-tls-profile-ja3-strict: только client + boring-tls | combo-tls — при несовпадении JA3 MD5 с полем ja3_md5 в профиле helper завершится ошибкой. Env: CLEAN_VPN_BORING_TLS_JA3_STRICT=1.
--type=ws-chrome: client — Puppeteer + Chrome держит WS к exit (npm install puppeteer). exit — HTTP /clean-vpn-chrome + WS только с --ws-server. Медленный CDP: --ws-chrome-cdp-data или CLEAN_VPN_WS_CHROME_CDP_DATA=1. Произвольная страница: --ws-chrome-url=... — только CDP.
--ws-chrome-executable=PATH, --ws-chrome-ws-url=ws://..., --ws-chrome-url=http://... (goto), --ws-chrome-exit-page, --ws-chrome-cdp-data
--type=rtc-chrome: только client — Puppeteer + Chrome WebRTC к exit --type=webrtc; --signaling — WSS сигналинга на --server + relay Chrome↔exit; иначе исходящий WS к --server. npm install puppeteer; --rtc-chrome-executable=PATH или PUPPETEER_EXECUTABLE_PATH
--ws-server: websocket / ws-chrome на exit — слушать HTTP+WS или WSS данных на --server; на client (websocket) — слушать WSS; без флага — исходящий WebSocket к --server.
--signaling: webrtc (exit|client) или rtc-chrome (client) — слушать WSS сигналинга на --server; без флага — исходящий WS. Для udp — вместе с UDP на PORT поднять WSS на PORT+1 (как webrtc). Алиас: --signalling.
--punch: только --type=udp — hole punching через STUN + сигналинг на PORT+1; на exit только вместе с --signaling.
--keep-alive=N: ... ws-chrome: переподключение поднимает новый Chrome (дорого). rtc-chrome: keep-alive рвёт только WebRTC к exit, Chrome остаётся (быстрый reconnect). QUIC/quic-ext: флаг не применяется. transport=tcp (--type=socket): idle на TCP-сервере (inbound) — FIN; на TCP-клиенте (outbound, в т.ч. exit с исходящим WS к client) TUN снимается без FIN, ждёт FIN сервера (CLEAN_VPN_TCP_GRACEFUL_CLOSE_MS, default 5s).
--keep-alive-reconnect-cooldown=M: целое M≥0; только с --keep-alive>0. После разрыва по idle M с не поднимать lazy по IPv4 с TUN (отбрасываются); не-IPv4 не поднимает сессию в любом случае. После M с следующий IPv4 снова может lazy-connect — cooldown не фильтр «навсегда». Меньше дребезга от DNS/ретрансмитов. По умолчанию 0. CLEAN_VPN_KEEPALIVE_DEBUG=1 — lazy/cooldown и drop не-IPv4 (hex). CLEAN_VPN_TLS_MUX_DEBUG=1 — диагностика TCP до ClientHello на exit и до handshake на client (--type=tls).
--tunnel-peer=HOST: для websocket/webrtc/rtc-chrome/udp + client при нюансах accept/split-default — см. шапку. Дополнительно: **transparent-tls** и **combo-tls + client** — **IPv4 или IPv4:PORT** (порт по умолчанию **443**) фиксирует один апстрим для всех локальных HTTPS-сессий (**без** iptables REDIRECT; нужен только с тестами на один хост). Обычный режим: **OUTPUT** ipv4/https→локальный intercept; при **--client-lan-subnet** — **PREROUTING DNAT** с LAN→LAN-IPv4 шлюза:intercept (второй listener, см. документацию).
--tls-cert-dir / --shared-hmac-key: для transparent-tls и combo-tls нужен тот же 32-байтовый ключ (enc-SNI AEAD и Bearer tls), что и для --type=tls (на exit при отсутствии автосоздание как у QUIC каталога).`);
    process.exit(1);
  }
  if (
    args.iceMode &&
    !['auto', 'relay', 'direct'].includes(args.iceMode)
  ) {
    console.error('[clean-vpn] --ice-mode должен быть auto | relay | direct');
    process.exit(1);
  }

  if (args.punch && args.type !== 'udp') {
    console.error('[clean-vpn] --punch допустим только с --type=udp');
    process.exit(1);
  }

  if (args.type === 'boring' || args.type === 'boring_tls') {
    if (args.role === 'client') {
      console.warn(
        `[clean-vpn] \`--type=${args.type}\` не поддерживается; имелось в виду \`--type=boring-tls\`. Подставляю boring-tls.`,
      );
      args.type = 'boring-tls';
    } else {
      console.error(
        `[clean-vpn] на exit для TLS используйте \`--type=tls\`, не «${args.type}» (алиас boring — только для client → boring-tls).`,
      );
      process.exit(1);
    }
  }

  let keepAliveSec = 0;
  if (args.keepAliveSec != null) {
    if (!Number.isInteger(args.keepAliveSec) || args.keepAliveSec < 0) {
      console.error('[clean-vpn] --keep-alive=N: N должно быть целым числом ≥ 0');
      process.exit(1);
    }
    keepAliveSec = args.keepAliveSec;
  }
  args.keepAliveSec = keepAliveSec;

  let keepAliveReconnectCooldownSec = 0;
  if (args.keepAliveReconnectCooldownSec != null) {
    if (
      !Number.isInteger(args.keepAliveReconnectCooldownSec) ||
      args.keepAliveReconnectCooldownSec < 0
    ) {
      console.error(
        '[clean-vpn] --keep-alive-reconnect-cooldown=M: M должно быть целым числом ≥ 0',
      );
      process.exit(1);
    }
    keepAliveReconnectCooldownSec = args.keepAliveReconnectCooldownSec;
  }
  args.keepAliveReconnectCooldownSec = keepAliveReconnectCooldownSec;

  if (args.tlsHttpVers != null && args.tlsHttpVers !== '1.1') {
    console.error('[clean-vpn] --http-vers поддерживает только значение 1.1');
    process.exit(1);
  }
  if (args.tlsHttpVers && !isTlsLikeType(args.type) && args.type !== 'combo-tls') {
    console.warn(
      '[clean-vpn] --http-vers действует только с --type=tls, boring-tls или combo-tls; флаг проигнорирован',
    );
  }

  if (args.clientLanSubnet) {
    if (args.role !== 'client') {
      console.error('[clean-vpn] --client-lan-subnet допускается только с --role=client');
      process.exit(1);
    }
    if (!args.splitDefault) {
      console.error('[clean-vpn] --client-lan-subnet требует --split-default');
      process.exit(1);
    }
    try {
      args.clientLanSubnet = parseIpv4CidrStrict(args.clientLanSubnet);
    } catch (e) {
      console.error('[clean-vpn]', e?.message || e);
      process.exit(1);
    }
  }

  if (args.transparentTlsLanBind != null && String(args.transparentTlsLanBind).trim()) {
    const bip = String(args.transparentTlsLanBind).trim();
    if (args.role !== 'client') {
      console.error('[clean-vpn] --transparent-tls-lan-bind только с --role=client');
      process.exit(1);
    }
    if (!args.splitDefault) {
      console.error('[clean-vpn] --transparent-tls-lan-bind требует --split-default');
      process.exit(1);
    }
    if (args.type !== 'transparent-tls' && args.type !== 'combo-tls') {
      console.error('[clean-vpn] --transparent-tls-lan-bind только с --type=transparent-tls или combo-tls');
      process.exit(1);
    }
    if (!args.clientLanSubnet) {
      console.error('[clean-vpn] --transparent-tls-lan-bind требует --client-lan-subnet=CIDR');
      process.exit(1);
    }
    if (!net.isIPv4(bip)) {
      console.error('[clean-vpn] --transparent-tls-lan-bind: укажите IPv4 вида 192.168.7.1');
      process.exit(1);
    }
    const uBind = ipv4StringToUint32(bip);
    if (!ipv4HostContainedInNormalizedCidr(uBind, args.clientLanSubnet)) {
      console.error(
        `[clean-vpn] --transparent-tls-lan-bind=${bip} должен находиться в --client-lan-subnet=${args.clientLanSubnet}`,
      );
      process.exit(1);
    }
    args.transparentTlsLanBind = bip;
  } else {
    args.transparentTlsLanBind = null;
  }

  const envTlsJa3 = envCleanVpnTruthy01('CLEAN_VPN_TLS_LOG_JA3');
  const envJa3VerboseOnly = envCleanVpnTruthy01('CLEAN_VPN_JA3_VERBOSE');
  const ja3Verbose =
    Boolean(args.ja3Verbose) || (envTlsJa3 && envJa3VerboseOnly);
  const tlsLogJa3 = Boolean(args.tlsLogJa3) || envTlsJa3 || ja3Verbose;
  args.tlsLogJa3 = tlsLogJa3;
  args.ja3Verbose = ja3Verbose;

  const tlsLogBearerFromFlag = Boolean(args.tlsLogBearer);
  const tlsLogBearerFromEnv = envCleanVpnTruthy01('CLEAN_VPN_TLS_LOG_BEARER');
  cleanVpnTlsLogBearer = tlsLogBearerFromFlag || tlsLogBearerFromEnv;
  args.tlsLogBearer = cleanVpnTlsLogBearer;
  if (process.env.CLEAN_VPN_TLS_LOG_BEARER != null && !cleanVpnTlsLogBearer) {
    console.warn(
      `[clean-vpn] tls-log-bearer: env CLEAN_VPN_TLS_LOG_BEARER=${JSON.stringify(process.env.CLEAN_VPN_TLS_LOG_BEARER)} не распознан (ожидается 1, true или yes)`,
    );
  }
  if (cleanVpnTlsLogBearer) {
    const src =
      tlsLogBearerFromFlag && tlsLogBearerFromEnv
        ? '--tls-log-bearer + CLEAN_VPN_TLS_LOG_BEARER'
        : tlsLogBearerFromFlag
          ? '--tls-log-bearer'
          : 'CLEAN_VPN_TLS_LOG_BEARER';
    console.log(
      `[clean-vpn] tls-log-bearer: включён (${src}); ok-frame boring-tls — только client; exit печатает tls bearer debug (exit http*)`,
    );
  }

  const envChProf = process.env.CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE?.trim();
  if (envChProf && !args.boringTlsClienthelloProfile) {
    args.boringTlsClienthelloProfile = path.resolve(envChProf);
  }
  if (!args.boringTlsJa3Strict && envCleanVpnTruthy01('CLEAN_VPN_BORING_TLS_JA3_STRICT')) {
    args.boringTlsJa3Strict = true;
  }
  if (
    args.boringTlsClienthelloProfile &&
    args.role === 'client' &&
    args.type !== 'boring-tls' &&
    args.type !== 'combo-tls'
  ) {
    console.warn(
      '[clean-vpn] --boring-tls-clienthello-profile / CLEAN_VPN_BORING_TLS_CLIENTHELLO_PROFILE действует только с --type=boring-tls или combo-tls; профиль не используется.',
    );
  }
  if (
    args.role === 'client' &&
    args.type === 'rtc-chrome' &&
    (args.tlsClientSni ||
      args.tlsLogJa3 ||
      args.boringTlsClienthelloProfile ||
      args.tlsServerName ||
      args.boringTlsHelper ||
      args.boringTlsProfile)
  ) {
    console.warn(
      '[clean-vpn] rtc-chrome: флаги --tls-* / --boring-tls-* / --ja3-* не используются (WebRTC в Chrome, exit — --type=webrtc).',
    );
  }

  if (args.role === 'exit') {
    await runExit(args);
  } else if (args.role === 'client') {
    await runClient(args);
  } else {
    console.error('role: exit | client');
    process.exit(1);
  }
}

main().catch((e) => {
  invokeCleanVpnEmergencyShutdown('main', e, 1);
});
