# Аудит безопасности транспортов `clean-vpn.js`

Документ оценивает каждый `--type` в `[scripts/clean-vpn.js](clean-vpn.js)` с точки зрения конфиденциальности, целостности, аутентификации, защиты от replay, защиты exit от анонимного abuse и устойчивости к active probing. Цель — выявить узкие места, отранжировать их по критичности и оценить сложность починки. Отдельная секция — необходимость каждого транспорта.

Этот документ **не** анализирует целостную систему (firewall/OS/ключевой менеджмент/обновления) — это отдельная работа.

---

## 1. Контекст и модель угроз

В шапке `[scripts/clean-vpn.js](clean-vpn.js)` явно заявлено: «Без шифрования и авторизации». Это **дизайн**, заточенный под anti-censorship поверх существующих TLS/QUIC, а не упущение. Часть транспортов **намеренно** не имеет криптографии — они полезны для отладки, локальной сети или поверх внешнего шифрования (SSH-туннель, stunnel, WireGuard, и т.п.).

### Шкала свойств


| Код    | Свойство                                  | Что значит                                                                               |
| ------ | ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| **C**  | Confidentiality (конфиденциальность wire) | шифруется ли поток на линии client↔exit                                                  |
| **I**  | Integrity (целостность)                   | защита от модификации в пути                                                             |
| **A**  | Authentication (аутентификация peer)      | exit знает, что подключился именно «свой»; client знает, что отвечает именно «свой» exit |
| **R**  | Replay protection                         | защита от воспроизведения перехваченных сообщений                                        |
| **AB** | Abuse protection                          | защита exit от использования анонимом как open NAT-relay                                 |
| **P**  | Active probing / DPI resistance           | устойчивость к активному пробингу и DPI-fingerprint                                      |


### Условные обозначения

- **ok** — реализовано адекватно для anti-censorship use case
- **partial** — частично, со значимыми оговорками
- **none** — отсутствует
- **by-design** — намеренно отсутствует (см. шапку файла), на стороннем шифровании

---

## 2. Сводная матрица свойств


| `--type`              | C                                                             | I                                   | A                                                                                                                                                          | R                                                                                     | AB                                                                                                                                                | P                                                                                                                                                                                                                                                      | Примечания |
| --------------------- | ------------------------------------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `tls`                 | ok (TLS 1.3)                                                  | ok                                  | ok (Bearer HMAC PSK + TLS exporter, серверный cert)                                                                                                        | ok (окно 15 мин + channel binding, см. [Fixed H-2](#fixed-h-2--bearer-окно-15-мин-1)) | ok (без Bearer → cover «It works!» / passthrough, rate-limit см. [Fixed M-1](#fixed-m-1--tls-cover-page-без-rate-limit))                          | ok (ClientHello + cover + passthrough к `--tls-probe-target`)                                                                                                                                                                                          |            |
| `boring-tls` (client) | ok                                                            | ok                                  | ok (как `tls` + контролируемый JA3 + exporter из helper)                                                                                                   | ok                                                                                    | ok (на exit — `tls`/`combo-tls`)                                                                                                                  | ok (контроль JA3/JA4 через BoringSSL helper)                                                                                                                                                                                                           |            |
| `combo-tls`           | ok (TUN: TLS; HTTPS: CVPTX по TLS-порту, но **на plain TCP**) | partial (HMAC в OPEN, не в OP_DATA) | partial (Bearer/HMAC OPEN — TUN-ветка через exporter v2)                                                                                                   | partial                                                                               | partial (TUN — ok; CVPTX-ветка — да, нужен HMAC OPEN; peek limits см. [Fixed M-4](#fixed-m-4--combo-tls-peek-timeout--медленный-dos))             | partial (TLS-ветка ok; CVPTX magic `CVPTX1\r\n` — DPI-сигнатура — Open, см. `[combo-tls-improvement.md](combo-tls-improvement.md)`)                                                                                                                    |            |
| `transparent-tls`     | none для CVPTX (plain TCP); IPv4 mux — none                   | partial (OPEN HMAC)                 | partial (HMAC OPEN); IPv4 mux — **none**                                                                                                                   | partial                                                                               | **partial** (IPv4 mux — open relay; CVPTX — нужен HMAC; peek timeout добавлен см. [Fixed M-4](#fixed-m-4--combo-tls-peek-timeout--медленный-dos)) | none (magic `CVPTX1\r\n` в plain — Open, см. `[combo-tls-improvement.md](combo-tls-improvement.md)`)                                                                                                                                                   |            |
| `quic`                | ok (QUIC/TLS)                                                 | ok                                  | partial (только TLS server-auth по shared CA; для node:quic exporter в Node ≥ 25 на стадии планирования)                                                   | partial (QUIC PN)                                                                     | partial (shared CA = «коллективный пароль»)                                                                                                       | partial (ALPN `clean-vpn` — узнаваемый маркер)                                                                                                                                                                                                         |            |
| `quic-ext`            | ok                                                            | ok                                  | partial (TLS server-auth по shared CA; quic-ext exporter не реализован quiche-биндингом)                                                                   | partial (QUIC PN, retry-token HMAC anti-amplification)                                | partial                                                                                                                                           | partial (ALPN `clean-vpn-ext` — маркер)                                                                                                                                                                                                                |            |
| `webrtc`              | ok (DTLS DC)                                                  | ok                                  | ok (HMAC сигналинга `clean-vpn-bind` + DTLS fingerprint binding, см. [Fixed C-2](#fixed-c-2--webrtc--rtc-chrome--udp-punch--сигналинг-без-аутентификации)) | ok (nonce + ts ±5 мин в bind; DTLS)                                                   | ok (MITM сигналинга больше не работает — подпись + fingerprint binding)                                                                           | partial (ICE/STUN/TURN, plain WS сигналинг палится; host-candidate утечка устранена, см. [Fixed M-5](#fixed-m-5--ip-утечка-через-ice-candidates))                                                                                                      |            |
| `rtc-chrome`          | ok (DTLS DC через Chrome)                                     | ok                                  | ok (как webrtc — embedded JS использует Web Crypto API для bind)                                                                                           | ok                                                                                    | ok                                                                                                                                                | partial (host-candidate filter в embedded JS, см. [Fixed M-5](#fixed-m-5--ip-утечка-через-ice-candidates); локальный 127.0.0.1 защищён secret-in-URL, см. [Fixed H-4](#fixed-h-4--ws-chrome--rtc-chrome--signalling-relay--локальный-127001-без-auth)) |            |
| `websocket`           | **none** (plain `ws://`)                                      | none                                | **none**                                                                                                                                                   | none                                                                                  | **none**                                                                                                                                          | none                                                                                                                                                                                                                                                   |            |
| `ws-chrome`           | **none** (plain `ws://` до exit)                              | none                                | **none**                                                                                                                                                   | none                                                                                  | **none**                                                                                                                                          | partial (Chrome-fingerprint TLS — только при WSS, которого здесь нет)                                                                                                                                                                                  |            |
| `udp`                 | **none**                                                      | none                                | **none** (первый отправитель захватывает)                                                                                                                  | none                                                                                  | **none**                                                                                                                                          | none                                                                                                                                                                                                                                                   |            |
| `udp --punch`         | **none**                                                      | none                                | **none** (сигналинг plain `ws://`)                                                                                                                         | none                                                                                  | **none**                                                                                                                                          | none                                                                                                                                                                                                                                                   |            |
| `socket`              | **none**                                                      | none                                | **none**                                                                                                                                                   | none                                                                                  | **none**                                                                                                                                          | none                                                                                                                                                                                                                                                   |            |
| `http`                | **none**                                                      | none                                | **none** (любой `\r\n\r\n` → 200)                                                                                                                          | none                                                                                  | **none**                                                                                                                                          | partial (маскировка под HTTP)                                                                                                                                                                                                                          |            |


Подробности — в разделе 3.

---

## 3. Узкие места по критичности

Каждая запись: проблема, цитата кода, сложность фикса (**S** ≈ часы, **M** ≈ дни, **L** ≈ недели/breaking change), идея фикса.

### 3.1. Critical

#### C-1. `socket` / `http` / `websocket` / `udp` — exit как open NAT-relay

Любой TCP/UDP-connect к exit → сразу `attachTunBridge`, без аутентификации. HMAC PSK для этих транспортов не подключается. Через ваш VPS можно NAT'ить произвольный трафик в интернет.

```6407:6424:scripts/clean-vpn.js
    tcpSrv = net.createServer((sock) => {
      console.log('[clean-vpn] tcp connected', sock.remoteAddress);

      if (type === 'http') { ... }
      if (type === 'transparent-tls') { ... }
      startBridge(sock, null, 'tcp');
```

`handleHttpSocket` не валидирует ни метод, ни путь, ни Host, ни Bearer — достаточно `\r\n\r\n`:

```5384:5417:scripts/clean-vpn.js
function handleHttpSocket(sock, onReady) {
  ...
  const idx = buf.indexOf('\r\n\r\n');
  if (idx === -1) { sock.__httpBuf = buf; return; }
  ...
  if (sock.__isServer) {
    const res =
      'HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n';
    sock.write(res);
  }
  onReady(rest);
}
```

WebSocket exit: `WebSocketServer` без TLS и без auth (см. `runExit` ветку `websocket` ~~6289-6339); UDP: peer = первый отправитель (~~6710-6722).

**Последствия:** анонимный спам/abuse через ваш VPS, ABuse-репорты к провайдеру VPS, утечка реального IP пользователя exit (вы) для произвольных назначений.

**Фикс:** **S** — добавить общий HMAC challenge-response handshake для не-TLS транспортов (после accept exit шлёт случайный nonce, client отвечает HMAC(PSK, nonce), exit проверяет). Это ломающее изменение протокола, но локализованное. Альтернативно **S** — firewall/iptables `--source` allowlist без правок кода.

#### C-2. WebRTC / rtc-chrome / udp-punch — сигналинг без аутентификации — **Fixed** (Phase 2)

> Статус: **Fixed**. См. [Fixed C-2](#fixed-c-2--webrtc--rtc-chrome--udp-punch--сигналинг-без-аутентификации) в разделе «Исправленные уязвимости» ниже.

Все WebSocket-сигналинги — plain `ws://` без auth/HMAC/подписи. `applyWebrtcRemoteSignal` слепо применяет SDP/candidates:

```2333:2343:scripts/clean-vpn.js
function applyWebrtcRemoteSignal(pc, msg) {
  if (!pc) return;
  if (msg.type === 'offer') pc.setRemoteDescription(msg.sdp, 'Offer');
  else if (msg.type === 'answer') pc.setRemoteDescription(msg.sdp, 'Answer');
  else if (msg.type === 'candidate') {
    try {
      pc.addRemoteCandidate(msg.candidate, msg.mid || '0');
```

Сигналинг punch-UDP в открытом виде:

```2248:2263:scripts/clean-vpn.js
  sigWs.send(
    JSON.stringify({
      type: CLEAN_VPN_UDP_REFLEXIVE,
      address: mapped.address,
      port: mapped.port,
    }),
  );
```

**Последствия:** атакующий с доступом к сети сигналинга может **занять слот** (один WS-клиент на listener), либо при MITM подменить SDP/fingerprint и провести MITM на DTLS DataChannel — Chrome/libdatachannel проверят fingerprint **только из перехваченного SDP**.

**Фикс:** **M** — обернуть сигналинг в HMAC: каждое сообщение JSON получает поле `mac = HMAC(PSK, body)` и **nonce**. **L** — переход на WSS + Bearer (требует cert/auto-LE).

### 3.2. High

#### H-1. `quic` / `quic-ext` — только TLS server-auth по shared CA — **частично Fixed для tls/boring-tls/combo-tls** (Phase 2)

> Статус: для `**tls` / `boring-tls` / `combo-tls`** добавлен Bearer с TLS exporter (RFC 5705) — см. [Fixed H-1+H-2](#fixed-h-1--h-2--bearer-окно-15-мин-1--tls-channel-binding-tls--boring-tls--combo-tls).
>
> Для `**quic`** (`node:quic`) и `**quic-ext`** Bearer внутри bidi stream ещё не реализован: Node `node:quic` exporter API стабилизируется только в Node 25+, а `@infisical/quic` (quiche) пока не экспортирует keying material наружу. Остаётся **Open**: фикс **M** — добавить тот же Bearer на первом frame stream + либо exporter (когда появится), либо challenge-response.

Проверка на client: `serverName: 'clean-vpn'` + `ca` из `--quic-certs-dir`. На exit — `verifyPeer: false`:

```6872:6877:scripts/clean-vpn.js
      config: {
        key: fs.readFileSync(tlsPaths.keyPath, 'utf8'),
        cert: fs.readFileSync(tlsPaths.certPath, 'utf8'),
        verifyPeer: false,
        applicationProtos: [QUIC_EXT_ALPN],
      },
```

```7657:7666:scripts/clean-vpn.js
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
```

Аналогично для `--type=quic` (node:quic) — только TLS server-auth (~7638-7642). Post-handshake auth нет: после рукопожатия любой, у кого тот же CA+cert или подменённый CA на клиенте, открывает bidi stream → TUN.

**Последствия:** любая утечка `ca.pem`/`cert.pem`/`key.pem` (или просто общего набора certs на нескольких клиентах) превращает QUIC-exit в open relay. HMAC PSK к QUIC-уровню **не подключен** (используется только для stateless retry — anti-amplification, не auth).

**Фикс:** **M** — добавить тот же Bearer HMAC, что в `--type=tls`, на первом frame в bidi stream (`uint32 BE` len + token + дальше как сейчас). Совместимо с anti-censorship-дизайном: токен внутри TLS, не виден на wire.

#### H-2. `tls` / `boring-tls` / `combo-tls` — Bearer-окно 15 мин ±1 — **Fixed** (Phase 2)

> Статус: **Fixed**. См. [Fixed H-1+H-2](#fixed-h-1--h-2--bearer-окно-15-мин-1--tls-channel-binding-tls--boring-tls--combo-tls) в разделе «Исправленные уязвимости» ниже.

```256:258:scripts/clean-vpn.js
const TLS_VPN_TOKEN_WINDOW_MS = 15 * 60 * 1000;
/** Контекст HMAC: фиксированная строка-домен. */
const TLS_VPN_TOKEN_CONTEXT = 'clean-vpn-tls-v1';
```

```619:635:scripts/clean-vpn.js
function verifyTlsVpnBearerToken(secret, token) {
  if (typeof token !== 'string' || token.length !== 32) return { ok: false, windowOffset: null };
  ...
  for (const offset of [0, -1, 1]) {
    const expected = Buffer.from(computeTlsVpnBearerToken(secret, offset), 'hex');
    if (expected.length === provided.length && timingSafeEqual(expected, provided)) {
      return { ok: true, windowOffset: offset };
    }
  }
  return { ok: false, windowOffset: null };
}
```

Перехваченный токен валиден **до ~45 минут** (текущее окно + ±1). Длина токена — **16 байт** (truncated HMAC-SHA256), что ниже типичного 32-байтового запаса.

**Последствия:** если злоумышленник один раз увидел токен (через logs/coredump/MITM до TLS), у него ~45 мин окно подключения как «свой».

**Фикс:** **M** — channel binding: токен включает TLS exporter (`tls.exporter("clean-vpn-bind", 32)`) или random nonce, переданный exit'ом до Bearer. Ломающее изменение протокола.

#### H-3. `transparent-tls` / `combo-tls` HTTPS-ветка — magic в plaintext — **Open** (вынесено)

> Статус: **Open**, реализация отложена и разобрана в отдельном документе `[scripts/combo-tls-improvement.md](combo-tls-improvement.md)` (два подхода: HTTP/2 mux через одну boring-tls сессию vs per-relay TLS с динамическим JA3, плюс зависимости от Phase 2 Bearer). После согласования подхода H-3 и M-3 закрываются вместе.

Постоянная сигнатура на wire:

```5:6:scripts/lib/transparent-tls-wire.mjs
export const TTL_FRAME_MAGIC_PREFIX = Buffer.from('CVPTX1\r\n', 'ascii');
```

OPEN-frame несёт **dst:port**, **origin SNI** и **fake SNI** в plaintext (HMAC только обеспечивает целостность):

```439:442:scripts/lib/transparent-tls-runtime.mjs
    console.warn(
      `[clean-vpn transparent-tls client] CVPTX: кадр OPEN + первые OP_DATA идут на exit по открытому TCP (только целостность HMAC у OPEN); поля origin_sni, fake_sni из OPEN и байты патченного ClientHello читаются пассивно на этом участке.`,
```

В `combo-tls` (одна точка :443) magic `CVPTX1\r\n` определяет ветку до TLS-парсинга:

```6439:6460:scripts/clean-vpn.js
  // --- runExit: --type=combo-tls (CVPTX + TLS mux одним listen TCP) ---
```

**Последствия:** DPI с pattern-match `CVPTX1\r\n` мгновенно распознаёт ваш протокол. Конфиденциальность origin/SNI не обеспечена.

**Фикс:** **L** — либо туннелировать CVPTX **внутри TLS** (использовать только `combo-tls` с CVPTX внутри ALPN/HTTP/2 stream), либо сделать magic «случайным» — обфускация под shared key (первые N байт = HMAC(PSK, nonce) с детекцией по timing-safe сравнению на exit). Любая обфускация = breaking.

#### H-4. `ws-chrome` / `rtc-chrome` / signalling relay — локальный 127.0.0.1 без auth — **Fixed** (Phase 1)

> Статус: **Fixed**. См. [Fixed H-4](#fixed-h-4--ws-chrome--rtc-chrome--signalling-relay--локальный-127001-без-auth) в разделе «Исправленные уязвимости» ниже.

Локальный WebSocket-мост (Node ↔ Chrome) слушает `127.0.0.1` на эфемерном порту. Принимается **первый** коннект:

```5666:5677:scripts/clean-vpn.js
        // первый клиент — мост
```

```5969:5980:scripts/clean-vpn.js

```

Аналогично для `attachRtcChromeSignalingRelay` (~1954-2058): Node делает relay двух WS (Chrome ↔ exit) без cookie/secret.

**Последствия:** любой локальный процесс под тем же UID (или с правом читать `/proc/<pid>/net`/CDP) может выиграть гонку с Chrome → получить полный duplex доступ к VPN TUN.

**Фикс:** **M** — добавить random secret в URL/Sec-WebSocket-Protocol, проверять при upgrade; для CDP — закрыть DevTools на ephemeral порту через `--remote-debugging-port=0` + auth-token.

### 3.3. Medium

#### M-1. TLS cover-page `It works!` без rate-limit — **Fixed** (Phase 1)

> Статус: **Fixed**. См. [Fixed M-1](#fixed-m-1--tls-cover-page-без-rate-limit) в разделе «Исправленные уязвимости» ниже.

Любой запрос без Bearer (или с неверным Bearer, или GET/POST не на `/clean-vpn`) получает 200 OK с заглушкой:

```4746:4802:scripts/clean-vpn.js

```

**Последствия:** массовое probing/корреляция (DPI: «этот IP отвечает `It works!` на любой URL» — слабый, но всё же признак не-настоящего сайта); рост стоимости probe для атакующего — низкий.

**Фикс:** **S** — счётчик «cover hits per IP per N минут», при превышении — TCP close или passthrough.

#### M-2. Серверные certs без SAN — **Fixed** (Phase 1)

> Статус: **Fixed**. См. [Fixed M-2](#fixed-m-2--серверные-certs-без-san) в разделе «Исправленные уязвимости» ниже.

Auto-gen certs на exit — `CN=clean-vpn`, без SAN:

```742:743:scripts/clean-vpn.js

```

Клиент при `--server=IP` без `--tls-server-name` принудительно проверяет имя `clean-vpn`, а SNI отправляет `www.google.com`:

```7680:7708:scripts/clean-vpn.js

```

**Последствия:** при работе с реальным IP вместо доменного имени защита от MITM ослаблена: проверяется только наличие у злоумышленника CA (см. H-1), не уникальное имя. Современные браузеры/curl такие certs не примут.

**Фикс:** **S** — при auto-gen добавить `subjectAltName` для `--server` host/IP + ротация при смене IP. При LE-cert (production) не актуально.

#### M-3. `transparent-tls` OP_DATA — без MAC — **Open** (вынесено)

> Статус: **Open**, закрывается вместе с H-3 в `[scripts/combo-tls-improvement.md](combo-tls-improvement.md)`: обёртка CVPTX в TLS даёт AEAD на весь поток (включая OP_DATA) и убирает потребность в per-frame MAC.

После OPEN-frame с HMAC последующие OP_DATA защищены только TCP-целостностью (нет AEAD/MAC):

```439:442:scripts/lib/transparent-tls-runtime.mjs

```

**Последствия:** MITM может модифицировать байты ClientHello после OPEN (например, заменить fake_sni обратно на origin_sni → exit пошлёт восстановленный к origin → утечка). Защищает только то, что byte-stream в обе стороны идёт через одно TCP, и для активной MITM нужен прямой in-path attacker.

**Фикс:** **L** — обернуть всё в TLS (move к `combo-tls`-варианту с TLS на :443). Альтернативно **M** — добавить per-frame MAC и счётчик, но не закрывает атаки до OPEN.

#### M-4. `combo-tls` peek timeout — медленный DoS — **Fixed** (Phase 1)

> Статус: **Fixed**. См. [Fixed M-4](#fixed-m-4--combo-tls-peek-timeout--медленный-dos) в разделе «Исправленные уязвимости» ниже.

При accept `combo-tls` exit ждёт первые байты до 60 секунд, чтобы определить ветку (CVPTX vs TLS). Атакующий открывает много slow-loris TCP без отправки → подвисший пул.

**Фикс:** **S** — уменьшить таймаут до 5-10 сек и/или ограничить число pending-pee коннекций (semaphore).

#### M-5. IP-утечка через ICE candidates — **Fixed** (Phase 1)

> Статус: **Fixed**. См. [Fixed M-5](#fixed-m-5--ip-утечка-через-ice-candidates) в разделе «Исправленные уязвимости» ниже.

При `--ice-mode=auto` host/srflx candidates уходят в SDP по открытому WS-сигналингу (~2378-2443). Любой, кто читает сигналинг (или его записал в логи), знает реальный публичный IP клиента (если он не за VPN другого уровня).

**Фикс:** **S** — для production ставить `--ice-mode=relay` (TURN) по умолчанию; **M** — добавить фильтрацию `host`-candidates в `applyWebrtcRemoteSignal`/перед отправкой.

### 3.4. Low / By design

- **TLS passthrough к `--tls-probe-target`** — open short-proxy ~5083-5116; защищён `--tls-probe-max-bytes=49152`, `--tls-probe-max-seconds=30`, `--tls-probe-full-proxy-per-ip=0`. Утечка реального IP клиента upstream'у нет: upstream видит IP exit. By design — без passthrough активный probe сразу детектит fake-сайт.
- **JA3 server-side TLS** не контролируется (`tls.createSecureContext` в Node) — только client side через boring-tls helper. Хардкод cipher/curve приближен к Chrome (`TLS_VPN_CIPHERS_1_3`, `TLS_VPN_ECDH_CURVES` ~262-266). Это компромисс anti-censorship vs. сложность нативного TLS-сервера.
- `**quic-ext` HMAC stateless retry** — anti-amplification, не аутентификация клиента (~488-512). Это by design в quiche.

---

## 4. Топ узких мест (с чего начинать)

1. **C-1** Open NAT-relay на не-TLS транспортах (socket/http/websocket/udp) — **Critical**, фикс **S** (HMAC handshake) либо firewall. *Open — оставлено для debug-режима.*
2. **C-2** Сигналинг WebRTC/punch без auth — **Critical** → **Fixed** (Phase 2): HMAC сигналинга + DTLS fingerprint binding. См. [Fixed C-2](#fixed-c-2--webrtc--rtc-chrome--udp-punch--сигналинг-без-аутентификации).
3. **H-1** Только shared-CA для QUIC/QUIC-ext, нет post-handshake auth — **High**: для `tls`/`boring-tls`/`combo-tls` **Fixed** через TLS exporter (Phase 2, общий фикс с H-2). `quic`/`quic-ext` — **Open**.
4. **H-3** `CVPTX1\r\n` plaintext magic — **High** → **Open**: вынесено в `[combo-tls-improvement.md](combo-tls-improvement.md)`.
5. **H-2** Bearer-окно 45 мин — **High** → **Fixed** (Phase 2, channel binding через TLS exporter). См. [Fixed H-1+H-2](#fixed-h-1--h-2--bearer-окно-15-мин-1--tls-channel-binding-tls--boring-tls--combo-tls).
6. **H-4** Локальный 127.0.0.1 без auth в chrome-режимах — **High** → **Fixed** (Phase 1, random secret в URL). См. [Fixed H-4](#fixed-h-4--ws-chrome--rtc-chrome--signalling-relay--локальный-127001-без-auth).
7. **M-1** Cover-page без rate-limit — **Medium** → **Fixed** (Phase 1). См. [Fixed M-1](#fixed-m-1--tls-cover-page-без-rate-limit).
8. **M-2** Server cert без SAN — **Medium** → **Fixed** (Phase 1). См. [Fixed M-2](#fixed-m-2--серверные-certs-без-san).
9. **M-5** IP-утечка ICE host-candidates — **Medium** → **Fixed** (Phase 1). См. [Fixed M-5](#fixed-m-5--ip-утечка-через-ice-candidates).
10. **M-4** `combo-tls` peek timeout 60s — **Medium** → **Fixed** (Phase 1). См. [Fixed M-4](#fixed-m-4--combo-tls-peek-timeout--медленный-dos).

---

## 5. Сложность починки (сводно)


| №   | Узкое место                           | Критичность | Сложность | Ломающее изменение      | Статус                                                                         |
| --- | ------------------------------------- | ----------- | --------- | ----------------------- | ------------------------------------------------------------------------------ |
| C-1 | socket/http/websocket/udp open relay  | Critical    | S         | Да (handshake)          | Open (debug-only)                                                              |
| C-2 | WebRTC/punch сигналинг без auth       | Critical    | M         | Да                      | **Fixed** (Phase 2)                                                            |
| H-1 | QUIC/QUIC-ext без post-handshake auth | High        | M         | Да                      | Open для quic/quic-ext; для tls/boring-tls/combo-tls покрыто **Fixed** H-1+H-2 |
| H-2 | Bearer replay-окно 45 мин             | High        | M         | Да                      | **Fixed** (Phase 2)                                                            |
| H-3 | CVPTX magic plaintext                 | High        | L         | Да                      | Open (см. `combo-tls-improvement.md`)                                          |
| H-4 | Локальный 127.0.0.1 без auth          | High        | M         | Нет (внутренний)        | **Fixed** (Phase 1)                                                            |
| M-1 | Cover-page без rate-limit             | Medium      | S         | Нет                     | **Fixed** (Phase 1)                                                            |
| M-2 | Cert без SAN                          | Medium      | S         | Нет                     | **Fixed** (Phase 1)                                                            |
| M-3 | OP_DATA без MAC                       | Medium      | L         | Да                      | Open (см. `combo-tls-improvement.md`)                                          |
| M-4 | combo-tls peek timeout                | Medium      | S         | Нет                     | **Fixed** (Phase 1)                                                            |
| M-5 | ICE host-candidates leak              | Medium      | S         | Нет (флаг по умолчанию) | **Fixed** (Phase 1)                                                            |


**S** ≈ часы, **M** ≈ дни, **L** ≈ недели/полный рефакторинг протокола.

---

## 5a. Исправленные уязвимости

Краткие записи по уже закрытым пунктам Phase 1 (M-1, M-2, M-4, M-5, H-4) и Phase 2 (H-1+H-2, C-2). Каждая запись: суть исходной проблемы, применённый фикс, остаточный риск и **как проверить** (работоспособность транспорта + корректность самого фикса).

### [Tested] Fixed M-1 — TLS cover-page без rate-limit

- **В чём была уязвимость.** На любой не-VPN запрос (без Bearer / wrong Bearer / GET-POST не на `/clean-vpn`) exit отвечал 200 OK «It works!» без ограничений. Это давало атакующему «бесплатный» канал для массового probing/корреляции и слабый DPI-сигнал «этот IP отвечает на любой URL».
- **Как починили.** В `[scripts/clean-vpn.js](clean-vpn.js)` добавлены константы `TLS_COVER_RATELIMIT_WINDOW_MS_DEFAULT` (60 с) и `TLS_COVER_RATELIMIT_MAX_DEFAULT` (10), in-memory `tlsCoverRateState: Map<ip, {count, windowStart}>` с LRU-очисткой через `setInterval`, функция `tlsCoverShouldThrottle(ip)`. Вызывается в `respondPublic` (HTTP/1.1) и в HTTP/2 stream handler; при превышении лимита соединение закрывается `socket.destroy()` без ответа. Успешный VPN-handshake счётчик не двигает. Тюнинг через `CLEAN_VPN_TLS_COVER_RL_MAX` / `CLEAN_VPN_TLS_COVER_RL_WINDOW_MS`.
- **Остаточный риск.** Счётчики per-IP — атакующий с большим пулом IP может всё ещё пробить лимит. Защиту это не отменяет, но повышает стоимость массового пробинга.
- **Как проверить.**
  - **Работоспособность транспорта (`--type=tls`).** Поднять exit и client с общим `clean-vpn-hmac.key`, подключиться с `--split-default`, выполнить `curl -4 https://ifconfig.me` — должен вернуться внешний IP exit'а. VPN-handshake с валидным Bearer не должен ломаться из‑за rate-limit (счётчик cover не растёт).
  - **Корректность фикса.** Важно: **clean-vpn никогда не отвечает HTTP 403** на cover-path — только `200 It works!` или обрыв TCP без ответа (`000`, `Empty reply`, `Connection reset`). Если видите **403 на всех запросах**, вы **не попали на cover exit'а** (passthrough к `--tls-probe-target`, Cloudflare orange cloud, nginx и т.п.).
  **Шаг 0 — убедиться, что curl бьёт в cover, а не в passthrough.** На exit в логах при каждом запросе должно быть одно из:
    - `tls cover: served ip=… reason=cover_…` — попали на cover (M-1 считает такие запросы);
    - `tls passthrough: start ip=… reason=sni_mismatch_public_name` (или `parse_fail`) — **не cover**, rate-limit M-1 не сработает.
    Если на exit задан `--tls-public-name=cloudflare.com` (или другое имя), curl к `https://VPS_IP:443/` **без** matching SNI уходит в passthrough — upstream (часто Cloudflare/Google) может вернуть **403**. Нужен SNI из `--tls-public-name` **и** прямой доступ к origin IP (Cloudflare **gray cloud**, не orange).
    **Рекомендуемый тест** (12 запросов с одного IP, HTTP/1.1, matching SNI):
    ```bash
    EXIT=62.84.120.30
    # SNI = значение --tls-public-name на exit (если не задано — можно IP или clean-vpn)
    SNI=cloudflare.com

    for i in $(seq 1 12); do
      echo "=== $i ==="
      meta=$(curl -sk --http1.1 --connect-timeout 5 \
        --resolve "${SNI}:443:${EXIT}" \
        "https://${SNI}/" \
        -o /tmp/cv-cover-body -w '%{http_code}|%{errormsg}' 2>/dev/null) || meta='000|'
      code=${meta%%|*}
      err=${meta#*|}
      echo "code=${code} err=${err}"
      [ "$code" = "200" ] && head -c 20 /tmp/cv-cover-body && echo
    done
    ```
    Альтернатива — `[scripts/probe.js](probe.js)` (ALPN только `http/1.1`, явный SNI):
    ```bash
    for i in $(seq 1 12); do
      echo "=== $i ==="
      node scripts/probe.js --type=full --server=${EXIT}:443 --domain=${SNI}:443
    done
    ```
    **Ожидание:** первые ~10 — `code=200`, тело начинается с `It works!`; с 11-го — `code=000` / `Empty reply` / `Connection reset`, на exit — `tls cover: ratelimit ip=…`. Для быстрого теста на exit: `CLEAN_VPN_TLS_COVER_RL_MAX=3`, затем 4-й запрос уже throttle.
    **Не путать с VPN-client'ом:** запущенный `--role=client --type=tls` для проверки M-1 не нужен — cover проверяют **отдельными** curl/probe-запросами к exit, параллельно с VPN или без него.

### Fixed M-2 — Серверные certs без SAN

- **В чём была уязвимость.** `ensureQuicCerts` генерировал self-signed `CN=clean-vpn` без `subjectAltName`. Современные браузеры/curl такие сертификаты не принимают, проверка имени ослаблена при работе через IP.
- **Как починили.** Добавлен `normalizeCertSanHosts(hosts)`, формирующий список `DNS:`/`IP:` записей. `ensureQuicCerts(dir, opts)` теперь принимает `opts.sanHosts` и при их наличии вызывает `openssl req` с `-extfile`, содержащим `subjectAltName=...`. `loadTlsServerCredentials` и `runExit` (`tls`/`quic`/`quic-ext`) прокидывают `[tlsPublicName, host].filter(Boolean)` как SAN. В шапке `[scripts/clean-vpn.js](clean-vpn.js)` явно указано: production — Let's Encrypt (fullchain.pem + privkey.pem), self-signed — только для отладки.
- **Остаточный риск.** Self-signed cert остаётся «коллективным паролем» (см. H-1 для QUIC). Рекомендация LE — единственное полноценное решение для проверки имени.
- **Как проверить.**
  - **Работоспособность транспорта.** Exit с `--server=0.0.0.0:443 --type=tls` (или `quic-ext`) **без** готовых cert'ов — `ensureQuicCerts` создаст новые. Client с `--server=VPS_IP:443 --type=tls --split-default` и `ca.pem` с exit'а — TLS-handshake и VPN должны пройти без `ERR_TLS_CERT_ALTNAME_INVALID`. Аналогично для `quic-ext`.
  - **Корректность фикса.** На exit после auto-gen:
    ```bash
    openssl x509 -in certs/cert.pem -noout -ext subjectAltName
    ```
    В выводе должны быть `IP:VPS_IP` (из `--server`) и/или `DNS:…` (из `--tls-public-name`). Без SAN (старый cert) — удалить `cert.pem`/`key.pem` в `--tls-cert-dir` и перезапустить exit для перегенерации.

### [Tested] Fixed M-4 — combo-tls peek timeout / медленный DoS

- **В чём была уязвимость.** При accept `combo-tls` exit ждал первые байты до 60 секунд, чтобы выбрать ветку (CVPTX vs TLS). `transparent-tls` peek-таймаута вообще не было. Атакующий мог открывать большое число slow-loris соединений и держать пул pending peek.
- **Как починили.** Введены константы `EXIT_PEEK_TIMEOUT_MS_DEFAULT = 10000` и `EXIT_PEEK_MAX_PENDING_DEFAULT = 1000`. Глобальный семафор `exitPeekActive` + `exitPeekAcquire()` (возвращает `release`-функцию) ограничивает число одновременно «висящих» peek; превышение — соединение `destroy()` без ответа. В `peekDispatchExitTransparentTlsOrIpv4Sock` и `peekDispatchExitComboTlsSock` добавлены `stallTimer` (10 с) с гарантированным `release()` в `finally`. Тюнинг: `CLEAN_VPN_EXIT_PEEK_TIMEOUT_MS` / `CLEAN_VPN_EXIT_PEEK_MAX`.
- **Остаточный риск.** Семафор глобальный — пик легитимного трафика на старте может временно занять слоты. В типовой нагрузке 1000 одновременных peek с большим запасом, но при необходимости можно поднять envом.
- **Как проверить.**
  - **Работоспособность транспорта.**
    - `**--type=combo-tls`:** client с `--split-default`, TUN через boring-tls + (опционально) transparent HTTPS — подключение и `curl -4` через VPN.
    - `**--type=transparent-tls`:** client с `--split-default`, IPv4 mux и/или HTTPS intercept — обычный трафик проходит.
  - **Корректность фикса (stall timeout).** Таймаут **10 с** действует только на exit с `**--type=combo-tls`** или `**--type=transparent-tls`** (peek-dispatch первых 8 байт). На `**--type=tls`** по-прежнему **60 с** ожидания полного ClientHello — это другой code-path, не M-4.
  Подключиться к peek-порту и **не отправлять** байты. **Критерий — лог exit** (~10 с), не время выхода `nc` на клиенте.
    ```bash
    apt install netcat-openbsd   # на Radxa: apt install nc не найдёт пакет
    time nc -v 62.84.120.30 443
    ```
    Подключились, **ничего не вводите**. Через ~10 с на **exit**: `peek прerван: … reason=10000ms без данных`. На клиенте `nc` может висеть до Ctrl+C — это нормально, exit уже закрыл peek. Не усложняйте `nc` (`-N`, `< /dev/null`, `sleep | nc` и т.п.) — усложнённые варианты не лучше простого.
    **Замер ~10 с на клиенте** (без Node, bash с `/dev/tcp`):
    ```bash
    time bash -c 'exec 3<>/dev/tcp/62.84.120.30/443; read -t 20 -u 3 _ || true; exec 3>&-'
    ```
    Ожидание: `real` ~10 с (±1 с), на exit — тот же `peek прerван … 10000ms`.
    Или Node:
    ```bash
    time node -e "
      const net = require('net');
      const t = Date.now();
      const s = net.connect(443, '62.84.120.30');
      s.on('close', () => console.log('closed after', Date.now() - t, 'ms'));
      s.on('error', (e) => console.log('error:', e.message, 'after', Date.now() - t, 'ms'));
    "
    ```
    Ожидание: `closed after ~10000 ms` (±1–2 с).
    С `CLEAN_VPN_TLS_MUX_DEBUG=1` на exit — дополнительный debug mux.
  - **Корректность фикса (semaphore).** Семафор **по умолчанию = 1000** (`EXIT_PEEK_MAX_PENDING_DEFAULT`). Если exit запущен **без** `CLEAN_VPN_EXIT_PEEK_MAX=5`, то 6, 10 и даже 100 «висящих» TCP **все** попадут в peek и отвалятся только через **~10 с** по stall-таймеру — в логах только `peek прерван: … 10000ms без данных`, **без** `peek отклонён`. Это **не баг**, а ожидаемое поведение при дефолтном лимите.
  **Шаг 1 — перезапустить exit** с пониженным лимитом (только для lab-теста):
    ```bash
    sudo env PATH=$PATH CLEAN_VPN_EXIT_PEEK_MAX=5 \
      node scripts/clean-vpn.js --role=exit --server=0.0.0.0:443 --type=combo-tls ...
    ```
    Env читается **только при старте** процесса exit — `export` после запуска не сработает.
    **Шаг 2 — с клиента** открыть 6+ TCP без отправки данных (Node держит процесс, пока сокет открыт):
    ```bash
    EXIT=62.84.120.30
    for i in $(seq 1 10); do
      node -e "
        const s = require('net').connect(443, process.argv[1]);
        s.on('connect', () => console.log('hold', process.argv[2]));
        s.on('close', () => process.exit(0));
      " "$EXIT" "$i" &
    done
    wait
    ```
    **Ожидание на exit:**
    - **Слоты 1–5:** `hold` на клиенте, через ~10 с — `peek прерван: … 10000ms без данных`.
    - **Слоты 6–10 (и далее):** сразу при accept — `peek отклонён: лимит pending peek превышен; peer=…` (без 10-секундного ожидания). На клиенте connect может не успеть (`hold` не печатается) или сокет сразу `close`/`ECONNRESET`.
    **Что вы уже проверили:** 10 соединений → все `peek прерван … 10000ms` — это подтверждает **stall timeout (10 с)**, не semaphore. Semaphore виден только при `CLEAN_VPN_EXIT_PEEK_MAX` ≤ числа параллельных «висящих» TCP.
    После закрытия «висящих» легитимный client снова подключается нормально.

### [1/2 Tested] Fixed M-5 — IP-утечка через ICE candidates

- **В чём была уязвимость.** При `--ice-mode=auto` host/srflx candidates уходили в SDP по открытому WS-сигналингу — любой, кто читает (или логирует) сигналинг, видит реальные RFC1918/loopback/link-local адреса клиента.
- **Как починили.** Добавлены утилиты `parseIceCandidateFields`, `isPrivateOrLoopbackIp`, `shouldDropIceCandidate`, `emitFilteredLocalCandidate`. По умолчанию для `typ host` и `typ prflx` отбрасываются IP из RFC1918 / loopback / IPv6 ULA / link-local — и в исходящих local-candidate'ах (`attachCleanVpnWebrtcExitSignaling`/`attachCleanVpnWebrtcClientSignaling`), и при `applyWebrtcRemoteSignal`. `srflx`/`relay` остаются (нужны для NAT-traversal). В `rtc-chrome` embedded JS добавлены идентичные функции и применяются к `pc.onicecandidate` и remote candidate processing. Флаг `--allow-host-candidates` — opt-out для отладки.
- **Остаточный риск.** Внешние публичные IP клиента (srflx через STUN) по-прежнему попадают в SDP — это by design ICE. Для полного скрытия — `--ice-mode=relay` (TURN).
- **Как проверить.**
  - **Работоспособность транспорта.**
    - `**--type=webrtc`:** exit `--signaling`, client `--split-default --ice-mode=auto` (или `relay`) — DataChannel поднимается, `curl -4 https://ifconfig.me` через VPN.
    - `**--type=rtc-chrome`:** client с Chrome/Puppeteer — аналогично, TUN ↔ exit webrtc.
  - **Корректность фикса.** В stderr **client'а** и **exit'а** при ICE gathering должны появляться строки вида:
    ```
    [clean-vpn] webrtc client: drop local host/prflx-private candidate (M-5; 192.168.1.42 typ=host; --allow-host-candidates для opt-out)
    [clean-vpn] webrtc exit: drop remote host/prflx-private candidate (M-5; 10.0.0.5 typ=host)
    ```
    (IP и `typ` в логе — отфильтрованный candidate; в WS-сигналинг он **не** уходит.)
  - **tcpdump на сигналинг (plain WS).** Exit webrtc слушает `--signaling` на порту `PORT` (тот же, что VPN UDP/TCP base, обычно из `--listen`). Сигналинг — **отдельный** TCP-порт `PORT+1` (см. лог `signaling ws://0.0.0.0:PORT+1` при старте exit).

    **Захват в файл (рекомендуется):**
    ```bash
    # на exit-машине или на client, если сигналинг идёт на VPS
    SIG_PORT=9877   # PORT+1, подставьте свой (например 9876+1)
    sudo tcpdump -i any -s0 -w /tmp/clean-vpn-signaling.pcap "tcp port ${SIG_PORT}"
    # подключите webrtc/rtc-chrome client, дождитесь ICE connected, Ctrl+C

    # анализ: приватные host/prflx НЕ должны встречаться в candidate-строках
    strings /tmp/clean-vpn-signaling.pcap | grep -E 'candidate|typ host|typ prflx' | grep -E '192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.0\.0\.1|169\.254\.' && echo FAIL || echo OK
    ```
    Ожидание: `OK` (grep ничего не нашёл) или в выводе только `typ srflx` / `typ relay` с публичными IP.

    **Живой просмотр (ASCII payload):**
    ```bash
    sudo tcpdump -i any -A -s0 "tcp port ${SIG_PORT}" 2>&1 | grep --line-buffered -E '"type":"candidate"|typ host|typ prflx|192\.168\.|10\.'
    ```
    Ожидание: JSON `"type":"candidate"` с `typ srflx` или `typ relay`; строк `typ host` с RFC1918 **нет**.

    **Wireshark:** открыть `.pcap` → Follow TCP Stream → искать `"candidate":"candidate:…"`. Допустимо: `typ srflx` (публичный mapping STUN), `typ relay` (TURN). Недопустимо: `typ host` / `typ prflx` с `192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`, `127.0.0.1`.
  - **Opt-out.** Запустить client с `--allow-host-candidates` — приватные host-candidate'ы снова появляются в сигналинге (для сравнения «до/после»); логи `drop … (M-5; …)` **исчезают**.

### [Tested] Fixed H-4 — ws-chrome / rtc-chrome / signalling relay — локальный 127.0.0.1 без auth

- **В чём была уязвимость.** Локальные WebSocket-мосты (Node ↔ Chrome) слушали `127.0.0.1` на эфемерном порту и принимали первый коннект. Любой локальный процесс под тем же UID мог выиграть гонку с Chrome и получить полный duplex доступ к VPN TUN.
- **Как починили.** В `createWsChromeClientBridge` и `createRtcChromeClientBridge` при старте генерируется `localSecret = randomBytes(16).toString('hex')`, добавляется к локальному URL как `?t=${localSecret}` и передаётся в Chrome через **встроенный JS** (не через argv — argv видны другим процессам). На сервере вход проверяется через `localWsRequestHasSecret(request, expectedSecret)` (constant-time `timingSafeEqual` поверх `URLSearchParams`). Чужие процессы без secret в connect-URL соединиться не могут.
- **Остаточный риск.** Если атакующий имеет право читать память процесса или его командную строку с расширенных привилегий (например, root) — secret всё равно утекает. Для UID-уровня атак защита полная.
- **Как проверить.**
  - **Работоспособность транспорта.**
    - `**--type=ws-chrome`:** client с `--split-default`, exit `--type=websocket --ws-server` (или ws-chrome exit-page) — Chrome поднимает WS к exit, TUN работает, `curl -4` через VPN.
    - `**--type=rtc-chrome`:** client → exit `--type=webrtc --signaling` — WebRTC + локальный WS-мост, VPN работает.
  - **Корректность фикса.** Пока client запущен, узнать порт локального WS (из лога или `ss -ltnp | grep clean-vpn`). Попробовать подключиться **без** secret:
    ```bash
    # замените PORT на эфемерный порт из лога
    node -e "
      const WebSocket=require('ws');
      const ws=new WebSocket('ws://127.0.0.1:PORT/');
      ws.on('open',()=>console.log('UNEXPECTED open'));
      ws.on('error',e=>console.log('expected:',e.message));
      ws.on('close',(c,r)=>console.log('close',c,r?.toString()));
    "
    ```
    Ожидание: соединение **не** устанавливается (close с кодом 1008 или обрыв до `open`). С правильным `?t=<32hex>` (из embedded JS страницы — только для ручного теста через DevTools) — `open` успешен. Штатный путь через Chrome secret подставляет автоматически — пользователю вручную secret знать не нужно.

### [Work Tested, fix not tested] Fixed H-1 + H-2 — Bearer-окно 15 мин ±1 + TLS channel binding (`tls` / `boring-tls` / `combo-tls`)

- **В чём была уязвимость.** Bearer-токен для `--type=tls` считался как `HMAC(PSK, "clean-vpn-tls-v1:" + window)[:16]` и был валиден ~45 минут (текущее окно ±1). Перехват токена (через MITM до TLS, coredump, логи) давал атакующему окно подключения как «свой» в **любой** TLS-сессии до exit (H-2). Также для transport'ов с TLS server-auth по shared CA любая утечка ca/cert/key превращала exit в open relay без post-handshake auth (H-1 для `tls`/`boring-tls`/`combo-tls` — частично).
- **Как починили.** В `[scripts/clean-vpn.js](clean-vpn.js)`: новые константы `TLS_VPN_TOKEN_CONTEXT_V2 = 'clean-vpn-tls-v2'`, `TLS_VPN_EXPORTER_LABEL = 'EXPORTER-clean-vpn-bind'`, `TLS_VPN_EXPORTER_LEN = 32`. `computeTlsVpnBearerToken` / `verifyTlsVpnBearerToken` принимают необязательный `exporterBuf`; при наличии — токен = `HMAC(PSK, "clean-vpn-tls-v2:" + base64(exporter) + ":" + window)[:16]`, иначе fallback на v1 (с warning `bearer_legacy=1`). `tlsVpnExporterFromSocket(tlsSock)` извлекает exporter из `tls.TLSSocket` (Node 19+). Клиентские пути (HTTP/2 `establishCleanVpnOverH2`, HTTP/1.1 `completeCleanVpnTlsSession`) и exit-стороны (`wireExitTlsSocket`, HTTP/2 stream handler) обмениваются exporter через сокет. Для `boring-tls` exporter возвращается из helper в JSON-frame `{"ok":true,"exporter":"<base64>"}` — в `[native/boring_tls/helper_main.cc](../native/boring_tls/helper_main.cc)` после `SSL_handshake` вызывается `SSL_export_keying_material(..., "EXPORTER-clean-vpn-bind", 32, NULL, 0, 0)` и результат base64-кодируется. `connectCleanVpnBoringTlsClient` парсит `exporter` из ответа helper. Перехваченный v2-Bearer вне той самой TLS-сессии не работает — exporter уникален per-session (RFC 5705).
- **Остаточный риск.** v1 Bearer всё ещё принимается с warning'ом ради миграции — удалить в следующем миноре. `quic` / `quic-ext` пока остаются на старой схеме (`node:quic` exporter API только в Node 25+, quiche/@infisical/quic пока не экспортирует keying material) — отдельная задача.
- **Как проверить.**
  - **Работоспособность транспорта.**
    - `**--type=tls`:** exit + client с общим `clean-vpn-hmac.key`, Node **19+** на обеих сторонах — VPN поднимается, `curl -4` через TUN.
    - `**--type=boring-tls`:** client через helper (пересобрать `npm run build:boring-tls-helper`), exit `--type=tls` — то же.
    - `**--type=combo-tls`:** client combo + exit combo — TUN и (если настроен) transparent HTTPS работают.
  - **Корректность фикса (v2 используется).** На exit в логах **нет** `bearer_legacy=1` при подключении свежего client'а (Node 19+ или пересобранный `boring-tls-helper`).

    **Где смотреть `exporter` для `boring-tls`.** Поле `"exporter":"<base64>"` — **не** в stderr helper'а. Helper после успешного `SSL_handshake` пишет **length-prefixed JSON-frame на stdout** (IPC с Node), пример содержимого frame:
    ```json
    {"ok":true,"alpn":"h2","exporter":"K7x…32байта в base64…="}
    ```
    Node читает его в `connectCleanVpnBoringTlsClient()` (`scripts/clean-vpn.js`) и передаёт в `computeTlsVpnBearerToken` как 32-байтовый TLS exporter (label `EXPORTER-clean-vpn-bind`, RFC 5705). Stderr helper'а — только диагностика (JA3, ошибки OpenSSL); при неудаче `SSL_export_keying_material` там будет `SSL_export_keying_material failed`, а поля `exporter` в ok-frame не будет.

    **Как увидеть channel-binding в логах (без секретов).** При **любом** успешном подключении client'а с exporter (boring-tls или `--type=tls` Node 19+) **всегда** печатаются строки:
    ```
    [clean-vpn] boring-tls: TLS channel-binding OK alpn=h2 exporter_len=32 (Bearer v2; полный token/exporter — --tls-log-bearer)
    [clean-vpn] TLS (VPN) соединение установлено http=HTTP/2 bearer=v2 channel-bound
    ```
    (для `--type=tls` вместо `boring-tls: …` — `[clean-vpn] tls: TLS channel-binding OK …`). На exit: `tls vpn: connected …` **без** `bearer_legacy=1`.

    **Полный token и exporter_b64** (для curl-теста channel binding) — только с флагом **`--tls-log-bearer`** на client **и** exit (или env `CLEAN_VPN_TLS_LOG_BEARER=1`):
    ```bash
    node scripts/clean-vpn.js --role=client --type=boring-tls --tls-log-bearer …
    ```
    Дополнительные строки:
    ```
    [clean-vpn] boring-tls: helper ok-frame (length-prefixed JSON на stdout, не stderr) alpn=h2 exporter=K7x…=
    [clean-vpn] tls bearer debug (client h2): token=abcdef… exporter_b64=K7x…= legacy=0
    ```
    Для `--type=tls` строки `ok-frame` нет — exporter из `tlsSock.exportKeyingMaterial()`; при `--tls-log-bearer` видна `tls bearer debug (client h2|client http1)`.

  - **Корректность фикса (channel binding).** Включить debug Bearer на **обеих** сторонах, поднять легитимный VPN, скопировать `token=` из лога, затем **новая** TLS-сессия с чужим Bearer:

    ```bash
    # Шаг 1 — легитимное подключение, снять Bearer v2
    node scripts/clean-vpn.js --role=client --type=boring-tls --tls-log-bearer \
      --server=EXIT_IP:443 --tls-cert-dir=./certs --shared-hmac-key=./certs/clean-vpn-hmac.key …
    # exit тоже с --tls-log-bearer — в логе:
    # [clean-vpn] tls bearer debug (exit http2 accept): token=… exporter_b64=… legacy=0
    # [clean-vpn] tls vpn: connected … windowOffset=0 http=HTTP/2   ← без bearer_legacy=1

    STOLEN=abcdef0123456789abcdef0123456789   # token= из лога (32 hex-символа)

    # Шаг 2 — новая TLS-сессия B, подставить STOLEN (другой TCP + другой exporter → v2 не сойдётся)
    curl -vk --http1.1 \
      --cacert ./certs/clean-vpn-ca.pem \
      --resolve "clean-vpn:443:EXIT_IP" \
      -H "Authorization: Bearer ${STOLEN}" \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      -H "Accept: */*" \
      "https://clean-vpn/clean-vpn"
    ```
    **Ожидание на client (curl):** HTTP/1.1 200, тело `It works!` (cover-страница), **не** бинарный VPN-поток.

    **Ожидание на exit:**
    ```
    [clean-vpn] tls bearer debug (exit http1 reject): token=abcdef… exporter_b64=<другой, чем в сессии A> legacy=0
    [clean-vpn] tls cover: served ip=… reason=cover_bad_bearer prefix=… http=HTTP/1.1
    ```
    VPN-мост **не** поднимается (`tls vpn: connected` **нет**).

    Для HTTP/2 client'а негативный тест через curl неудобен (нужен POST + h2); достаточно HTTP/1.1 curl выше — проверка Bearer/exporter та же на exit.

    **Переходный v1 (для сравнения):** старый client без exporter → exit: `bearer_legacy=1` + warning «принят legacy Bearer».

### Fixed C-2 — WebRTC / rtc-chrome / udp-punch — сигналинг без аутентификации

- **В чём была уязвимость.** Сигналинг для `webrtc`, `rtc-chrome`, `udp --punch` шёл по plain `ws://` без HMAC/подписи. MITM сигналинга мог подменить SDP/DTLS-fingerprint и провести MITM на DTLS DataChannel (Chrome/libdatachannel проверяет fingerprint **только из перехваченного SDP**); MITM `clean-vpn-udp-reflexive` мог направить UDP-punch в подконтрольный endpoint.
- **Как починили.** В `[scripts/clean-vpn.js](clean-vpn.js)` добавлены константы `SIGNALING_BIND_CONTEXT = 'clean-vpn-signal-bind'`, `SIGNALING_BIND_MSG_TYPE = 'clean-vpn-bind'`, `SIGNALING_BIND_TS_WINDOW_MS = 5*60*1000`, аналогичные `SIGNALING_UDPBIND_`* для udp-punch. Утилиты `signSignalingBind` / `verifySignalingBind` (HMAC-SHA256 от `ctx || ts || nonce || dtls_fingerprint`), `signUdpPunchBind` / `verifyUdpPunchBind` (без fingerprint — UDP). `loadSignalingPskOrWarn` загружает `clean-vpn-hmac.key` для сигналинговых веток. В `attachCleanVpnWebrtcExitSignaling` / `attachCleanVpnWebrtcClientSignaling`: после `setLocalDescription` извлекается `a=fingerprint` через `extractDtlsFingerprintFromSdp`, отправляется подписанный `clean-vpn-bind` (fingerprint + nonce + ts + mac), пир проверяет HMAC и хранит `expectedRemoteFingerprint`; при получении remote `offer`/`answer` SDP fingerprint сверяется с подписанным (`signalingFingerprintsEqual`). Nonce кладётся в `seenNonces` (replay-protection). Для `rtc-chrome` embedded JS в `buildRtcChromeEmbeddedPageHtml` реализованы те же шаги через **Web Crypto API** (`crypto.subtle.importKey` + `crypto.subtle.sign` для HMAC-SHA256). Для `udp --punch` в `runUdpPunchAsPeer` обмен `clean-vpn-udp-bind` с HMAC + nonce + ts происходит **до** обмена reflexive endpoint'ами. Флаг `--signaling-psk-required` (default `true`) обязателен; для отладки можно отключить.
- **Остаточный риск.** Сигналинг по-прежнему идёт plain `ws://` — DPI всё ещё видит факт сигналинга и его метаданные (но не может подменить fingerprint). PSK не ротируется автоматически — управление ключом остаётся на пользователе.
- **Как проверить.**
  - **Работоспособность транспорта.**
    - `**--type=webrtc`:** exit `--signaling`, client `--split-default`, **одинаковый** `clean-vpn-hmac.key` на обеих сторонах — ICE/DTLS, DataChannel, `curl -4` через VPN.
    - `**--type=rtc-chrome`:** client с Chrome, exit `--type=webrtc --signaling`, общий PSK — то же.
    - `**--type=udp --punch`:** exit `--signaling --punch`, client `--punch --server=VPS:PORT`, общий PSK — в логах `UDP punch: подпись peer'а ОК (C-2)`, затем `connected` к пиру, VPN через UDP.
  - **Корректность фикса (PSK обязателен).** Запустить webrtc/udp-punch **без** `clean-vpn-hmac.key` (и без `--shared-hmac-key`) при default `--signaling-psk-required` — процесс должен завершиться с ошибкой про отсутствие PSK. С `--signaling-psk-required=false` — подключение возможно, в логах warning о пропуске C-2 (только для отладки).
  - **Корректность фикса (bind в wire).** Перехватить WS-сигналинг (tcpdump/wireshark на порту `PORT+1` для udp-punch или webrtc signaling port): первые служебные JSON после connect — `{"type":"clean-vpn-bind",…}` или `{"type":"clean-vpn-udp-bind",…}` с полями `nonce`, `ts`, `mac` (и `fingerprint` для webrtc).
  - **Корректность фикса (неверный PSK).** Client с **другим** `clean-vpn-hmac.key`, чем на exit — bind не проходит, WebSocket закрывается / udp-punch падает с `подпись пира недопустима (bind_mac_mismatch)` или аналогом.
  - **Корректность фикса (fingerprint mismatch, webrtc).** MITM-тест в lab: подменить `a=fingerprint` в SDP, не меняя bind — peer должен отклонить offer/answer до установки DTLS (close с reason про fingerprint mismatch).

---

## 6. Необходимость каждого транспорта

Оценка ценности vs. поддержки. Решение принимается с учётом anti-censorship use case.

### 6.1. `tls` — **keep** (основной)

- **Ценность:** основной production-transport. Маскировка под HTTPS, cover «It works!», passthrough к probe-target, Bearer HMAC.
- **Риски:** H-2, M-1, M-2 (см. выше).
- **Рекомендация:** оставить, прокачать H-2 (channel binding) и M-1 (rate-limit).

### 6.2. `boring-tls` — **keep optional** (когда важен JA3-fingerprint)

- **Ценность:** контроль над ClientHello через BoringSSL helper для имитации Chrome (см. `[scripts/boring-tls-plan.md](boring-tls-plan.md)`).
- **Риски:** доп. attack surface (child-process IPC, `ca_pem` в JSON-frame); сборка тяжёлая.
- **Рекомендация:** оставить как опциональный режим для сред с активным JA3-фильтром. Документировать как «advanced».

### 6.3. `combo-tls` — **keep optional** (порт :443 для всего)

- **Ценность:** уникальный — VPN-TUN (boring-TLS) + transparent HTTPS-перехват (CVPTX) на одном `:443`. Минимизирует footprint открытых портов.
- **Риски:** H-3 (CVPTX magic), M-4 (peek timeout), сложность поддержки.
- **Рекомендация:** оставить, но H-3 нужно адресовать (либо обфускация magic, либо встроить CVPTX в TLS-mux).

### 6.4. `transparent-tls` — **keep** (уникальная фича)

- **Ценность:** HTTPS-перехват без перехода на default-route + перенос app-уровня к exit. Нет альтернатив с этой семантикой.
- **Риски:** H-3, M-3, IPv4 mux — open relay (часть C-1).
- **Рекомендация:** оставить, но IPv4 mux требует C-1 (auth handshake).

### 6.5. `quic-ext` — **keep** (основной QUIC)

- **Ценность:** UDP-транспорт с TLS 1.3, библиотека quiche через `@infisical/quic`, работает на Node 18+.
- **Риски:** H-1 (нет post-handshake auth).
- **Рекомендация:** оставить, добавить Bearer внутри stream (H-1 fix).

### 6.6. `quic` (node:quic) — **deprecate-candidate**

- **Ценность:** нативный `node:quic`, тот же ALPN-style, та же семантика, что `quic-ext`.
- **Минусы:** требует **Node 25+** и сборку Node с `node_use_quic` (часто отсутствует в apt/snap), нет HMAC retry, в остальном дублирует quic-ext.
- **Рекомендация:** **удалить** или пометить как «experimental, для бенчмарков»; на production использовать `quic-ext`.

### 6.7. `webrtc` — **keep** (для NAT-traversal)

- **Ценность:** единственный transport с полноценным ICE/STUN/TURN из коробки. Полезен, когда между client и exit нет прямой связности (CG-NAT, symmetric NAT).
- **Риски:** C-2 (сигналинг), M-5 (IP-утечка).
- **Рекомендация:** оставить, исправить C-2 (HMAC сигналинга) и M-5 (дефолт relay).

### 6.8. `rtc-chrome` — **keep optional** (когда нужен Chrome-fingerprint)

- **Ценность:** имитация реального Chrome WebRTC stack (DTLS-fingerprint, ICE-поведение). Уникальна для обхода DPI, который фильтрует node-datachannel.
- **Минусы:** Puppeteer + Chrome — тяжёлая зависимость, локальная attack surface (H-4).
- **Рекомендация:** оставить как опциональный режим. Документировать как «advanced».

### 6.9. `websocket` — **deprecate-candidate** или **debug-only**

- **Ценность:** plain `ws://`. В производстве — низкая (без TLS = легко детектится DPI; маскировка только под трафик `:80`). Полезен для отладки и сценария «WSS терминирует nginx впереди».
- **Риски:** C, I, A, R, AB, P — все «none».
- **Рекомендация:** оставить как **debug** transport. В документации явно: «production: только за nginx с WSS». Либо добавить `wss://` поверх него (отдельный режим).

### 6.10. `ws-chrome` — **keep optional** (узкая ниша)

- **Ценность:** маскировка WebSocket-handshake под Chrome (TLS-fingerprint + HTTP-заголовки). Полезен при WSS-варианте; для plain `ws://` ценность ниже.
- **Минусы:** Puppeteer overhead, H-4, ws:// без TLS на wire.
- **Рекомендация:** оставить опциональным; нужно перевести на WSS (через nginx или встроенный TLS), иначе ценность Chrome-fingerprint теряется (TLS-handshake = единственное, что fingerprintsится).

### 6.11. `udp` (без `--punch`) — **keep** (когда есть белый IP)

- **Ценность:** низкая латентность, простая семантика «датаграмма = пакет».
- **Риски:** C-1 (open relay).
- **Рекомендация:** оставить, но добавить HMAC handshake (часть C-1). Иначе только debug.

### 6.12. `udp --punch` — **keep** (NAT-traversal с UDP)

- **Ценность:** прямой UDP без relay, когда обе стороны за NAT.
- **Риски:** C-2 (сигналинг), C-1 (данные).
- **Рекомендация:** оставить, исправить C-2 и C-1.

### 6.13. `socket` — **debug-only** или **deprecate-candidate**

- **Ценность:** голый TCP + uint32+IPv4. Самый простой транспорт, эталон для тестов.
- **Риски:** C-1 (open relay).
- **Рекомендация:** оставить как **debug** (например, `--insecure-debug` warning при старте). Либо добавить HMAC handshake — фактически приведёт к простому secure-варианту.

### 6.14. `http` — **deprecate-candidate**

- **Ценность:** маскировка под HTTP-сервер (любой `GET /clean-vpn`, ответ 200, далее uint32+IPv4). По защите эквивалентно socket.
- **Минусы:** маскировка слабая (DPI легко детектит «HTTP-сервер, который шлёт mismatched content-type»), а защиты как у `socket` (none).
- **Рекомендация:** **удалить** или объединить с `socket` под флагом `--http-preamble`. Если нужна обёртка под HTTP — использовать `tls` / `combo-tls`, там полноценный HTTP/2 внутри TLS.

---

## 7. Что можно безболезненно удалить или объединить


| Действие                              | Транспорт                       | Обоснование                                                           |
| ------------------------------------- | ------------------------------- | --------------------------------------------------------------------- |
| Удалить                               | `http`                          | Эквивалент `socket` по защите, маскировка слабая, заменяется на `tls` |
| Удалить или пометить experimental     | `quic` (node:quic)              | Дублирует `quic-ext`, требует Node 25+, нет HMAC retry                |
| Пометить debug-only                   | `socket`, `websocket` (без TLS) | Production непригодны без внешнего шифрования                         |
| Объединить в один опциональный пресет | `boring-tls` + `combo-tls`      | На клиенте оба идут через тот же helper                               |
| Дефолт relay                          | `webrtc`, `rtc-chrome`          | Снижает IP-утечку (M-5)                                               |


---

## 8. Что не покрывает этот документ

- Целостная картина безопасности (firewall на VPS, OS hardening, ротация PSK, secure logging) — отдельная работа.
- Анализ нативного `[native/boring_tls/](../native/boring_tls/)` helper-процесса (см. `[scripts/boring-tls-plan.md](boring-tls-plan.md)`).
- Анализ TUN-уровня и потенциальных побочных каналов через `attachTunBridge` (cooldown, keep-alive).
- IPv6: см. отдельный `[scripts/ipv6-plan.md](ipv6-plan.md)` — там же отмечены IPv6-specific риски (RA, ND, ICMPv6).

---

## Указатель ключевых мест в коде


| Тема                                   | Файл и строки                                                                         |
| -------------------------------------- | ------------------------------------------------------------------------------------- |
| Shared HMAC PSK файл                   | `[scripts/clean-vpn.js](clean-vpn.js)` ~243-258                                       |
| Bearer compute / verify                | `[scripts/clean-vpn.js](clean-vpn.js)` ~605-635                                       |
| TLS exit cover/passthrough             | `[scripts/clean-vpn.js](clean-vpn.js)` ~4746-4802, ~5083-5116, ~5264-5275             |
| QUIC-ext exit/client config            | `[scripts/clean-vpn.js](clean-vpn.js)` ~6867-6877, ~7657-7666                         |
| socket/http/transparent-tls ветка exit | `[scripts/clean-vpn.js](clean-vpn.js)` ~6389-6436                                     |
| HTTP preamble (без auth)               | `[scripts/clean-vpn.js](clean-vpn.js)` ~5384-5417                                     |
| WebRTC apply signal                    | `[scripts/clean-vpn.js](clean-vpn.js)` ~2333-2343                                     |
| UDP punch signaling                    | `[scripts/clean-vpn.js](clean-vpn.js)` ~2248-2263                                     |
| Локальный 127.0.0.1 WS Chrome          | `[scripts/clean-vpn.js](clean-vpn.js)` ~5666-5677, ~5969-5980, ~1954-2058             |
| CVPTX magic                            | `[scripts/lib/transparent-tls-wire.mjs](lib/transparent-tls-wire.mjs)` ~5-47          |
| CVPTX plaintext warning                | `[scripts/lib/transparent-tls-runtime.mjs](lib/transparent-tls-runtime.mjs)` ~439-442 |


