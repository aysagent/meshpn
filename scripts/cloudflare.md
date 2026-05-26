# clean-vpn за Cloudflare (free)

Как завернуть VPS за Cloudflare бесплатно, чтобы трафик к VPS выглядел как обращения к серверам Cloudflare CDN. Включая ограничения, подводные камни и совместимость с транспортами clean-vpn.

---

## Главный риск, который надо понять сразу

Cloudflare на free plan **терминирует ваш TLS** — независимо от настройки SSL/TLS mode (Flexible / Full / Full Strict). Это значит:

- **DPI до Cloudflare** видит только TLS к IP Cloudflare (`104.x.x.x`, `172.67.x.x`). Это и есть желаемый эффект «выглядит как CDN».
- **Cloudflare сам видит ваш VPN-трафик в plaintext** — все WS-кадры, Bearer-токены, IPv4-пакеты из TUN. Cloudflare обязан соблюдать запросы юрисдикции, и в их ToS прямо есть запрет на «использование сервиса для проксирования произвольного трафика, не являющегося web-content» (раздел 2.8 / Self-Serve Subscription Agreement).
- В терминах [`clean-vpn-security-analysis.md`](clean-vpn-security-analysis.md) Cloudflare становится **полностью доверенным** посредником с правом читать всё.

Если эта модель приемлема (anti-censorship на стороне выхода в интернет, не anti-Cloudflare) — план ниже подходит. Если нет — это путь не для вас.

---

## Совместимость наших транспортов с CF (free plan)

| `--type` | Через CF proxy? | Почему |
|----------|:---------------:|--------|
| `websocket` (WSS) | **Да** | WS upgrade проксируется, binary frames пропускаются |
| `ws-chrome` | **Да** | то же, WSS upgrade; Chrome нативно делает WSS |
| `http` | Нет | После `\r\n\r\n` CF ждёт нормальный HTTP-response, не сырой бинарь |
| `tls` | Нет | CF делает TLS termination; HTTP/2 stream с открытым телом и Bearer переупаковывается. Технически работает, но 100-секундный idle timeout и буферизация ломают сессии |
| `combo-tls`, `boring-tls`, `transparent-tls` | Нет | CF терминирует TLS — JA3 умирает на CF, CVPTX в plain не пройдёт |
| `quic`, `quic-ext`, `udp`, `udp --punch` | Нет | CF не проксирует raw UDP/QUIC client↔origin на free (это **Cloudflare Spectrum**, ~$200+/мес) |
| `webrtc`, `rtc-chrome` | Нет | WebRTC через CDN не работает |

**Единственный реальный путь — `--type=websocket` (или `ws-chrome`) поверх WSS.**

### Подводный камень в текущем коде

В текущем [`clean-vpn.js`](clean-vpn.js) клиент `--type=websocket` создаёт `new WebSocket('ws://...')` (~7200, ~7221) — **только plaintext WS**, не WSS. Чтобы достучаться до Cloudflare, нужен один из вариантов:

1. **Локальный TLS-frontend на клиенте**: stunnel или nginx, который терминирует исходящий WSS к CF и отдаёт `ws://` локально на clean-vpn.
2. **Дописать WSS-режим в `--type=websocket`** (несложно — `ws` библиотека уже подключена; см. [`wss.md`](wss.md) про WSS-режим в `--type=tls`).
3. **`--type=ws-chrome`** — Puppeteer-Chrome **уже умеет WSS** (это нативный браузер). Минус: Chrome на клиенте.

---

## Путь A: Cloudflare proxy (orange cloud) + ваш VPS

«Классическая» схема. Нужен домен.

### A.1. Подготовка

1. **Домен.** Бесплатных не осталось (Freenom умер). Минимум:
   - **Cloudflare Registrar** (`.com` ~$10/год по cost-price),
   - PorkBun `.top` / `.xyz` за $1-2 на первый год,
   - `*.is-a.dev` / `*.js.org` через бесплатные SLD-сервисы — но многие из них не дают подключить orange cloud, потому что NS не передаются Cloudflare.

2. **Подключить домен к Cloudflare.** Бесплатный план: добавить сайт → CF выдаст 2 NS → поменять у регистратора.

3. **DNS-запись:**
   - `vpn` (например `vpn.example.com`) → A → IP VPS → **proxy status: Proxied (orange cloud)**.
   - Никаких `AAAA`, если IPv6 не используете.

4. **SSL/TLS mode** в CF: **Full (strict)** — требует валидного TLS на origin (LE или CF Origin Certificate).

### A.2. На VPS (Linux)

5. **TLS на 443 на VPS.** Два варианта:

   **nginx + Let's Encrypt** (через DNS-01, потому что 443 за CF):
   ```bash
   apt install nginx certbot python3-certbot-dns-cloudflare
   # ~/.cloudflare.ini с API token для DNS:edit
   certbot certonly --dns-cloudflare \
     --dns-cloudflare-credentials ~/.cloudflare.ini \
     -d vpn.example.com
   ```

   `/etc/nginx/sites-enabled/vpn.conf`:
   ```nginx
   server {
     listen 443 ssl http2;
     server_name vpn.example.com;
     ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
     ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;

     location /clean-vpn {
       proxy_pass http://127.0.0.1:8765;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "Upgrade";
       proxy_set_header Host $host;
       proxy_buffering off;
       proxy_read_timeout 3600s;
       proxy_send_timeout 3600s;
     }

     location / {
       return 200 "It works!\n";
       add_header Content-Type text/plain;
     }
   }
   ```

   **Cloudflare Origin Certificate** (живёт 15 лет, выпускается мгновенно из CF dashboard → SSL/TLS → Origin Server). Используется только между CF и origin — публичные браузеры его не примут, но это и не нужно.

6. **clean-vpn на 127.0.0.1:8765:**
   ```bash
   sudo node scripts/clean-vpn.js --role=exit \
     --server=127.0.0.1:8765 --type=websocket --ws-server
   ```
   Порт 443 — только у nginx; clean-vpn доступен только с localhost.

7. **Firewall.** На VPS закрыть всё, кроме CF IP диапазонов на 443 — блокирует прямое обращение в обход CF:
   ```bash
   # https://www.cloudflare.com/ips/
   for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
     iptables -A INPUT -p tcp -s $ip --dport 443 -j ACCEPT
   done
   iptables -A INPUT -p tcp --dport 443 -j DROP
   ```

### A.3. На клиенте

8. **Локальный stunnel** для WSS-фронтенда (если не патчим clean-vpn под WSS):

   `/etc/stunnel/clean-vpn.conf`:
   ```
   client = yes
   foreground = no

   [clean-vpn-cf]
   accept = 127.0.0.1:18765
   connect = vpn.example.com:443
   sni = vpn.example.com
   verifyChain = yes
   CAfile = /etc/ssl/certs/ca-certificates.crt
   ```

   Затем clean-vpn:
   ```bash
   sudo node scripts/clean-vpn.js --role=client \
     --server=127.0.0.1:18765 --type=websocket --split-default \
     --tunnel-peer=vpn.example.com --keep-alive=60
   ```

   В коде клиента URL по умолчанию — `ws://127.0.0.1:18765/`; stunnel оборачивает в TLS и подменяет SNI на `vpn.example.com`. `--tunnel-peer=vpn.example.com` прописывает `/32`-bypass на CF anycast IP через uplink.

   **Альтернатива** — `--type=ws-chrome`: Chrome сам ходит на `wss://vpn.example.com/clean-vpn` без stunnel.

---

## Путь B: Cloudflare Tunnel (`cloudflared`) — без открытых портов на VPS

Часто **значительно проще**, особенно если VPS за NAT/файрволом:

- VPS **не публикует никаких портов в интернет**.
- `cloudflared` устанавливает обратное подключение **к** CF и держит туннель.
- CF принимает входящие на `https://vpn.example.com` и заворачивает в туннель к VPS.
- На клиенте всё то же — `wss://vpn.example.com/clean-vpn`.

### B.1. Шаги

1. **На VPS:**
   ```bash
   # https://pkg.cloudflare.com/index.html
   wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
   dpkg -i cloudflared-linux-amd64.deb

   cloudflared tunnel login
   cloudflared tunnel create cleanvpn
   cloudflared tunnel route dns cleanvpn vpn.example.com
   ```

2. **`~/.cloudflared/config.yml`:**
   ```yaml
   tunnel: cleanvpn
   credentials-file: /root/.cloudflared/<tunnel-uuid>.json

   ingress:
     - hostname: vpn.example.com
       service: http://127.0.0.1:8765
       originRequest:
         noTLSVerify: true
         connectTimeout: 30s
         tlsTimeout: 10s
         keepAliveTimeout: 90s
         disableChunkedEncoding: true
     - service: http_status:404
   ```

3. **Запустить:**
   ```bash
   cloudflared tunnel run cleanvpn
   # или сервис:
   cloudflared service install
   ```

4. **clean-vpn на VPS:**
   ```bash
   sudo node scripts/clean-vpn.js --role=exit \
     --server=127.0.0.1:8765 --type=websocket --ws-server
   ```

5. На клиенте — то же, что в варианте A (stunnel / ws-chrome / WSS-патч).

### B.2. Плюсы / минусы

**Плюсы:**
- Не нужен публичный IP на VPS.
- Не нужно открывать порты.
- TLS-сертификат CF делает сам.
- Не нужно фильтровать IP CF на iptables — VPS просто недоступен снаружи.

**Минусы:**
- Зависимость от `cloudflared` (отдельный бинарь, обновления).
- Туннель работает поверх QUIC к CF — если ISP блокирует UDP, есть fallback на HTTP/2 (`--protocol http2`).
- WebSocket idle timeout ~100s тот же (см. ниже).

---

## Подводные камни (общие для A и B)

### 1. Idle timeout 100 секунд

CF свободного плана **рвёт HTTP/WSS соединения через ~100 секунд бездействия**. У нас есть `--keep-alive=N` в clean-vpn (см. шапку [`clean-vpn.js`](clean-vpn.js), ~84) — поставьте `--keep-alive=60`. Это будет периодически слать данные через мост, обнуляя idle timer. Библиотека `ws` сама шлёт ping/pong, но CF на это не всегда реагирует — лучше держать **прикладные** ping'и.

### 2. MTU и фрагментация

WS-кадр через WSS внутри TLS: накладные расходы ~10-15 байт WS-header + TLS overhead 22-40 байт + сетевые заголовки. IPv4-пакеты 1500 байт после оборачивания будут резаться. Установите MTU на TUN ниже стандартного:

- В коде уже есть `TUN_MTU` ([`clean-vpn.js`](clean-vpn.js) ~3531) — для CF practical 1280-1380 безопасно.

### 3. Cloudflare Trust & Safety / ToS

- ToS section 2.8: запрет на «non-HTML content delivery, including but not limited to streaming, downloads, online gaming». VPN — серая зона.
- Триггеры аккаунта: большой объём (TB+ в месяц), много мелких WS-кадров с большим upload — могут вызвать ручную проверку.
- На практике до десятков GB в месяц обычно никто не тревожит, но **гарантий нет**, аккаунт могут забанить, и тогда CDN/Tunnel теряете (домен остаётся, если зарегистрирован в CF Registrar).

### 4. JA3/JA4 и DPI

После того как клиент ходит на CF IP с TLS-handshake к **Cloudflare**:
- TLS-handshake виден DPI **как обычный** TLS к Cloudflare — типовой JA3 (Chrome / curl / stunnel — в зависимости от того, что у вас на клиенте).
- К origin (VPS) идёт **Cloudflare TLS** — типовой JA3 Cloudflare egress (это видит только тот, кто между CF и origin, обычно никто).
- DPI **не видит** ваш `boring-tls` JA3, потому что CF делает handshake вместо вас. Это плюс для anti-censorship, но **минус** для тех, кто полагался на кастомный JA3 — `boring-tls` теряет смысл за CF.

### 5. Bypass-маршрут к CF на клиенте

Если на клиенте `--split-default`, нужно **bypass к CF IP'ам** через uplink, иначе соединение зациклится. Сейчас в `setupClientRoutesAsync` ([`clean-vpn.js`](clean-vpn.js) ~3580+) bypass добавляется к `--server` host'у. Со stunnel это `127.0.0.1` (никаких маршрутов), реальный bypass нужно делать к **`vpn.example.com`** — а это CF anycast IP, который может меняться.

Хитрость: `--tunnel-peer=vpn.example.com` или `--tunnel-peer=<один CF IP>` пропишет `/32` через uplink. Лучше — bypass для всего CF range:

```bash
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
  ip route add $ip via $GW dev $UPLINK
done
```

### 6. Cloudflare-добавляемые заголовки

CF добавляет к запросу: `CF-Connecting-IP`, `X-Forwarded-For`, `CF-Ray`, `CF-IPCountry`. Origin (clean-vpn / nginx) их видит, можно использовать для логирования. Это нормально и не мешает.

---

## Что НЕ получится бесплатно на CF

- **Raw TCP/UDP** между клиентом и origin (нужен **Cloudflare Spectrum**, $200+/мес).
- **TLS passthrough** (CF читает ваш TLS — это и есть free-режим).
- **Прямой QUIC** клиент↔origin (только клиент↔CF может быть HTTP/3).
- **Bypass HTTP-протокольной модели** — всё, что не HTTP/WS, через free не пройдёт.

---

## Минимально работающий setup для production (TL;DR)

1. Купить домен ($1-10/год).
2. Подключить к Cloudflare, **proxied A-запись** к VPS.
3. **SSL/TLS: Full (strict)** + Cloudflare Origin Certificate.
4. На VPS:
   - nginx с CF Origin Cert на 443 + WSS proxy_pass на `127.0.0.1:8765`,
   - `clean-vpn --role=exit --type=websocket --ws-server --server=127.0.0.1:8765 --keep-alive=60`,
   - iptables: на 443 — только CF IPs.
5. На клиенте:
   - stunnel `127.0.0.1:18765` → `vpn.example.com:443` (SNI),
   - bypass на CF IPs через uplink,
   - `clean-vpn --role=client --type=websocket --server=127.0.0.1:18765 --tunnel-peer=vpn.example.com --split-default --keep-alive=60`.

**Альтернатива «попроще»:** Cloudflare Tunnel (`cloudflared`) — снимает nginx, LE-серт, iptables-фильтрацию CF, открытый порт 443 на VPS. Всё то же, но на VPS только `cloudflared` + clean-vpn на localhost.

---

## Альтернативы, если CF не устраивает

| Сервис | Особенности |
|--------|-------------|
| **Fastly** (free Compute tier) | CDN с TLS termination, поддерживает WSS; `Fastly@Edge` лимиты строже |
| **Bunny.net** | CDN с WSS, ~$1/мес минимум, не free |
| **AWS CloudFront** + Lambda@Edge | сложно, не free после 12 месяцев |
| **Самостоятельный shared фронтенд** | nginx на дешёвом «домено-IP» VPS, без CDN — фактически только смена IP, не CDN-camouflage |
| **Tor + obfs4** | бесплатно, но медленно и DPI Tor-bridges детектят |
| **WireGuard на 443/UDP** | без камуфляжа CDN |

Для **anti-censorship поверх CDN** Cloudflare остаётся самым практичным бесплатным вариантом.

---

## Связь с другими документами

- [`wss.md`](wss.md) — почему WSS — единственный путь через CF, и как добавить WSS-режим в существующие TLS-вариации, чтобы убрать stunnel-обвязку на клиенте.
- [`nginx.md`](nginx.md) — конфигурация nginx как WSS-фронтенда (вариант A.2 здесь — частный случай).
- [`clean-vpn-security-analysis.md`](clean-vpn-security-analysis.md) — модель угроз; за CF добавляется новый «доверенный наблюдатель» (Cloudflare).
- [`clean-vpn-diagrams.md`](clean-vpn-diagrams.md) — общая архитектура транспортов.
