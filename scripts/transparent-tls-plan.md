# transparent-tls: план (clean-vpn, SNI relay)

Каноническая копия плана в репозитории: изучение и реализация от этого файла.

## Backlog (кратко)

- **MVP scope:** Linux, IPv4, `REDIRECT`/`SO_ORIGINAL_DST`, same-length SNI, патч только первого ClientHello.
- **Протокол client→exit** поверх **`--type=socket`:** кадры (session / dst / port / поля restore + payload TLS stream); PSK/HMAC для контрольных полей (как у Bearer) — не замена конфиденциальности на участке client↔exit.
- **Парсер TLS:** record + handshake state machine или буферизованный MVP.
- **Интеграция:** `--type=transparent-tls` в [`scripts/clean-vpn.js`](clean-vpn.js) без поломки TUN-пути; help + при необходимости отдельный md.

## 1. Цель режима и границы

**Цель.** Скрыть **настоящий SNI** на участке между **клиентской стороной clean-vpn** и **exit**: приложение ведёт обычный TLS к origin, но локально в первый **ClientHello** подставляется **фейковый `server_name`** (в MVP желательно **той же длины**, чтобы не двигать длины сообщений); на **exit** нужные байты восстанавливаются перед `connect(origin)` и дальнейшим байт-проксированием.

**Не цель режима.**

- Поверх приложенческого TLS не добавлять **ещё один TLS record-layer средствами того же режима.** В частности, **не** брать **`--type=tls` на участке clean-vpn client↔exit как оболочку для потоков transparent-tls**: получится второй TLS вокруг байтов уже шифрующего TLS приложения.
- Полная замена JA3/JA4 (наоборот, стремиться к минимуму изменений кроме SNI / расширения 0 там, где можно без сдвига длин).

**Имя `transparent-tls` в коде / help.** Пояснять как **TCP TLS ClientHello SNI relay**, чтобы не путать с существующим VPN-транспортом **`--type=tls`** в [`scripts/clean-vpn.js`](clean-vpn.js).

## 2. Контекст clean-vpn: что уже есть и что нужно

- **[`scripts/clean-vpn.js`](clean-vpn.js)**: соединение **client ↔ exit** с разными **типами транспорта** — `socket`, `http`, `websocket`, `tls`, `boring-tls`, QUIC и др.; основной режим сейчас несёт **IPv4-пакеты с TUN** (длина + payload). Совместимость типов задаётся в скрипте (напр. пары типов для client/exit).
- **Перехват приложений** через iptables REDIRECT/TPROXY и **`SO_ORIGINAL_DST`** в репозитории **нет** — отдельная новая работа на клиентской машине рядом с клиентским процессом clean-vpn / прозрачным прокси.

Нужны: **локальный TCP-прокси на клиенте**, **relay на exit**, и **новый тип полезной нагрузки** (фрейминг сессий) при **`--type=transparent-tls`**, явно отделённый от TUN+IPv4, без неявного смешивания.

## 3. Архитектура потоков

```mermaid
flowchart LR
  app[App_browser]
  redir[Linux_redirect]
  clProxy[Client_transparent_proxy]
  cvpnCh[CleanVpn_client_to_exit_channel]
  exProxy[Exit_relay]
  origin[Origin_TLS]

  app --> redir --> clProxy
  clProxy -->|"bytes_plus_meta"| cvpnCh --> exProxy --> origin
```

- **Клиентский прокси:** TCP после redirect, буферизация до первого **ClientHello**, парсинг, при необходимости сохранение оригинального hostname (или компактных данных для restore), **same-length** подмена SNI в MVP.
- **Exit relay:** приём «open session» (dst, port, auth), `connect()` к origin, отправка **восстановленного** начала потока и далее симметричный pipe.

### 3.1. Транспорт clean-vpn (client ↔ exit)

Речь только о **том же зоопарке `--type=...`**, что уже в [`scripts/clean-vpn.js`](clean-vpn.js), но выбранный для режима **transparent-tls** не должен сам по себе вкладывать второй TLS вокруг проксируемого TLS.

| Вариант | Рекомендация |
|--------|---------------|
| **`--type=socket`** | **Базовый выбор для transparent-tls.** Одно TCP-соединение client↔exit + **свой** фрейминг (`uint32_be + payload` и т.п.): open-session, чанки потока, закрытие. Без дополнительного TLS envelope от clean-vpn для этих байтов. |
| **`--type=tls`** для несущего канала **этого** режима | **Не рекомендуется** как целевой вариант: двойной TLS — транспортный record layer clean-vpn + TLS приложения внутри проксируемого потока. |
| **`websocket`** | Запасной вариант той же идеологии что socket (без второй «криптосессии» поверх уже TLS-тела): удобство за HTTP-прокси, свой framing поверх транспортного типа в clean-vpn. |

**Участок client↔exit при `--type=socket`.** Конфиденциальность приложения к origin обеспечивается TLS приложения; **сырые record-байты** на линке client↔exit для внешнего наблюдателя на этом участке не скрыты транспортом clean-vpn. **Метаданные** команд (куда звонить, как восстановить SNI) обязательно **подписывать / привязать к PSK** (аналоги общих секретов в существующем `tls` в скрипте), чтобы exit не выполнял произвольные `connect(dst)` по подделке. Это даёт авторизацию и целостность команд, но **не** заменяет шифрование линка; при необходимости — свой доверенный канал между хостами или нижний туннель (вне этого UX-режима).

**Не IPv4+TUN:** несколько локальных TCP-сессий приложения упаковываются в один (или несколько) канал transparent-tls, кадры вида минимально `(session_id | dst_ipv4_be | dst_port_be | … | tls_stream_chunk)`.

### 3.2. Черновик протокола кадров client↔exit (MVP)

1. После установления выбранного транспортного канала (**предпочтительно `socket`**) — handshake/авторизация режима transparent-tls на уровне прокси↔relay (PSK, по аналогии с принятыми в проекте для VPN).
2. Кадр «open»: dst, port, данные для restore SNI, **MAC** блока общим с exit ключом.
3. Далее двунаправленный **byte stream** между локальной стороной и апстримом на exit до закрытия.

Детали заголовка (session id, поля SNI, AEAD vs HMAC только на командах) — на фазу реализации без раздувания MVP.

## 4. Объём MVP vs усложнения

| Что | Относительно MVP |
|-----|-------------------|
| Linux, IPv4, `SO_ORIGINAL_DST`, same-length SNI | **В MVP** |
| Variable-length SNI + пересчёт длин handshake/record | После MVP |
| Полный TCP reassembly | После MVP; MVP: «первые N KiB содержат целый ClientHello» |
| ECH | Практически out of scope простого патча |
| HRR / второй ClientHello | Явная политика; в MVP — «только первый релевантный CH» |

## 5. Интуиция и предостережения

- При same-length и корректной TCP-последовательности схема жизнеспособна с минимальным вмешательством в fingerprint.
- Формулировка «не MITM»: вы доверенно **байтово правите** первый апстрок до exit и восстановление на exit — доверие к exit как к инфре.

## 6. Риски

1. Фрагментация первого ClientHello без стейт-машины.
2. ECH — SNI не plaintext.
3. Повторные ClientHello после HRR — политика патча.
4. DPI может коррелировать фейковый SNI у локального наблюдателя.

## 7. Фазы

**Фаза A — прототип.** REDIRECT→локальный порт, `SO_ORIGINAL_DST`, same-length патч ↔ тестовый relay; канал до exit через **`clean-vpn` с `--type=socket`** без оборачивания в **`--type=tls`** для этого испытания / или unix-сокет локально.

**Фаза B — `--type=transparent-tls`** в [`scripts/clean-vpn.js`](clean-vpn.js), без поломки существующего TUN-сценария; для начала режим можно ограничить «без поднятия TUN».

## 8. Ориентир по срокам

- MVP (ограниченный scope из п. 4): порядка **нескольких недель** одного опытного разработчика.
- Production-grade парсинг, переменная длина SNI, HRR, матрица браузеров — **×2–4** по сроку к MVP.

## 9. Файлы

- Основная обёртка: [`scripts/clean-vpn.js`](clean-vpn.js).
- Этот план: [`scripts/transparent-tls-plan.md`](transparent-tls-plan.md).
