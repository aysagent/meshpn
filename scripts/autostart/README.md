# clean-vpn: автозапуск через systemd

Простой автозапуск без hot-reload и без бота. Установщик генерирует
`/usr/local/bin/<SERVICE_NAME>-run.sh` с зашитыми аргументами и ставит systemd-юнит,
который запускает `scripts/clean-vpn.js` **из этого репозитория** (удобно на этапе
разработки/тестирования).

## Установка / обновление

Всё, что идёт после `install.sh`, — это аргументы `clean-vpn.js` как есть:

```bash
sudo env "PATH=$PATH" scripts/autostart/install.sh \
  --role=exit --server=0.0.0.0:443 --type=combo-tls --keep-alive=5 \
  --tls-probe-target=www.trustpilot.com:443 --tls-public-name=www.trustpilot.com
```

Пример для client:

```bash
sudo env "PATH=$PATH" scripts/autostart/install.sh \
  --role=client --server=62.84.120.30:443 --type=combo-tls --keep-alive=5 \
  --split-default --tls-client-sni=www.trustpilot.com --tls-public-name=www.trustpilot.com \
  --boring-tls-clienthello-profile=/root/dev/meshpn/browser-profile.json \
  --client-lan-subnet=192.168.7.0/24
```

Повторный запуск с новыми аргументами полностью перезаписывает `run.sh` и юнит
и делает `restart` — это и есть «обновить актуальным».

`sudo env "PATH=$PATH" ...` нужен, чтобы установщик нашёл ваш `node` (важно при nvm).

## Опции установщика (через env)

- `SERVICE_NAME` — имя сервиса, default `clean-vpn`. Влияет и на имя run.sh
  (`/usr/local/bin/<SERVICE_NAME>-run.sh`), поэтому на одной машине можно держать
  несколько сервисов (напр. `clean-vpn` и `clean-vpn-exit`).
- `NODE_BIN` — путь к `node`, если автодетект не подходит:

```bash
sudo NODE_BIN=/root/.nvm/versions/node/v24.13.0/bin/node \
  scripts/autostart/install.sh --role=exit --type=combo-tls ...
```

Два сервиса на одной машине:

```bash
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn-exit scripts/autostart/install.sh --role=exit ...
sudo env "PATH=$PATH" SERVICE_NAME=clean-vpn-cli  scripts/autostart/install.sh --role=client ...
```

## Управление

```bash
systemctl status clean-vpn
journalctl -u clean-vpn -f          # логи
sudo systemctl restart clean-vpn
sudo systemctl stop clean-vpn       # SIGTERM → откат маршрутов/NAT
```

## Удаление

```bash
sudo scripts/autostart/uninstall.sh
sudo SERVICE_NAME=clean-vpn-exit scripts/autostart/uninstall.sh
```

## Что создаётся

- `/usr/local/bin/<SERVICE_NAME>-run.sh` — обёртка: выставляет `PATH`
  (с `/usr/sbin`,`/sbin` для `iptables`/`ip`/`sysctl`), делает `cd` в корень репозитория
  и `exec node scripts/clean-vpn.js <аргументы>`.
- `/etc/systemd/system/<SERVICE_NAME>.service` — юнит: `Type=simple`, `Restart=always`,
  `After/Wants=network-online.target`, `TimeoutStopSec=15`.

## Заметки

- Сервис исполняется от root (нужно для TUN/iptables) — это дефолт system-юнита.
- Пути к сертификатам/`--config` в аргументах лучше указывать **абсолютными**
  (юнит делает `cd` в корень репо, но абсолютные надёжнее).
- Сервис ссылается на `clean-vpn.js` в текущем репозитории; при переносе репозитория
  перезапустите установщик, чтобы обновить пути в `run.sh`.
