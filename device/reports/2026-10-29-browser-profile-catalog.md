# Браузерные профили: захват, каталог, импорт — 29 октября 2026

## Реализовано

- `npm run device:profile:capture`: отдельная HTTPS-страница. При открытии
  наблюдает ClientHello браузера, сохраняет структурный профиль на диск,
  показывает каталог и выдаёт JSON для импорта. Не читает профиль из User-Agent:
  UA используется только для названия в списке.
- На плате: четыре NVS-слота плюс встроенный профиль, импорт/выбор/удаление в
  админке. Импорт не переключает туннель; применяется через Save and apply.
  ID неизменяемы, выбранный сохранённой конфигурацией профиль удалить нельзя.
- До сохранения формируется настоящий ClientHello в memory BIO на 32 KiB PSRAM
  worker, без сетевой отправки. Не совпали JA3/JA4 — профиль не сохраняется.
- Каждая новая VPN-сессия получает свою неизменяемую копию модели и собственный
  gate. Любой новый ClientHello, в том числе HRR, проверяется перед записью в
  сокет. Нет перехода на встроенный профиль при ошибке импорта/загрузки.
- CA, имя exit, HMAC key и trust policy не берутся из браузерного профиля.
  В TLS 1.3 профиль задаёт порядок ciphers, groups, shares, signature algorithms,
  extensions, ALPN и поддержанные флаги. Размеры/поля ограничены; JSON 4096 байт,
  глубина до 8 до вызова cJSON, escaped NUL и повторные ключи запрещены.

Это совпадение JA3/JA4 выбранного снимка, а не всей семантики браузера. Chromium
переставляет расширения; сохранённый порядок фиксирован. Идентификаторы trust
anchors, случайные данные, SNI-текст и ключевые доли не сохраняются. Объявление
trust anchors воспроизводится пустым списком; HTTP fingerprint не клонируется.
Поддержанный subset и команда запуска: [инструкция](../docs/browser-profile-capture.md).

## Проверки

1. Настоящий Chromium `156.0.8078.47`, Linux ARM64 в отдельном контейнере без сети
   кроме loopback. Headless, свежий процесс на каждый образец, private test CA.
   Недоверенный сертификат отклонён; после импорта CA **только в контейнер**
   три открытия страницы сохранили три разных порядка расширений. Refresh того
   же соединения не дублирует профиль. Download совпадает с каталогом; каталог
   переживает рестарт. Неверный токен даёт 404.
2. Для каждого из трёх JSON production C parser и генератор формируют три свежих
   ClientHello. Независимый JS observer подтвердил обе хеш-суммы. Повторный
   прогон сделан на ещё трёх новых браузерных снимках; они сохранены в
   `tests/fixtures/browser-profile-capture-chromium156.json` для регрессий.
3. 30 отрицательных случаев: изменённый JA3/JA4, порядок extensions, неизвестные
   поля, дубликаты, неверные числа, неподдержанные TLS параметры, размер имени,
   ID, чрезмерная вложенность и NUL. ASan/UBSan на собственном коде тестов.
4. Production NVS/API-код с host boundaries: авторизация, preview до записи,
   неизменяемость ID, защита выбранного профиля, лимит каталога, ошибки NVS,
   повреждённый blob, OOM и сохранность отдельного секрета VPN.
5. Один импортированный профиль прошёл текущий native engine: **61 попытка,
   4736 IP round-trips, 59 независимо наблюдённых ClientHello**. ALPS on/off,
   reconnect, bulk, неверные key/CA/name/profile, повреждённые ALPS. Gate совпал
   с выбранными JA3/JA4 на всех наблюдённых соединениях.
   Engine SHA256: `224894fe16d9b0fccb37a266853629357a7410620a23905120423e589600cf27`.
   Native собран из текущих исходников; чужие изменения native не редактировались.
   Вместо TUN — существующая AF_UNIX packet fixture, без VPS/маршрутов/firewall.
6. Прошли полный `scripts/test-host.sh`, DOM/JS админки и существующие
   профилированные TLS H1/H2 регрессии со старым JS exit.
7. `BUILD_ONLY=1 PROFILED_TLS=1`: XIAO ESP32-S3, M5Stack Stamp-P4+C6,
   Waveshare ESP32-P4-WIFI6. Физические платы не прошивались.

Локальные артефакты, исключённые из git:

- `perf-results/browser-profile-capture-20261029/{result,rechecked}.json`
- `perf-results/native-browser-profile-build-20261029/sources.sha256`
- `perf-results/native-profiled-1KMrzW/result.json`
- `/tmp/meshpn-profiles-host.log`
- `/tmp/meshpn-profile-{xiao,stamp,wave}-final.log`

## Воспроизведение без плат

```sh
node device/tests/test-browser-profiles.mjs /tmp/meshpn-profile-final-gated-host \
  device/tests/fixtures/browser-profile-capture-chromium156.json
node device/tests/test-browser-profile-storage.mjs \
  device/tests/fixtures/browser-profile-capture-chromium156.json
```

Первый аргумент — подготовленный каталог host-зависимостей
`device/experiments/profiled-tls/build-host.sh`, а не обязательное конкретное имя.
Тест браузерной страницы: `tests/test-browser-profile-capture-lab.mjs` внутри
существующего disposable browser lab, `--network=none`, с
`CVPN_DISPOSABLE_BROWSER_LAB=1`; вне контейнера он отказывается запускаться.
Native runner теперь принимает `MESHPN_TEST_PROFILE=/absolute/path/profile.json`.

## Что ещё не подтверждено

Аппаратные импорт/reconnect/power cycle, одновременная нагрузка USB+Wi-Fi+VPN,
достаточность памяти и throughput. Другие браузеры принимаются только в пределах
описанного subset и при успешном preview. Полная HTTP/2/браузерная мимикрия,
transparent/combo TLS не являются результатом этого блока.
