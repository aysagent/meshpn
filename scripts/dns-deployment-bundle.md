# Публикация и откат DNS code bundle

`lib/dns-deployment-bundle.mjs` добавляет исполняемую файловую транзакцию для
`/opt/clean-vpn`. Она не запускает код, службы или DNS, не публикует opt-in и
не предоставляет live installer CLI. Применение к настоящему `/` требует
отдельного установщика с проверкой клиента, root authority, неактивного состояния
интеграции и общим lifecycle/deployment lock. Тесты работают только в temp roots.

## Порядок

1. Проверить предварительно собранный source bundle и явно переданный ожидаемый
   SHA256 его manifest. Все файлы читаются ограниченно, проверяются SHA256,
   UID/mode/nlink, полный inventory и отсутствие symlink/неучтённых объектов.
   Требуются entrypoints client/guard/adapter и authority module. Это проверка
   файлового набора, не доказательство происхождения кода или полноты import graph.
2. Скопировать файлы в `bundle/` внутри private0700 journal directory, без
   hardlinks на source. Каталоги0755, файлы0644 даже при umask077; fsync всех
   файлов/каталогов. Повторно проверить source и готовую копию.
3. Записать private0600 write-ahead journal с точным inventory копии.
4. Перенести копию в отсутствующий `/opt/clean-vpn`, затем fsync обоих родителей
   и отметить `installed`. Разрешение клиента публикуется отдельной
   [транзакцией приватных файлов](dns-deployment-files.md) лишь после проверки bundle.

Целевой путь фиксирован относительно предоставленного root; journal не может
лежать внутри него. Root, `/opt` и journal directory привязаны по identity/mode.
Journal и `/opt` должны находиться на одном **mount**, не просто устройстве.
Проверки контекста и настоящего унаследованного exclusive flock повторяются
при staging/инвентаризации. Полный `assertInactive` нужен на входе/выходе
операции и до/после публичного move, но не для каждого приватного code file.
Callback не заменяет реальную OS-проверку: `true`
в тесте не является разрешением для живой установки.

Перенос выполняет root-pinned `/usr/bin/mv` с `--no-clobber --no-target-directory`,
через существующий bounded runner с тем же унаследованным lock. `-T` исключает
вложение в внезапно возникший каталог, `-n` — его замену. Exit status не считается
доказательством переноса: исходный путь должен исчезнуть, а итоговый inventory —
совпасть с журналом. Cross-mount запрещён до staging, чтобы не использовать
copy/remove fallback. Семантика опций:
[GNU mv](https://www.gnu.org/s/coreutils/manual/html_node/mv-invocation.html),
[GNU target directory](https://www.gnu.org/software/coreutils/manual/html_node/Target-directory.html).
Это не защита от конкурентного враждебного root, меняющего mounts/код в обход lock.

## Recovery и rollback

Стадии: `prepared → installed → removing → removed`. `recover` продолжает только
записанное направление. Допустим ровно один экземпляр: staging, published или
retired согласно стадии; совпадение байтов чужого inode не позволяет его принять.
Повторный install/upgrade поверх существующей установки запрещён.

`remove` разрешён только при подтверждённой неактивности и переносит точный
owned bundle в `retired/` внутри private journal directory. **Код сохраняется**,
рекурсивного удаления нет. Такой же откат возможен до публикации prepared bundle.
Чужие правки, лишний файл, другой inode, потеря lock/неактивности или смена parent
останавливают операцию. Opt-in/службы/boot dependencies должны быть сняты
координатором до удаления кода; этот модуль сам этого не доказывает.

Обрыв до появления журнала оставляет staging для review; автоматически принять
его нельзя. Неизвестный или повреждённый journal не разрешает mutation. Удаление
архива и обновление версий — отдельные операции, не побочный эффект recovery.

## Проверки

```bash
npm run test:dns-deployment-bundle
```

30 проверок используют настоящие файлы, GNU mv и flock в приватном
user/mount/network/PID namespace с маленьким chroot. Рабочие файлы доступны
на запись только в temp data root; код/библиотеки подключены read-only.
Root-owned системные tools моделируются копиями в chroot: production UID gate
не отключается, хотя в рабочем sandbox оригинальные `/usr` files видны как nobody.
Проверены6 настоящих SIGKILL вокруг journal/publish/retire, конкурирующий flock,
umask077, отказ при source/target drift и same-device/different-mount.
Это process-crash файловой транзакции, **не VM power-loss или live install PASS**.

Результат: **30/30 PASS**, включая6 SIGKILL; общая Node-регрессия
**1953/1953 PASS**, без skips (`/var/tmp/meshpn-acceptance-k7LYuT/report.json`).
Первый запуск тестов отказал на UID системной утилиты в sandbox; это устранено
изолированным root-owned fixture, без изменения production gate. Стенд использует
GNU coreutils9.4; отдельный distro/installed VM-прогон этим не подменяется.

Следом — собрать реальный source bundle, связать обе файловые транзакции с
[inactive OS-проверкой](dns-deployment-inactive.md) и активацией/отключением служб, затем проверить единый
install/activate/disable/uninstall в VM. DNS v1 и Radxa остаются в полном объёме.
