# Актуальная Alpine/Compose проверка, 31 октября

Новая ARM64 musl сборка включает diagnostics, bounded HTTP-профиль и актуальную
админку с evidence профилей. Компиляция из кеша исходников без сети, два jobs,
только в отдельном контейнере. Все native source hashes сверены с allowlisted
контекстом упаковки. Дистрибутивные слои переиспользованы из предыдущей принятой
Alpine-сборки; это не полный повтор скачивания APK/CMake dependencies с нуля.

- CTest — 14/14.
- Независимые H1/H2 wire endpoints и полный enrollment — 10/10 на musl.
- [VPN + admin Compose](../fixtures/clean-vpn-native-managed-20261031.json) —
  12/12 с private DNS/discovery, реальным TUN, add/revoke без смены exit PID,
  auth/capture, stop/start/SIGKILL и запретом обхода DNS.
- [Combo runtime](../fixtures/clean-vpn-native-alpine-combo-20261031.json) —
  17/17 с новым HTTP-профилем, независимым pcap, настоящими TUN/LAN relay,
  совместной нагрузкой и восстановлением ресурсов, отдельным active health,
  replay, SIGKILL/recreate и закрытым удержанным namespace после смерти клиента.

[Build receipt](../fixtures/clean-vpn-native-musl-http-20261031.json) содержит
source provenance и SHA до/после strip. Runtime engine:
`0c87b6e4b83b0fb4ace4e694c86637035bc8e9c72c9f88f697247136d255e273`.
Рабочие Radxa/VPS и сеть Mac не менялись, собственные ресурсы сценариев удалены.

Локальные теги принятого результата:

```text
localhost/cvpn-alpine-runtime:http-v2-20261031
localhost/cvpn-managed-alpine:http-v2-20261031
localhost/cvpn-managed-web-alpine:http-20261031
```

В первых лабораторных overlay попытках не было `strip` в runtime и затем
потерялся executable-бит entrypoint. Strip выполнен в builder, права entrypoint
восстановлены при упаковке; окончательные прогоны выше привязаны к новым image ID.
Официальный Alpine Containerfile уже делал это правильно, его не ослабляли.

Compose provider требует явного выбора той же remote connection. Установленный
`podman-compose` добавлял `--podman-args=--connection ...` после подкоманды;
в прогоне использован отдельный wrapper `podman --connection ... "$@"` через
`--podman-path`. Default Podman connection не меняли.

Это ARM64 Podman/Linux VM acceptance. Docker Engine, amd64 musl, reboot и
физический пилот имеют отдельные предыдущие receipts; результаты новой сборки
на них автоматически не переносятся. Новые netem faults отдельно проверены
на glibc diagnostic snapshot, не приписываются этому musl бинарнику.
