# Подготовка нового exit-сертификата без установки

`clean-vpn-native-certificate-renew.mjs` создаёт кандидат leaf/key/config под
существующим private CA. Рабочие файлы, PSK, клиентский trust, часы и службы не
изменяются; автоматического install/restart нет. Это отдельный offline шаг,
который можно выполнить перед будущей контролируемой активацией.

```sh
node scripts/clean-vpn-native-certificate-renew.mjs \
  --config=/absolute/path/exit/engine.json \
  --ca-cert=/absolute/offline/authority/ca.pem \
  --ca-key=/absolute/offline/authority/ca.key \
  --server-name=vpn.example \
  --engine=/absolute/path/clean-vpn-engine \
  --output=/absolute/private/renewal-20261030 \
  --days=30
```

При отдельном клиентском trust bundle добавить `--trust=/absolute/path/ca.pem`.
Все пути должны быть абсолютными. Output должен отсутствовать; родитель должен
быть доступен только администратору. Каталог создаётся mode0700, файлы mode0600.
CA private key читается только из исходного файла и передаётся OpenSSL через
read-only inherited FD; в output он не копируется. Команды/ключи/stderr OpenSSL
в сообщения об ошибке не выводятся. Encrypted CA key/HSM пока не поддержаны.

Проверяется:

- TLS exit роль, соответствие текущего leaf имени и подписывающему CA;
- соответствие CA private/public key и безопасные permissions файла ключа;
- цепочка и `sslserver` purpose через OpenSSL, включая ограничения CA;
- сохранение DNS/IP SAN и типа RSA/EC ключа; свежий ключ и random serial;
- срок 1–397 дней, строго внутри срока всех входных CA/сохранённых intermediate;
- имя, цепочка, соответствие нового key/leaf и native `--check-config`;
- исходные config/cert/CA/key не изменились во время подготовки.

Если CA не покрывает запрошенный срок, команда явно отказывает. CA rotation —
отдельная задача: нельзя молча заменить CA, которому уже доверяют клиенты.
Старый leaf может быть просрочен для проверки исходной цепочки; CA должен быть
действующим. Старый просроченный leaf, естественно, не подходит для rollback.
Поддержаны RSA2048–4096 и EC P-256/P-384/P-521, обычные DNS/IP SAN. Другие типы
ключей/расширения имени отклоняются. OCSP/CRL и ACME здесь не реализованы.

Результат: `engine.json` с новыми абсолютными путями cert/key, `cert.pem`,
`key.pem`, public chain/trust, CSR/extensions и `manifest.json` с публичными
hashes и сроками. PSK paths остаются исходными; PSK не экспортируется. Для combo
изменяется только TLS-ветка `boring`, relay identity и replay state сохраняются.

Перед будущей активацией проверить manifest, actual client handshake с прежним
CA и неизменённым именем, затем применить кандидат отдельной процедурой. Peer
SIGHUP не является интерфейсом замены TLS identity. Старые config/leaf/key
сохранить до завершения проверки. При неуспешной активации восстановить именно
старый config и его пути, а не перезаписывать старый leaf новым. Этот helper
такую активацию и rollback не запускает.

Проверки: `node --test scripts/test-native-certificate-renewal.mjs` (8 offline/TLS сценариев; ещё 2 native при `CVPN_ENGINE`),
в Linux laboratory дополнительно `CVPN_ENGINE=/path/clean-vpn-engine` включает
реальную native validation и H1/H2 tunnel с новым leaf, прежним CA, 2000 packets
и reconnect/blackhole recovery. RSA и EC кандидаты выполняют настоящий TLS
handshake с прежним CA; старый leaf/key также остаётся рабочим. Проверены
ошибочное имя, чужой CA/key/trust, недостаточный срок, плохие permissions,
clientAuth purpose, занятый output и очистка после отказа native validation.
Это не physical deployment и не тест рестарта рабочего VPN.
