# clean-vpn transport tests

**Документация перенесена:** [scripts/clean-vpn/tests/README.md](clean-vpn/tests/README.md)

Запуск:

```bash
sudo env PATH=$PATH node scripts/clean-vpn/tests/run.mjs --tier=1
```

Ниже — архив прежнего плана (может частично устареть).

---

# clean-vpn: автоматизированное smoke-тестирование транспортов

План разработки harness-скрипта для проверки, что **client ↔ exit** поднимают TUN-мост и пропускают IPv4 к peer **10.99.0.1**.

**Реализация:** `scripts/clean-vpn/tests/run.mjs`

**Scope:** connectivity smoke (ping + HTTP через client TUN). **Не** throughput.

**Связанные файлы:**
- [clean-vpn.js](clean-vpn.js) — реализация транспортов
- [clean-vpn/tests/README.md](clean-vpn/tests/README.md) — актуальная спека harness
