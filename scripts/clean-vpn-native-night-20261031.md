# Ночь 31 октября: после исправления управления Radxa

Пользователь поручил сначала исправить отсутствие интернета/управления на Radxa,
затем продолжать ночной план самостоятельно. Source edits/commits/push — на Mac;
на физических узлах только Git pull и штатные установщики. Сеть Mac не менять.
Рабочую combo-пару после ремонта не переключать ради следующих испытаний.

## Текущий checkpoint

1. **Готово:** [admin repair](clean-vpn-native-admin-repair-20261031.md), source
   `44f2bb5`, установлен на Radxa. 53 unit/HTTP проверки, два Chromium DOM
   сценария, 14 настоящих systemd gates и 9 физических gates. Guard off даёт
   direct USB HTTPS/DNS, guard on + start возвращает VPN. Ремонт оставлен с
   включёнными combo и защитой; VPS не перезапускался.
2. **Готово:** [30 минут на точном daily binary](clean-vpn-native-daily-soak-20261031.md),
   четыре клиента, 14073 mixed rounds, quota isolation и cleanup.
   **Готово:** [netem/crash на diagnostic runtime](clean-vpn-native-netem-20261031.md),
   delay/loss/reorder/blackout, обе ветки и SIGKILL/recreate; daily не затронут.
3. **Готово локально:** [диагностика relay/packet/H2/DNS](clean-vpn-native-diagnostics.md),
   typed counters и строгие readers, CTest 14/14, H1/H2/service 3/3, Linux controllers 49/49. Никакого
   вывода «исправлено» по одному успешному повтору. Отдельно TLS без SNI сейчас
   отклоняется transparent; совместимость исследовать без прямого обхода.
4. **Готово локально:** [bounded HTTP-профиль](clean-vpn-native-http-profile-20261031.md),
   UA H1/H2, pseudo-header order, SETTINGS 3 opt-out, независимая wire-проверка;
   22/22 integration, 14/14 CTest. Priority/полная browser equivalence не реализованы.
   H2 mimicry: исполняемый bounded contract, ALPS agreement, wire comparison;
   сначала исследовать существующую реализацию, не повторять уже готовые окна/
   SETTINGS. Новые browser параметры не должны молча обходить memory limits.
5. **Готово локально:** [UI и evidence профилей](clean-vpn-native-profile-evidence-20261031.md),
   SHA файла, import receipt, configured/saved, capture provenance; 15/15 + Chromium.
   UI профилей: captured/candidate/active, provenance, ограничения, самостоятельный
   observer; combo packet и app TLS должны иметь раздельные результаты.
6. **Повторено локально:** существующий enrollment с новым bounded HTTP-профилем,
   Linux 28/28, включая 32 клиента/exit; [receipt](../fixtures/clean-vpn-native-enrollment-20261031.json).
   Удобство combo enrollment: add/export/import/connect/rotate/revoke, готовые
   отдельные keys/CA/profile; `.mpn` и discovery только в изолированной среде.
7. Повтор актуальных managed Compose/Alpine, restart/recreate/state preservation.
   Это обновление имеющейся реализации, не новая разработка контейнеров с нуля.
8. Резерв: первые локально устанавливаемые OpenWrt packages/UCI/procd/LuCI и
   виртуальная приёмка. Физические роутеры не трогать; не обещать полную LuCI
   функциональность по одному прототипу.

Каждый завершённый этап — отдельный логический commit/push и receipt. Продолжать
следующий, если нет внешнего блокера; не ждать пользовательского «продолжай».
Сохранённые отчёты предыдущих дат не переписывать новыми результатами.
