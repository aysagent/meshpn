# Private DNS: bounded WAN budget

Во время длительного Radxa ↔ VPS combo-прогона получен `SERVFAIL` по TCP при
непрерывно работающем packet-сеансе. Сопоставление pcap показало корректный
ответ `laptop.mpn`: **1451.443 мс от первого SYN** и **841.715 мс от полной
передачи DNS query**. Прежний deadline 1200 мс начинался до TCP connect, поэтому
статистика только query→answer скрывала превышение общего бюджета.

Клиентский запрос приватной зоны к exit:1055 теперь имеет **3000 мс на весь
exchange**. Loopback bridge на exit сохраняет 1200 мс; бюджеты фиксированных
public upstream также не меняются. Нет нового retry, public fallback или
ослабления проверки DNS ID/question/response. Прежние worker/peer/FD limits и
проверки cancellation сохраняются. После исчерпания бюджета возвращается SERVFAIL.

Native ARM64 regression в отдельном Linux namespace:

- Ответ private UDP/TCP задерживается на 1400 мс. Старый код проваливает
  assertion; исправленный принимает корректный NXDOMAIN.
- Молчащий private UDP upstream даёт SERVFAIL за 2800–4000 мс.
- Public upstream не получает эти приватные запросы.
- Также проходят 100 запросов, identity, saturation, cancellation и FD cleanup.

Для этой проверки нужен настоящий Linux socket API: user-mode QEMU x86 на ARM
возвращает ENOPROTOOPT для SO_MARK. Это отказ эмулятора; ослаблять production
SO_MARK ради него нельзя. Тест выполнен native ARM64 с CAP_NET_ADMIN/NET_RAW.

Отдельный предыдущий WAN-отказ совпал с `h2_ping_timeout` и TCP retransmissions;
клиент сам переподключился и восстановил DNS. Увеличение private DNS deadline
не объявляется исправлением причин такого разрыва. Повторная WAN-приёмка с
новыми binaries требуется перед постоянным переключением.
