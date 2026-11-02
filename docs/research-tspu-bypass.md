# Обход ТСПУ: что работает в ноябре 2026 и что делать в нашей ситуации

Дата: 2026-11-02. Метки: **[подтв.]** означает, что есть первичный или технический источник. **[сообщ.]** означает единичные сообщения пользователей. **[не пров.]** означает, что пункт не проверен и является нашим выводом.

Исходные факты (получены нашими тестами): из Донецка (российские аплинки) часть EU-хостинговых IP ведёт себя так:
- TLS с любым SNI режется, а TLS без SNI проходит.
- На части IP Aeza и AdminVPS/Snowd TCP-рукопожатие проходит, но полезная нагрузка не идёт, UDP теряется.
- Полностью случайный поток «замерзает» после первых килобайт.
- XHTTP без TLS и Sudoku на незаблокированных IP проходят.
- Московский VPS (FirstVDS) доступен, и канал Москва→EU чистый.

---

## 1. Короткий вывод

1. **Первое: российский входной узел (relay) на FirstVDS.** Цепочка: клиент → FirstVDS (Москва) → EU-выход. Наблюдения (b) и (a) — это фильтрация по IP или подсети на «пограничном» ТСПУ. Обфускацией её не победить, можно только сменить точку входа. Участок Москва→EU у нас чистый, поэтому этот вариант закрывает все три типа блокировок разом. Так же поступает сообщество с января 2026 года ([habr 985674](https://habr.com/en/articles/985674), [habr 990236](https://habr.com/ru/articles/990236/)). Транспорт клиент→RU: VLESS+XHTTP+REALITY с российским SNI. Транспорт RU→EU: VLESS+XHTTP с REALITY или с VLESS-Encryption.
2. **Второе: 2–3 выхода у разных провайдеров и в разных ASN**, плюс прямые пути в обход relay как резерв. Прямые пути — это XHTTP без TLS и Sudoku на «чистых» IP. Каждый IP проверяйте и из Донецка, и из Москвы (раздел 3). Не держите все выходы в Aeza или Snowd.
3. **Третье: автопереключение на клиенте и устойчивая доставка подписки.** Нужны группа url-test/balancer в Happ, v2rayNG или Hiddify и подписка, которая отдаётся с RU-узла и с запасного домена. Отдельно: **на Xray 26.9.8+ у REALITY сломан fingerprint `qq`** ([XTLS #7144](https://github.com/XTLS/Xray-core/discussions/7144), октябрь 2026). У нас 26.9.9, поэтому используйте `chrome` или `safari` и проверяйте это на клиентах.

---

## 2. Каталог методов (2026)

Колонка «IP-блок» показывает, помогает ли метод против блокировки по IP или подсети, то есть против нашего случая (b).

| Метод | Как работает и какой сигнал ТСПУ обходит | IP-блок | Клиенты | Сервер (3X-UI/Xray) | Зрелость и риск |
|---|---|---|---|---|---|
| **RU-вход (каскад)** | Клиент подключается к российскому IP, а трансграничный участок идёт DC→DC. Обходит пограничные правила по IP, SNI и энтропии. | **Да** | Любые: клиент видит обычный VLESS | Inbound на RU и outbound VLESS к EU с `routing` (geosite:category-ru → direct). В 3X-UI это делается через Xray template или отдельный outbound. | Самый надёжный метод в 2026 году [подтв.]. Риски: задержка ×2, законы РФ о хостинге (раздел 5), блокировка RU-IP по жалобе. |
| **XHTTP** (packet-up / stream-up / stream-one, xPadding, xmux) | Выглядит как HTTP-трафик и обходит «замерзание» длинной TCP-сессии: packet-up режет поток на множество POST-запросов. xPadding размывает длины, xmux управляет мультиплексированием. | Нет (только через relay или CDN) | v2rayNG, Happ, v2rayN, Streisand, Hiddify 4.x (sing-box-ext) [сообщ.] | Встроен в Xray. Для каскада packet-up рекомендуют с Xray ≥25.12.8 ([habr 985674](https://habr.com/en/articles/985674)). | Основной транспорт 2026 года. Есть сообщения о блокировке XHTTP в отдельных регионах ([habr 1047442](https://habr.com/ru/articles/1047442/comments/)) [сообщ.]. |
| **REALITY** (с соседним или своим доменом) | Подмена TLS под чужой сайт. Обходит проверку SNI и сертификата. Важно: serverNames и dest должны совпадать с сертификатом донора ([XTLS #6300](https://github.com/XTLS/Xray-core/discussions/6300)). | Нет | Все Xray-клиенты | Встроен | На RU-входе с российским SNI работает. Напрямую на EU-хостинг в 2026 часто режется по IP+TLS. Fingerprint `chrome` местами блокируется [сообщ.]. `qq` сломан на 26.9.8+ ([#7144](https://github.com/XTLS/Xray-core/discussions/7144)). |
| **VLESS-Encryption (ML-KEM)** | Шифрует содержимое внутри транспорта. **Сам по себе не обходит блокировки**: случайный поток без маски режется, как в нашем случае (d) ([zapret wiki](https://publish.obsidian.md/zapret/xray/vless-encryption)). | Нет | Xray-клиенты ≥25.9.5: v2rayNG, Happ, Streisand. В апстримном sing-box (Hiddify, NekoBox) поддержки нет. | `xray vlessenc` | Нужен вместе с XHTTP без TLS, с CDN или на участке между узлами. |
| **FinalMask** (sudoku, fragment, header-custom, noise, salamander, udphop) | Слой масок поверх транспорта ([docs](https://xtls.github.io/config/transports/finalmask.html)). `sudoku` убирает высокую энтропию (против (d)). `fragment` с `packets:"tlshello"` режет ClientHello (против SNI-фильтра). `salamander`/`noise` предназначены для UDP. | Нет | Ссылка `&fm=`, Happ 3.23+ ([apkmirror](https://www.apkmirror.com/?p=14188655)), v2rayNG/v2rayN на свежем ядре [не пров.]. Throne и Karing не подтверждены. | 3X-UI 3.8.x | Новая разработка, формат ещё меняется. Хороший резерв, но не основа. |
| **Фрагментация ClientHello** (клиентский fragment, tlshello) | Делит ClientHello на части, чтобы ТСПУ не собрал SNI. | Нет | v2rayNG, Happ, Hiddify, Throne | На сервере ничего не нужно | Против (a) стоит пробовать. В феврале 2026 пустой SNI помогал во всех тестах ([habr 990236](https://habr.com/ru/articles/990236/)) [сообщ.]. |
| **CDN-фронтинг** (Cloudflare, Gcore и др. + XHTTP/WS) | Клиент видит IP CDN, а не VPS. | Да (IP скрыт) | Все | Домен + CDN, XHTTP или WS без REALITY | Cloudflare в РФ с 2025 года обрезается на ~16 КБ у крупных операторов ([zona.media](https://en.zona.media/article/2025/06/27/cloud_confirmed)). На мобильных сетях работает только на домашнем Wi-Fi ([habr 1021160](https://habr.com/en/articles/1021160)). Gcore и другие CDN нужно проверять по месту [не пров.]. |
| **ECH / domain fronting через ECH** | Скрывает SNI. | — | — | — | ТСПУ блокирует ECH к Cloudflare с ноября 2024 ([lantern](https://corpus.lantern.io/findings/2025-niere-encrypted__russia-tspu-ech-direct-block/), [kod.ru](https://kod.ru/rkn-block-ech-cloudflare)). **Не использовать.** |
| **Hysteria2 / TUIC / XHTTP-H3** (+ salamander, port-hopping) | QUIC/UDP. Salamander прячет Initial-пакеты, port-hopping обходит блокировку по порту. | Нет | Hiddify, Happ, Karing, NekoBox/Throne, v2rayNG (hy2) | Отдельный inbound, в Xray — через finalmask/quicParams | В РФ UDP часто режется или замедляется ([habr 1008554](https://habr.com/ru/articles/1008554/)). У нас UDP на заблокированные IP теряется полностью. Годится только как дополнительный путь. |
| **AmneziaWG 2.0** | WireGuard с мусорными пакетами, паддингом и CPS-мимикрией под DNS, QUIC или SIP ([amnezia.org](https://amnezia.org/blog/amneziawg-2-0-available-for-self-hosted)). | Нет | AmneziaVPN ≥4.8.12.9, AmneziaWG-клиенты | Отдельный сервис, не 3X-UI | Работает только по UDP. Несовместим с 1.x. Удобен для «семейных» пользователей на незаблокированных IP. |
| **Shadowsocks-2022** | AEAD без «рукопожатия». | Нет | Все | Встроен в 3X-UI | В феврале 2026 ещё проходил ([habr 990236](https://habr.com/ru/articles/990236/)) [сообщ.]. По энтропии похож на наш случай (d), поэтому рискованно без маски. |
| **ShadowTLS v3 / NaiveProxy** | Настоящий TLS к чужому домену (ShadowTLS) или стек Chrome (Naive). | Нет | sing-box-клиенты (Hiddify, Karing, NekoBox); Naive — NekoBox, Karing | Вне 3X-UI (sing-box или Caddy) | Свежих данных по РФ за 2026 год нет [не пров.]. RPRX предпочитает XHTTP с Browser Dialer вместо Naive ([projectxtls](https://t.me/s/projectxtls/1613)). |
| **Порты, IPv6** | Случайный высокий порт вместо 443 пропускал до 80% трафика ([habr 990236](https://habr.com/ru/articles/990236/)). IPv6 у мобильных операторов РФ встречается редко. | Частично (IPv6 — другой префикс) | Все | Тривиально | Это дешёвые эксперименты, а не стратегия. IPv6 на выходе помогает WhatsApp ([habr 985674](https://habr.com/en/articles/985674)). |
| **WARP как egress** | Выход с IP Cloudflare: сайты не видят IP VPS. | Нет (это только выход) | — | outbound WireGuard в Xray | Полезно против антибот-блоков и 451. Ко входу отношения не имеет. |
| **Белые списки (мобильные)** | При ограничениях доступны только IP из реестра. | — | — | Нужен вход на «белом» RU-IP | С января 2026 РКН требует от облаков отделять «белые» пулы от клиентских ([kod.ru](https://kod.ru/vpn-fail-bely-spisok)). Yandex Cloud ≠ AS Яндекса ([habr 1021160](https://habr.com/en/articles/1021160)). Поиск «белого» IP — лотерея. Для пользователей в РФ на мобильном интернете это единственный путь. |
| **Tor Snowflake / WebTunnel** | Последний резерв. | Да | Tor Browser | Не нужен | Snowflake с 30.03.2026 блокируется по JA3/JA4 DTLS ([lantern](https://corpus.lantern.io/papers/2026-wkrp-snowflake-targeted-dtls-filtering/)). WebTunnel блокируется частично ([tor gitlab](https://gitlab.torproject.org/tpo/anti-censorship/censorship-analysis/-/issues/40064)). |

---

## 3. Диагностика: какой механизм бьёт по IP

Тест-сервер: на проверяемом VPS временно поднимите `python3 -m http.server 8081` и положите файл: `head -c 2M /dev/urandom > big.bin`. Порт 8081 откройте только на время теста. Ниже `IP` — это IP проверяемого VPS, `CLIENT_IP` — IP клиента.

| # | Команда (Windows PowerShell или MobaXterm) | Ожидаемо, если всё чисто | Что значит сбой | Метод |
|---|---|---|---|---|
| 1 | `Test-NetConnection IP -Port 8081` | `TcpTestSucceeded: True` | False: блок на L3/L4 или фаервол | Сменить IP или relay |
| 2 | `curl.exe -v -o NUL http://IP:8081/big.bin` | Скачано 2 МБ | Висит с 0 байт при живом TCP: **IP-блок полезной нагрузки (b)** | Только RU-relay, CDN или новый IP |
| 3 | То же, но обрывается на ~15–20 КБ | — | **«Заморозка» длинной сессии** | XHTTP packet-up, xmux с малым `cMaxReuseTimes` |
| 4 | `openssl s_client -connect IP:443 -servername www.microsoft.com` и затем `-noservername` | Оба варианта дают сертификат | С SNI висит, без SNI проходит: **фильтр по SNI или ClientHello (a)** | fragment tlshello, пустой SNI, XHTTP без TLS, relay |
| 5 | Сервер: `head -c 200k /dev/urandom \| nc -l 9000` (временно открыть порт 9000). Клиент (MobaXterm или ncat из пакета Nmap): `nc IP 9000 > out.bin`, затем проверить размер | 200 КБ | Обрезается после нескольких КБ: **детект энтропии (d)** | Sudoku, XHTTP, TLS-обёртка |
| 6 | На сервере: `ncat -ul 9001`. На клиенте: `ncat -u IP 9001` | Строки доходят | Не доходят: UDP режется | Не использовать Hy2/AWG на этом IP |
| 7 | `tracert -d IP` / `mtr -rwz IP` (на MobaXterm) | — | Потери на стыке RU→EU | Сравнить с тестом из Москвы |

Со стороны сервера во время тестов 2 и 4 выполните `tcpdump -ni any host CLIENT_IP and port 8081 -c 50`. Если видны SYN/ACK, но нет PSH-пакетов от клиента, полезную нагрузку режут по пути. Если данные от сервера уходят, а клиент их не получает, режется обратное направление. Повторите тесты 1–6 **с FirstVDS** (`curl -o /dev/null -w '%{size_download}\n' http://IP:8081/big.bin`). Если из Москвы всё чисто, IP годится как выход для relay, даже если напрямую он «мёртв». Временный сервер на порту 8081 после проверки выключите (Ctrl+C).

---

## 4. Архитектура для ~20 пользователей

```
Клиент (Happ / v2rayNG / Hiddify), группа url-test
 ├─ [A] RU-вход FirstVDS :443 VLESS+XHTTP+REALITY (SNI — российский сайт)
 │      ├─ balancer (leastPing) → EU-1 (провайдер X, ASN 1) VLESS+XHTTP(+REALITY|vlessenc)
 │      └─                     → EU-2 (провайдер Y, ASN 2)
 ├─ [B] напрямую EU-1 :8080 VLESS-enc+XHTTP без TLS   (если IP не в блоке)
 ├─ [C] напрямую EU-2 :8443 VLESS-enc+Sudoku
 └─ [D] второй RU-вход (другой провайдер) — холодный резерв
```

- **Кто инициирует соединение:** всегда клиент, затем RU-узел устанавливает исходящее соединение к EU. Входящие порты нужны только на RU (443) и на EU (порт межузлового канала). На EU разрешите этот порт **только с IP RU-узла** (finalmask `filter` или nftables).
- **Отказы.** Если падает RU-вход, клиент через url-test (интервал 3–5 мин, tolerance 50–100 мс) уходит на [B] или [C]. Если падает EU-выход, balancer на RU с `observatory`/`burstObservatory` (probeInterval ≥30 s) переключается на другой выход. Существующие TCP-сессии при этом рвутся, и приложения переподключаются сами. Шторма переподключений нет, потому что пробы идут по таймеру, а не по каждой ошибке.
- **Маршрутизация.** На RU-узле `geosite:category-ru` и `geoip:ru` отправляются в direct, чтобы банки и Госуслуги видели российский IP. Блокируйте сервисы определения IP, которые раскрывают адрес выхода ([habr 1021160](https://habr.com/en/articles/1021160)).
- **Подписка.** Отдавайте её с RU-узла по HTTPS и дублируйте на втором домене. В Happ и v2rayNG задайте интервал автообновления подписки. Держите в ней не меньше трёх профилей, чтобы клиенты не оставались без связи, пока IP меняется.
- **Мобильные «белые списки»** нужны только пользователям в РФ на мобильной сети. Для них ищите вход на «белом» RU-IP. Это ненадёжно, поэтому предупредите их заранее.
- **Точки отказа:** RU-узел (держите [D]), домен подписки и одиночные ASN.

---

## 5. Риски

**Правовые (РФ, 2026):**
- В апреле 2026 к законопроекту «Антифрод 2.0» подготовили поправки: хостерам предлагается запретить предоставлять мощности владельцам VPN и проверять клиентов ([anti-malware](https://www.anti-malware.ru/news/2026-04-16-111332/49735), [Meduza](https://meduza.io/news/2026/04/17/rossiyskim-provayderam-hostinga-sobirayutsya-zapretit-predostavlyat-vychislitelnye-moschnosti-vladeltsam-vpn)).
- 1 октября 2026 Минцифры предложило реестр нарушителей с годовым запретом на аренду серверов у российских хостеров. Это **проект**, вступление в силу планируется 1 марта 2028 ([kod.ru](https://kod.ru/vpn-hosting-year-ban)).
- Работать без регистрации в реестре хостинг-провайдеров РКН могут только хостеры из реестра. FirstVDS в нём есть, поэтому он обязан реагировать на запросы РКН.
- Aeza удаляла VPS по запросу РКН ([habr 1021160](https://habr.com/en/articles/1021160)).
- **Вывод:** RU-узел на FirstVDS может быть отключён в любой момент. Держите его конфигурацию воспроизводимой (скрипт плюс бэкап) и имейте запасного провайдера. Предоставление доступа третьим лицам может подпадать под ст. 15.8 149-ФЗ. Детальная правовая оценка выходит за рамки отчёта [не пров.].

**Операционные:**
- IP «сгорают». Есть сообщения о блокировке IP после всплеска соединений ([habr 1047442](https://habr.com/ru/articles/1047442/comments/)) [сообщ.]. Не допускайте массовых проб: url-test не чаще раза в несколько минут, xmux с разумным `maxConcurrency`.
- Пакетные шаблоны выдают туннель: длинные сессии с постоянной нагрузкой, keepalive строго по таймеру.
- Fingerprint, который блокируется в регионе, «залипает» до ~130 секунд ([#7144](https://github.com/XTLS/Xray-core/discussions/7144)). Учитывайте это при тестах.

**Безопасность:**
- Донор REALITY должен быть чужим популярным сайтом с TLS 1.3 и H2, а не случайным сервером. Некорректный dest или serverNames выдаёт сервер ([#6300](https://github.com/XTLS/Xray-core/discussions/6300)).
- Не ставьте «скрипты-однострочники» и форки панелей из Telegram без ревизии. Закрепляйте версии и проверяйте хэши.
- Панель 3X-UI не открывайте в интернет: доступ к ней только через SSH-туннель.
- Межузловой канал ограничьте фильтром по IP источника.
- На публичных узлах не храните секреты в логах.

---

## 6. Источники

- XTLS FinalMask docs: https://xtls.github.io/config/transports/finalmask.html
- XTLS #7144 (REALITY и qq, 26.9.8+, окт. 2026): https://github.com/XTLS/Xray-core/discussions/7144
- XTLS #6300 (SNI и dest против ТСПУ, июнь 2026): https://github.com/XTLS/Xray-core/discussions/6300
- Project X, канал (finalmask, XHTTP vs Naive): https://t.me/s/projectxtls/1613
- VLESS Encryption, zapret wiki: https://publish.obsidian.md/zapret/xray/vless-encryption
- Habr 985674, каскад и белые списки (янв. 2026): https://habr.com/en/articles/985674
- Habr 990236, блокировки XRay и VLESS (фев. 2026): https://habr.com/ru/articles/990236/
- Habr 1021160, многоуровневый VPN (апр. 2026): https://habr.com/en/articles/1021160
- Habr 1008554, Hysteria 2 (мар. 2026): https://habr.com/ru/articles/1008554/
- Habr 1047442, «заморозка по fingerprint» (июнь 2026): https://habr.com/ru/articles/1047442/comments/
- Kod.ru, белые IP облаков (янв. 2026): https://kod.ru/vpn-fail-bely-spisok
- Kod.ru, законопроект о годовом запрете (окт. 2026): https://kod.ru/vpn-hosting-year-ban
- Anti-Malware, «Антифрод 2.0» (апр. 2026): https://www.anti-malware.ru/news/2026-04-16-111332/49735
- Mediazona, цензура в 2026: https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026
- Mediazona, 16 КБ и Cloudflare: https://en.zona.media/article/2025/06/27/cloud_confirmed
- ECH и ТСПУ: https://corpus.lantern.io/findings/2025-niere-encrypted__russia-tspu-ech-direct-block/
- Snowflake и DTLS (2026): https://corpus.lantern.io/papers/2026-wkrp-snowflake-targeted-dtls-filtering/
- Блокировка WebTunnel в РФ: https://gitlab.torproject.org/tpo/anti-censorship/censorship-analysis/-/issues/40064
- AmneziaWG 2.0: https://amnezia.org/blog/amneziawg-2-0-available-for-self-hosted
- Happ 3.23.0 (finalmask): https://www.apkmirror.com/?p=14188655
- ntc.party, тред о подтверждённых блокировках ТСПУ: https://ntc.party/t/читайте-1-сообщение-сообщения-об-отдельных-подтверждённых-блокировках-тспу/4625
