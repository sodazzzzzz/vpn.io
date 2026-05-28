# vpn.io

Учебный VPN на Go: TCP + TLS 1.3 + mTLS поверх TUN-устройства.
Поддерживаемые платформы: Linux, macOS, Windows.

## Что умеет

- Полный full-tunnel: сервер пушит клиенту маршруты (`-push-routes 0.0.0.0/0`)
  и DNS (`-push-dns 1.1.1.1,9.9.9.9`); клиент применяет их и снимает на выходе.
- Hub-and-spoke private LAN: если `-push-routes` не задан, клиенты получают
  только адрес в туннельной подсети и видят друг друга через сервер
  (с anti-spoof и изоляцией dst).
- Кроссплатформенный TUN (linux/darwin/windows) и кроссплатформенная
  установка маршрутов / DNS на клиенте.
- mTLS с собственным CA, выпуск/перечисление клиентских сертификатов
  одной командой.
- Reconnect с экспоненциальным backoff'ом + jitter, keepalive поверх TLS.

## Архитектура

```
        ┌────────────┐  TLS 1.3 + mTLS  ┌────────────┐
client →│ vpn-client │ ───────────────▶ │ vpn-server │ → TUN → kernel routing
        └────────────┘                  └────────────┘   (+ NAT, см. ниже)
              ▲                                ▲
              │ /etc/.../tunN                  │ /dev/net/tun (utun on macOS, wintun on Win)
```

- **Wire protocol** — 1-byte type prefix (`Control` JSON / `Data` raw IPv4), length-prefixed frames.
- **Authentication** — взаимный TLS, единый CA подписывает и серверный, и клиентские сертификаты. CommonName сертификата клиента = его идентификатор.
- **IP-пул** — детерминированный, выдаётся из CIDR (`-subnet`), gateway и broadcast зарезервированы.
- **Routes/DNS push** — сервер сообщает клиенту в `AssignIP`. Клиент ставит host route к серверу через старый default gw (pin-hole, иначе TLS-соединение зациклится), затем `0.0.0.0/0` через TUN (разбивается на `0.0.0.0/1` + `128.0.0.0/1` чтобы не трогать оригинальный default).
- **Reconnect** — клиент держит экспоненциальный backoff + jitter, кепалайвы поверх TLS.

## Сборка

Нужен Go 1.26+.

```bash
make build                # → ./bin/vpn-ca, vpn-server, vpn-client
# или вручную:
go build ./cmd/vpn-ca ./cmd/vpn-server ./cmd/vpn-client
```

## Быстрый локальный старт (loopback)

Полный pipeline для попробовать на одной машине:

```bash
make ca-init                                    # фабрика CA в ./ca-data/
make ca-server CA_HOSTS=localhost,127.0.0.1     # сертификат сервера
make ca-client CLIENT_NAME=alice                # сертификат клиента

# Сервер (нужен root для создания TUN)
sudo make run-server PUSH_ROUTES=0.0.0.0/0 PUSH_DNS=1.1.1.1

# В другом терминале — клиент (тоже root)
sudo make run-client CLIENT_NAME=alice SERVER=127.0.0.1:8443 SERVER_NAME=localhost
```

`make help` покажет все цели.

## Развёртывание боевого full-tunnel сервера на Linux

```bash
# 1. Собрать
GOOS=linux GOARCH=amd64 go build -o vpn-server ./cmd/vpn-server

# 2. Один раз — включить IP forwarding и MASQUERADE для туннельной подсети
sudo scripts/setup-nat.sh 10.8.0.0/24 eth0    # eth0 = ваш WAN-интерфейс

# 3. Раздать клиентам сертификаты (vpn-ca issue-client …) и запустить
sudo ./vpn-server \
  -ca   ca-data/ca.crt \
  -cert ca-data/server/server.crt \
  -key  ca-data/server/server.key \
  -subnet 10.8.0.0/24 -gateway 10.8.0.1 \
  -push-routes 0.0.0.0/0 \
  -push-dns    1.1.1.1,9.9.9.9
```

Откатить NAT/forwarding: `sudo scripts/teardown-nat.sh 10.8.0.0/24 eth0`.

## Раскладка `ca-data/`

```
ca-data/
├── ca.crt, ca.key
├── server/
│   ├── server.crt
│   └── server.key
└── clients/
    ├── alice.crt
    └── alice.key
```

`ca-data/` в `.gitignore` — приватные ключи никогда не попадают в репо.

## Платформенные тонкости

| Платформа | TUN driver | Privileges | Заметки |
|-----------|-----------|------------|---------|
| Linux | kernel TUN | `sudo` или CAP_NET_ADMIN | `ip` должен быть на PATH; для full-tunnel сервера нужен `scripts/setup-nat.sh` |
| macOS | `utun` | `sudo` | utun — point-to-point, gateway обязателен; DNS пушится через `networksetup` на все enabled services |
| Windows | [wintun.dll](https://www.wintun.net/) | Administrator | `wintun.dll` рядом с .exe или в PATH; DNS пушится через `netsh interface ipv4 set dnsservers` |

Linux **клиент** запустится, но автоматическая установка DNS не реализована
(systemd-resolved/NetworkManager/raw resolv.conf слишком разнятся). При
запуске на Linux вы увидите предупреждение и должны настроить
`/etc/resolv.conf` сами.

## Структура

```
cmd/
├── vpn-ca/      — CLI для CA (init / issue-server / issue-client / list)
├── vpn-server/  — VPN-сервер
└── vpn-client/  — VPN-клиент

internal/
├── ca/          — выпуск ECDSA P-256 сертификатов
├── dns/         — кроссплатформенный pусh resolver'ов (darwin/windows/linux-stub)
├── frame/       — длино-префиксная фреймовка
├── ipalloc/     — пул IPv4-адресов
├── route/       — кроссплатформенная установка маршрутов в системную таблицу
├── tun/         — кроссплатформенный TUN (linux/darwin/windows)
└── tunnel/      — wire protocol и логика сервера/клиента
    ├── server/  — TLS listener, registry, маршрутизация
    └── client/  — connect + reconnect, keepalive, route/DNS push

scripts/
├── setup-nat.sh     — sysctl + iptables MASQUERADE для full-tunnel
└── teardown-nat.sh  — откат рулесов из setup-nat.sh
```

## Tests

```bash
make test          # ≈ go test ./...
make cross         # кросс-сборка под linux/amd64 и windows/amd64
```
