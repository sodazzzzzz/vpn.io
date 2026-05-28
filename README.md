# vpn.io

Учебный VPN на Go: TCP + TLS 1.3 + mTLS поверх TUN-устройства.
Поддерживаемые платформы: Linux, macOS, Windows.

> **Статус:** работает peer-to-peer (hub-and-spoke) между клиентами.
> Full-tunnel выход в интернет (NAT на сервере + push маршрутов/DNS на клиента)
> ещё не реализован — в работе.

## Архитектура

```
        ┌────────────┐  TLS 1.3 + mTLS  ┌────────────┐
client →│ vpn-client │ ───────────────▶ │ vpn-server │ → TUN → kernel routing
        └────────────┘                  └────────────┘
              ▲                                ▲
              │ /etc/.../tunN                  │ /dev/net/tun (utun on macOS, wintun on Win)
```

- **Wire protocol** — 1-byte type prefix (`Control` JSON / `Data` raw IPv4), length-prefixed frames.
- **Authentication** — взаимный TLS, единый CA подписывает и серверный, и клиентские сертификаты. CommonName сертификата клиента = его идентификатор.
- **IP-пул** — детерминированный, выдаётся из CIDR (`-subnet`), gateway и broadcast зарезервированы.
- **Изоляция** — клиенты не могут адресовать друг друга (anti-spoof на src, hub-and-spoke check на dst).
- **Reconnect** — клиент держит экспоненциальный backoff + jitter, кепалайвы поверх TLS.

## Сборка

Нужен Go 1.26+.

```bash
go build ./cmd/vpn-ca ./cmd/vpn-server ./cmd/vpn-client
```

## Быстрый локальный старт (loopback)

Полный pipeline для попробовать на одной машине:

```bash
# 1. CA и сертификаты
./vpn-ca init
./vpn-ca issue-server -hosts localhost,127.0.0.1
./vpn-ca issue-client -name alice

# 2. Сервер (нужен root для создания TUN)
sudo ./vpn-server -listen :8443

# 3. В другом терминале — клиент (тоже root)
sudo ./vpn-client \
  -server 127.0.0.1:8443 \
  -server-name localhost \
  -cert ca-data/clients/alice.crt \
  -key  ca-data/clients/alice.key
```

После подключения клиент получит адрес из `10.8.0.0/24` (по умолчанию) и
сможет пинговать gateway сервера: `ping 10.8.0.1`.

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
| Linux | kernel TUN | `sudo` или CAP_NET_ADMIN | `ip` должен быть на PATH |
| macOS | `utun` | `sudo` | utun — point-to-point, gateway обязателен |
| Windows | [wintun.dll](https://www.wintun.net/) | Administrator | `wintun.dll` рядом с .exe или в PATH |

## Структура

```
cmd/
├── vpn-ca/      — CLI для CA (init / issue-server / issue-client / list)
├── vpn-server/  — VPN-сервер
└── vpn-client/  — VPN-клиент

internal/
├── ca/          — выпуск ECDSA P-256 сертификатов
├── frame/       — длино-префиксная фреймовка
├── tun/         — кроссплатформенный TUN (linux/darwin/windows)
├── ipalloc/     — пул IPv4-адресов
└── tunnel/      — wire protocol и логика сервера/клиента
    ├── server/  — TLS listener, registry, маршрутизация
    └── client/  — connect + reconnect, keepalive
```

## Tests

```bash
go test ./...
```
