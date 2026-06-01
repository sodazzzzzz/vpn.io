# Packaging — system services for the helper daemon

The `vpn-helper` daemon owns the tunnel and must run with root privileges
(it creates the TUN device and edits routes, the firewall and DNS). These
files install it as a system service so it starts at boot and is restarted
if it crashes.

| OS      | Mechanism   | Files                                        |
| ------- | ----------- | -------------------------------------------- |
| Linux   | systemd     | `systemd/vpn-helper.service`, `systemd/*.sh` |
| macOS   | launchd     | `launchd/io.vpnio.helper.plist`, `launchd/*.sh` |
| Windows | —           | not yet (ships with the named-pipe transport) |

## 1. Build the binary

The scripts install but do not build. Put the helper where the service
unit expects it (`/usr/local/bin/vpn-helper`):

```sh
go build -o /usr/local/bin/vpn-helper ./cmd/vpn-helper
```

Override the location with the `BIN` environment variable if you install
it elsewhere.

## 2. Install / uninstall

### Linux (systemd)

```sh
sudo packaging/systemd/install.sh     # copy unit, daemon-reload, enable --now
systemctl status vpn-helper           # check it
journalctl -u vpn-helper -f           # follow logs
sudo packaging/systemd/uninstall.sh   # stop, disable, remove
```

The unit uses a private runtime directory: systemd creates `/run/vpn-io`
on start (mode 0755) and removes it on stop. The control socket lives at
`/run/vpn-io/helper.sock`.

### macOS (launchd)

```sh
sudo packaging/launchd/install.sh     # copy plist, bootstrap, enable
sudo launchctl print system/io.vpnio.helper   # check it
sudo packaging/launchd/uninstall.sh   # bootout, remove
```

Logs go to `/var/log/vpn-io-helper.log`; the control socket is
`/var/run/vpn-io-helper.sock`.

## Granting a desktop user access

By default the control socket admits **only root** — both the file mode
(`0660`, owned by root) and the daemon's peer-credential check restrict it.
A front-end (CLI/GUI) running as a normal user therefore can't connect yet;
that is intentional until GUI integration wires this up.

To grant a specific user now, the daemon needs to (a) allow their group in
its peer-credential policy and (b) have the socket be group-accessible to
that group:

- **systemd:** add a drop-in. `sudo systemctl edit vpn-helper` and set:

  ```ini
  [Service]
  ExecStart=
  ExecStart=/usr/local/bin/vpn-helper -socket /run/vpn-io/helper.sock -socket-mode 0660 -allow-gid 1000 -log-level info
  ```

  (replace `1000` with the target gid; the empty `ExecStart=` clears the
  original line). Then `sudo systemctl restart vpn-helper`. The runtime
  directory is `0750 root:root` by default, so that group also needs to
  reach the socket — add `RuntimeDirectoryMode=0755` to the same drop-in (or
  group-own the directory) so a non-root member can traverse `/run/vpn-io`.

- **launchd:** add `-allow-gid <gid>` to the `ProgramArguments` array in the
  plist, then reinstall.

The peer-credential check (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on
macOS) is the authority on who may connect; the socket mode is the first
gate in front of it. root is always allowed.

## Notes

- The helper exits cleanly on `SIGTERM`, tearing the tunnel down; both
  services send `SIGTERM` on stop.
- Restart policy covers crashes only, not a clean stop/uninstall.
