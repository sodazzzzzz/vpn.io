# Backing up and restoring the CA

The CA directory (`ca-data/` by default) is the one piece of this project that
cannot be rebuilt. Everything else — the server, the helper, a client install —
can be reinstalled from a release in minutes. The CA cannot: `ca.key` signed
every certificate in circulation, and there is exactly one copy of it, on the
machine you run `vpn-ca` from.

If it is lost, every client certificate has to be re-issued and every profile
re-delivered by hand. If it is copied, whoever has it can mint a client
certificate the server will accept — silently, forever, without touching the
server at all.

So: keep an encrypted backup somewhere else, and make sure you can actually
restore from it.

## What is in the CA directory

| File | Rebuildable? |
|---|---|
| `ca.crt`, `ca.key` | **No.** The root of everything. |
| `issued.json` | **No.** Every serial ever issued — the only record that lets you revoke a superseded certificate. |
| `revoked.json` | **No.** The deny-list the server enforces. |
| `clients/<name>.crt`, `.key` | Re-issuable, but re-issuing revokes the profile that person already has. |
| `server/server.crt`, `.key` | Re-issuable; requires a server restart and briefly drops tunnels. |

`vpn-ca backup` captures all of it, so a restore puts you back exactly where you
were — including the ability to re-export an existing friend's profile without
invalidating theirs.

## Making a backup

The passphrase comes from a file, from stdin, or from `$VPNIO_CA_PASSPHRASE` —
never from a prompt, so nothing echoes into a terminal scrollback and the same
command works from a script.

```bash
# from a password manager (recommended)
pass show vpnio/ca-backup | vpn-ca backup -passphrase-file -

# or from the environment
export VPNIO_CA_PASSPHRASE='...'
vpn-ca backup -dir ca-data -out ca-backup-2026-08-09.vpnio-ca
```

The result is a single self-describing JSON file: a cleartext header (format,
KDF parameters, the CA's CommonName and the date, so you can tell two backups
apart without opening them) and one AES-256-GCM sealed blob holding a gzipped
copy of the directory. The key comes from the passphrase via PBKDF2-HMAC-SHA256
(600 000 iterations); the header is authenticated alongside the ciphertext, so
editing it — for instance to weaken the KDF — makes the file fail to open rather
than open more cheaply.

Rules that matter more than the crypto:

- **Minimum 12 characters, and not one you use elsewhere.** The passphrase is
  the only thing protecting the root key once the file leaves your machine.
- **Store the file and the passphrase in different places.** A backup in the
  same password manager entry as its passphrase is a plaintext backup.
- **Never commit it.** `.gitignore` covers `*.vpnio-ca`, but that is a safety
  net, not permission to keep it in the repo directory.
- **Re-take it after issuing or revoking**, otherwise a restore silently
  resurrects access you removed. It is one command; run it in the same sitting.

## Restoring

Restore refuses to write into a directory that already holds a `ca.crt` or
`ca.key`, so it can never half-overwrite a live CA. Restore into a new path and
move it into place once you have checked it.

```bash
vpn-ca restore -in ca-backup-2026-08-09.vpnio-ca -dir ca-data
```

It prints which CA and which date the file holds before asking the passphrase to
do any work, then reloads the restored directory and reports the client count —
so a container that unpacks into something that is not a working CA fails here,
not at the next issuance.

### Verify before you trust it

A restore that "succeeded" is not yet a CA you can rely on. Check it end to end:

```bash
vpn-ca list -dir ca-data                       # expected clients and revocations?
vpn-ca issue-client -dir ca-data -name drill   # can it still sign?
vpn-ca export-profile -dir ca-data -name drill -server <host:port> -out drill.vpnio
```

Import `drill.vpnio` in the app and connect. A tunnel that comes up proves the
restored key is the same one the server's certificate chain expects.

Then clean up the drill client so it does not stay valid for a year:

```bash
vpn-ca revoke -dir ca-data -name drill
```

## Fire drill

Do this once now, and again after any change to how the CA is stored. Restoring
for the first time during an actual emergency is how backups turn out to have
been unreadable all along.

1. Copy the backup file to a machine that has never held the CA (or just a fresh
   directory — the point is to use *only* the file and the passphrase).
2. Retrieve the passphrase from wherever you claim it lives. If you cannot find
   it in under a minute, the drill has already failed; fix that first.
3. `vpn-ca restore -in <file> -dir drill-ca`.
4. Run the verification above against the real server.
5. Delete the restored directory and revoke the drill client.

`TestBackupRestoreFireDrill` in `internal/ca` runs the same sequence in CI on
every commit — backup, restore into an empty directory, issue, verify the chain
against the original root — so the code path cannot rot between drills. What it
cannot check is whether *you* can find the file and the passphrase.

## If the key is gone and there is no backup

There is no recovery — this is the situation the backup exists to prevent. The
path forward is a new CA: `vpn-ca init`, re-issue the server certificate,
redeploy it to the VPS (see [SERVER.md](SERVER.md)), re-issue a client
certificate for every person and deliver every profile again. Everyone's current
profile stops working the moment the server picks up the new CA, so tell people
before, not after.

## If the key may have been copied

Treat it as compromised: anyone holding it can issue a client certificate the
server accepts, and revocation cannot help — the deny-list works by serial, and
they can mint serials you have never seen. The only fix is the same rebuild as
above, plus working out how the copy happened before rebuilding onto the same
machine.
