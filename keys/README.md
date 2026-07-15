# Router SSH key

This directory intentionally contains no keys in Git.

Generate a dedicated Ed25519 key on Windows:

```powershell
.\generate_router_key.ps1
```

Copy the generated `router_monitor_ed25519.pub` line to `/etc/dropbear/authorized_keys` on OpenWrt. Keep the private key local and never commit it.

Recommended restrictions:

- use a dedicated key for the monitor;
- protect the private file with Windows ACL;
- remove the key from OpenWrt when it is no longer needed;
- do not reuse an administrator key from another server.
