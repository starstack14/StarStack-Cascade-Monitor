# Security policy

## Reporting a vulnerability

Do not publish API tokens, passwords, private keys, router backups or exploit details in a public issue. Contact the repository owner privately and provide only the minimum information required to reproduce the problem.

## Secret handling

- Remnawave tokens and local passwords are stored in `config.local.json` using Windows DPAPI.
- SSH private keys, databases, diagnostics, logs and backups are excluded by `.gitignore`.
- The mobile backend binds to `127.0.0.1`; publish it only behind an HTTPS reverse proxy.
- Use a dedicated Remnawave read-only API token instead of a Superadmin session token.
- Rotate any secret that was pasted into a chat, issue or commit.

Before every release, inspect the staged files and run a secret scanner such as Gitleaks.
