# Keys Keeper development

Start with `docs/architecture/VPS-REFACTOR-2026-10-02.md` for current scope,
VPS contracts and validation. `HARDENING-2026-10-02.md` records the preceding
mutation/private-file hardening. Earlier reviews describe their pinned
baselines, not the current working tree.

- Keep CLI, HTTP and workers as adapters around application/domain code.
- S3/WebVault were removed. KK1 file backup, local admin, KK2 VPS and KK3
  project/personal sync remain. Snapshot preparation lives in `vault_snapshot`.
- Never skip fresh remote membership/revocation or signed ancestry verification
  to optimize VPS history. Relay quota counters must share the data transaction.
- Ordinary master writes use `VaultService` and `MasterMutationManager` for
  both metadata schemas. Do not add another exception-only rollback path.
- Use `private_files` for bounded private IO and `request_json` for local JSON
  request contracts. Windows creation must set its DACL before writing data.
- Agent instructions live in `src/keys_keeper/agent_rules/canonical.py`.
  Regenerate shipped skills, references and rule fixtures after changing it.
- Run tests against temporary synthetic vaults. Ordinary pytest isolates the
  clipboard; native clipboard tests require explicit environment opt-in.
  Never run diagnostics against the operator's vault or login keychain.
- Existing dependencies and ordinary HTML/JS are sufficient. Add no optional
  UI libraries or new storage/protocol mechanisms without a concrete need.

Local validation: `PYTHONPATH=src .venv/bin/python -m pytest -q -o addopts=''`.
The CI matrix also covers Windows native DACLs, Linux Secret Service, Python
3.10/3.14, native macOS builds and installed-wheel generation.
