# macOS Keychain bypass

### User reports repeated macOS Keychain authorization dialogs

1. Stop the exact automatic caller after verifying its PID. Do not retry the
   failing command in a loop and do not type a password or click the system
   authorization dialog on the user's behalf.
2. Run `keys keychain status`; this is metadata-only and does not open Keychain.
3. Only when the user explicitly requests bypass, run `keys keychain bypass`.
   This keeps the original secrets in macOS Keychain and disables Keychain UI;
   it does not export, copy, migrate, or replace any value.
4. In bypass, ordinary operations use Security.framework in-process. A legacy
   read may use `/usr/bin/security` only after native ACL inspection proves that
   the unlocked original item already grants it decrypt access. Unknown,
   locked, or untrusted ACLs fail before a compatibility process can start.
5. Verify policy and unlocked readiness with `keys keychain status --check`;
   this metadata-only probe also forbids UI. Then run the requested operation
   once.
6. If that one attempt fails because the original item's ACL does not trust the
   native runtime, `keys keychain prepare NAME --check` is a metadata-only
   preflight. Only when the user explicitly asks to change that exact item, run
   `keys keychain prepare NAME`. It changes the decrypt ACL of that one original
   item without reading or copying its value; macOS may ask the human to
   authorize this setup step.
7. Never loop or bulk-run preparation and never interact with the system dialog
   for the user. The trusted identity comes from Security.framework's current
   executable identity, not a caller-supplied client label. This compatibility
   setup is not signed-broker isolation; partitioned items are refused rather
   than weakened. `keys keychain prompt` restores normal macOS authorization
   dialogs.
