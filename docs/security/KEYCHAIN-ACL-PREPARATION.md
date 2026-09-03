# Native access preparation for original macOS Keychain items

## Problem and boundary

`UI_FORBIDDEN` guarantees that background and server operations never ask
macOS to display Keychain authorization UI. An older original item may trust
only `/usr/bin/security`; strict native access must then fail closed.

`keys keychain prepare NAME` is an explicit, one-item compatibility repair. It
adds the currently executing Keys Keeper runtime to that original item's
decrypt ACL. It does not read, copy, export, replace, or migrate the password
value. `--check` performs only a no-UI ACL metadata preflight.

There is deliberately no bulk command. Apple does not document a transaction
or a single authorization grant covering ACL changes to multiple items, so a
batch could create the same prompt storm this feature is intended to prevent.

## Native operation

The implementation uses the macOS Security.framework contract:

1. Locate the generic-password item by service and account while requesting
   only its item reference, never its data.
2. Copy its access instance and find ACL entries carrying decrypt
   authorization.
3. Create a `SecTrustedApplication` for `NULL`, which Apple defines as the
   application or tool making the call.
4. Append that identity to the existing trusted-application arrays without
   removing existing applications, descriptions, prompt selectors, or other
   ACL entries.
5. Commit once with `SecKeychainItemSetAccess`, then re-read ACL metadata and
   verify that the current runtime is present.

Primary sources:

- [Apple: Access Control Lists](https://developer.apple.com/documentation/security/access-control-lists)
- [Apple: SecKeychainItemSetAccess](https://developer.apple.com/documentation/security/seckeychainitemsetaccess%28_%3A_%3A%29)
- [Apple: SecTrustedApplicationCopyData](https://developer.apple.com/documentation/security/sectrustedapplicationcopydata%28_%3A_%3A%29)
- Local macOS SDK headers: `Security.framework/Headers/SecKeychainItem.h`,
  `SecACL.h`, and `SecTrustedApplication.h`.
- The local `security(1)` manual states that
  `set-generic-password-partition-list` requires the keychain password; Keys
  Keeper does not request or place that password in argv.

## Honest limitations

- These per-item ACL APIs are deprecated by Apple. They still exist on current
  macOS but are a compatibility mechanism, not the long-term broker design.
- With a Python/pipx installation, the trusted identity is the current runtime
  executable. Apple says the opaque trusted-application data includes identity
  such as a cryptographic hash and verifies that it is unaltered; nevertheless,
  this is not equivalent to a separately signed, code-designated Keys Keeper
  broker.
- The setup call may display macOS authorization UI. The CLI targets exactly
  one item and issues exactly one protected ACL commit, but it cannot promise
  how many UI surfaces a particular macOS release or Keychain policy displays.
- A code-signature partition ACL is refused rather than weakened; it requires
  the future signed broker. A locked Keychain, an iCloud-only item, a missing
  decrypt ACL, or denied authorization likewise fails without changing the
  stored secret. Background access remains fail-closed afterward.
