"""keys-keeper Web — a zero-knowledge web vault.

A hardened proxy + browser SPA that lets you open your keys-keeper vault from a
browser. The browser fetches the encrypted KK1 blob and decrypts it IN-PAGE with
WebCrypto; the passphrase and plaintext never reach this server. The server is a
dumb, authenticated ciphertext shuttle that reuses S3Remote and never imports
`decrypt_blob`. See docs and the design at clever-floating-blanket.

v1 is READ-ONLY (unlock, view, copy). Multi-tenant-ready, run single-tenant.
"""
__all__ = ["store", "remote", "server"]
