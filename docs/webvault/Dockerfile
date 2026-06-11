# keys-keeper web vault — a zero-knowledge browser vault (read-only v1).
#
# The browser fetches the encrypted KK1 blob and decrypts it IN-PAGE with the
# user's passphrase; this server only ever shuttles ciphertext + non-secret
# commit metadata to/from S3. It never sees the passphrase or plaintext.
#
# Put TLS (and HSTS) in front via a reverse proxy, OR pass --certfile/--keyfile.
FROM python:3.12-slim

# Pin to an immutable commit instead of git HEAD so image builds are reproducible
# and a compromised/force-pushed branch can't silently change what we install.
# bump on release
RUN pip install --no-cache-dir \
    "keys-keeper @ git+https://github.com/kyzdes/keys-keeper-skill.git@078b2cac79f6eff66d8a2ebff97c03635546ef47"

# Non-secret defaults; override the rest at runtime (see README).
ENV WEBVAULT_S3_REGION=us-east-1 \
    WEBVAULT_S3_ADDRESSING=path

# Required env at runtime:
#   WEBVAULT_S3_ENDPOINT  WEBVAULT_S3_BUCKET  WEBVAULT_S3_ACCESS_KEY_ID
#   WEBVAULT_S3_SECRET_KEY  WEBVAULT_VAULT_PREFIX
# Single-tenant registration is CLOSED by default (fail-closed): set
#   WEBVAULT_REGISTER_TOKEN  to gate sign-up with a token, or (only on a trusted
# network) WEBVAULT_ALLOW_OPEN_REGISTRATION=1 for token-less sign-up.
# Behind a TLS reverse proxy, set WEBVAULT_BEHIND_PROXY=1 so the session cookie
# gets the Secure flag from X-Forwarded-Proto=https.
# Account/session state persists in /data.

# Run as an unprivileged user. Create the data dir up front and hand it to the
# non-root user so the persisted account store is writable without root.
RUN useradd --system --create-home --uid 10001 kkvault \
    && mkdir -p /data \
    && chown -R kkvault:kkvault /data
VOLUME ["/data"]
EXPOSE 8333

USER kkvault

CMD ["keys", "webvault", "serve", "--host", "0.0.0.0", "--port", "8333", "--data-dir", "/data"]
