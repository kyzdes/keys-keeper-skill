# keys-keeper web vault — a zero-knowledge browser vault (read-only v1).
#
# The browser fetches the encrypted KK1 blob and decrypts it IN-PAGE with the
# user's passphrase; this server only ever shuttles ciphertext + non-secret
# commit metadata to/from S3. It never sees the passphrase or plaintext.
#
# Put TLS (and HSTS) in front via a reverse proxy, OR pass --certfile/--keyfile.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
    "keys-keeper @ git+https://github.com/kyzdes/keys-keeper-skill.git"

# Non-secret defaults; override the rest at runtime (see README).
ENV WEBVAULT_S3_REGION=us-east-1 \
    WEBVAULT_S3_ADDRESSING=path

# Required env at runtime:
#   WEBVAULT_S3_ENDPOINT  WEBVAULT_S3_BUCKET  WEBVAULT_S3_ACCESS_KEY_ID
#   WEBVAULT_S3_SECRET_KEY  WEBVAULT_VAULT_PREFIX  WEBVAULT_REGISTER_TOKEN
# Account/session state persists in /data.
VOLUME ["/data"]
EXPOSE 8333

CMD ["keys", "webvault", "serve", "--host", "0.0.0.0", "--port", "8333", "--data-dir", "/data"]
