// kkcrypto.mjs — WebCrypto port of keys_keeper/crypto.py (the KK1 blob format).
//
// Decryption happens ONLY here, in the browser. The passphrase and the
// decrypted plaintext never leave the page — the server only ever holds the
// AES-256-GCM ciphertext. Byte-for-byte compatible with crypto.encrypt_blob:
//   blob = magic(4) | salt(16) | nonce(12) | AES-256-GCM(ct+tag)
//   key  = PBKDF2-HMAC-SHA256(passphrase, salt, 600000) -> 256-bit
//   AAD  = the magic bytes
//
// Locked against a CLI-produced blob by tests/test_webvault_crypto.py.

const MAGIC = new Uint8Array([0x4b, 0x4b, 0x31, 0x00]); // "KK1\0" — also the GCM AAD
const KDF_ITERATIONS = 600000;

const subtle = globalThis.crypto.subtle;

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export class BadPassword extends Error {}

async function deriveBlobKey(passphrase, salt) {
  const base = await subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"],
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: KDF_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable — even injected JS cannot exportKey() it
    ["decrypt"],
  );
}

// Mirrors crypto.decrypt_blob. Returns the parsed JSON payload object.
export async function decryptBlob(blob, passphrase) {
  const b = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  if (b.length < 32 || !bytesEqual(b.slice(0, 4), MAGIC)) {
    throw new BadPassword("not a keys-keeper blob");
  }
  const salt = b.slice(4, 20);
  const nonce = b.slice(20, 32);
  const ct = b.slice(32);
  const key = await deriveBlobKey(passphrase, salt);
  let pt;
  try {
    pt = await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: MAGIC }, key, ct,
    );
  } catch {
    throw new BadPassword("passphrase incorrect or vault corrupted");
  }
  return JSON.parse(new TextDecoder().decode(new Uint8Array(pt)));
}

// Account auth hash — a SEPARATE derivation from the passphrase (different,
// per-account salt) that the server verifies WITHOUT learning the blob key.
// Returns lowercase hex. Mirrors a server-side PBKDF2(passphrase, authSalt, n).
export async function deriveAuthHash(passphrase, authSalt, iterations) {
  const base = await subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt: authSalt, iterations, hash: "SHA-256" }, base, 256,
  );
  return hex(new Uint8Array(bits));
}

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
