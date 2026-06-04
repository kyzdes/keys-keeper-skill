// Node harness: decrypt a CLI-produced KK1 blob with the browser crypto port,
// and derive the account auth-hash. Prints {payload, ah} as JSON.
// argv: <kkcrypto.mjs path> <blob path> <passphrase> <authSaltHex> <iterations>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [, , modPath, blobPath, passphrase, authSaltHex, itersStr] = process.argv;
const kk = await import(pathToFileURL(modPath).href);

const blob = new Uint8Array(readFileSync(blobPath));
const payload = await kk.decryptBlob(blob, passphrase);

const authSalt = Uint8Array.from(authSaltHex.match(/../g).map((h) => parseInt(h, 16)));
const ah = await kk.deriveAuthHash(passphrase, authSalt, parseInt(itersStr, 10));

process.stdout.write(JSON.stringify({ payload, ah }));
