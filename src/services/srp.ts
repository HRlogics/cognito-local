import crypto from "node:crypto";

/**
 * AWS Cognito SRP-6a primitives, byte-for-byte compatible with
 * `amazon-cognito-identity-js` (`AuthenticationHelper`) and `cognito-srp-helper`,
 * so clients that sign M1 against those libraries verify here.
 *
 * The emulator keeps the plaintext password in its user store, so the per-user
 * salt + verifier are derived on the fly at auth time rather than persisted —
 * this also makes AdminCreateUser / AdminSetUserPassword users SRP-loginable
 * without touching every password-set path.
 */

// Well-known Cognito 3072-bit group (RFC 3526 group 15). g = 2.
const N_HEX = [
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
].join("");

const ZERO = BigInt(0);
const ONE = BigInt(1);

export const N = BigInt(`0x${N_HEX}`);
export const g = BigInt(2);

const sha256 = (buf: Buffer): Buffer =>
  crypto.createHash("sha256").update(buf).digest();

/** SHA256 over the bytes of a hex string, returned as hex (amazon's hexHash). */
const hexHash = (hexStr: string): string =>
  sha256(Buffer.from(hexStr, "hex")).toString("hex");

/**
 * amazon-cognito-identity-js padHex: even-length hex, and a leading "00" when
 * the top nibble is >= 8 so the value reads as unsigned.
 */
export const padHex = (value: bigint): string => {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  } else if ("89abcdefABCDEF".includes(hex[0])) {
    hex = `00${hex}`;
  }
  return hex;
};

export const modPow = (
  base: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint => {
  if (modulus === ONE) return ZERO;
  let result = ONE;
  let b = base % modulus;
  if (b < ZERO) b += modulus;
  let e = exponent;
  while (e > ZERO) {
    if (e & ONE) result = (result * b) % modulus;
    e >>= ONE;
    b = (b * b) % modulus;
  }
  return result;
};

const k = BigInt(`0x${hexHash(padHex(N) + padHex(g))}`);
export const getK = (): bigint => k;

/** Pool id without the `region_` prefix (e.g. `us-east-1_AbC` -> `AbC`). */
export const poolNameFromId = (userPoolId: string): string =>
  userPoolId.includes("_") ? userPoolId.split("_")[1] : userPoolId;

/**
 * x = SHA256(PAD(salt) || SHA256(poolName || username || ':' || password))
 */
export const deriveX = (
  poolName: string,
  username: string,
  password: string,
  saltHex: string,
): bigint => {
  const credHash = sha256(
    Buffer.from(`${poolName}${username}:${password}`, "utf8"),
  ).toString("hex");
  const saltPadded = padHex(BigInt(`0x${saltHex}`));
  return BigInt(`0x${hexHash(saltPadded + credHash)}`);
};

/** v = g^x mod N */
export const deriveVerifier = (
  poolName: string,
  username: string,
  password: string,
  saltHex: string,
): bigint => modPow(g, deriveX(poolName, username, password, saltHex), N);

/** u = SHA256(PAD(A) || PAD(B)) */
export const computeU = (A: bigint, B: bigint): bigint =>
  BigInt(`0x${hexHash(padHex(A) + padHex(B))}`);

/** B = (k*v + g^b) mod N */
export const computeB = (b: bigint, v: bigint): bigint =>
  (k * v + modPow(g, b, N)) % N;

/** Server shared secret: S = (A * v^u)^b mod N */
export const computeServerS = (
  A: bigint,
  v: bigint,
  u: bigint,
  b: bigint,
): bigint => modPow((A * modPow(v, u, N)) % N, b, N);

const INFO_BITS = Buffer.concat([
  Buffer.from("Caldera Derived Key", "utf8"),
  Buffer.from([1]),
]);

/** Cognito HKDF: HMAC-SHA256(salt=PAD(u), ikm=PAD(S)) then HMAC over info, 16 bytes. */
export const deriveKey = (S: bigint, u: bigint): Buffer => {
  const ikm = Buffer.from(padHex(S), "hex");
  const salt = Buffer.from(padHex(u), "hex");
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  return crypto
    .createHmac("sha256", prk)
    .update(INFO_BITS)
    .digest()
    .subarray(0, 16);
};

/**
 * M1 = base64(HMAC-SHA256(K, poolName || username || decode(SECRET_BLOCK) || TIMESTAMP))
 * `secretBlockB64` is echoed verbatim by the client; its raw bytes go into the MAC.
 */
export const computeM1 = (
  key: Buffer,
  poolName: string,
  username: string,
  secretBlockB64: string,
  timestamp: string,
): string => {
  const message = Buffer.concat([
    Buffer.from(poolName, "utf8"),
    Buffer.from(username, "utf8"),
    Buffer.from(secretBlockB64, "base64"),
    Buffer.from(timestamp, "utf8"),
  ]);
  return crypto.createHmac("sha256", key).update(message).digest("base64");
};

export interface SrpServerState {
  /** internal username (also echoed as USER_ID_FOR_SRP) */
  username: string;
  /** server salt (hex) */
  saltHex: string;
  /** server private ephemeral b (hex) */
  bHex: string;
  /** client public ephemeral A (hex) */
  aHex: string;
}

/** Cognito lets a PASSWORD_VERIFIER challenge be answered for about 3 minutes */
export const SECRET_BLOCK_TTL_MS = 3 * 60 * 1000;

// Per-process key for the opaque SECRET_BLOCK that carries server SRP state across the
// InitiateAuth -> RespondToAuthChallenge round-trip. The state includes the private ephemeral b,
// from which a client could recover the verifier (v = (B - g^b) / k) and sign in without the
// password, so it is encrypted (AES-256-GCM), not just signed. Regenerated on restart: in-flight
// SRP sessions then fail, like real expired Cognito sessions.
const SERVER_BLOCK_KEY = crypto.randomBytes(32);

export const encodeSecretBlock = (
  state: SrpServerState,
  now = Date.now(),
): string => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", SERVER_BLOCK_KEY, iv);
  const data = Buffer.concat([
    cipher.update(JSON.stringify({ ...state, issuedAt: now }), "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64");
};

// SECRET_BLOCKs already answered, so a captured PASSWORD_VERIFIER response can't be replayed.
// Entries are dropped once they are past the TTL, when decodeSecretBlock would reject them anyway.
const usedSecretBlocks = new Map<string, number>();

/**
 * Opens a SECRET_BLOCK issued by encodeSecretBlock. Throws when it was tampered with, issued by
 * another process, older than SECRET_BLOCK_TTL_MS, or already used.
 */
export const decodeSecretBlock = (
  secretBlockB64: string,
  now = Date.now(),
): SrpServerState => {
  const raw = Buffer.from(secretBlockB64, "base64");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    SERVER_BLOCK_KEY,
    raw.subarray(0, 12),
  );
  decipher.setAuthTag(raw.subarray(12, 28));
  // final() throws when the block was tampered with or issued by another process
  const json = Buffer.concat([
    decipher.update(raw.subarray(28)),
    decipher.final(),
  ]).toString("utf8");
  const { issuedAt, ...state } = JSON.parse(json) as SrpServerState & {
    issuedAt: number;
  };
  if (now - issuedAt > SECRET_BLOCK_TTL_MS) {
    throw new Error("SECRET_BLOCK expired");
  }
  for (const [block, expiresAt] of usedSecretBlocks) {
    if (expiresAt < now) usedSecretBlocks.delete(block);
  }
  if (usedSecretBlocks.has(secretBlockB64)) {
    throw new Error("SECRET_BLOCK already used");
  }
  usedSecretBlocks.set(secretBlockB64, issuedAt + SECRET_BLOCK_TTL_MS);
  return state;
};

/**
 * Verifies a PASSWORD_VERIFIER answer: recovers the server state from SECRET_BLOCK, re-derives the
 * shared key from the stored password and checks the client's M1 proof. Returns false for a
 * missing, expired, replayed or foreign block, or a wrong proof.
 */
export const verifyPasswordClaim = (
  poolId: string,
  user: { Username: string; Password?: string },
  secretBlock: string,
  timestamp: string,
  signature: string,
): boolean => {
  let serverState: SrpServerState;
  try {
    serverState = decodeSecretBlock(secretBlock);
  } catch {
    return false;
  }
  if (serverState.username !== user.Username || user.Password === undefined) {
    return false;
  }

  const poolName = poolNameFromId(poolId);
  const A = BigInt(`0x${serverState.aHex}`);
  const b = BigInt(`0x${serverState.bHex}`);
  const verifier = deriveVerifier(
    poolName,
    user.Username,
    user.Password,
    serverState.saltHex,
  );
  const u = computeU(A, computeB(b, verifier));
  const key = deriveKey(computeServerS(A, verifier, u, b), u);
  const expected = Buffer.from(
    computeM1(key, poolName, user.Username, secretBlock, timestamp),
    "base64",
  );
  const provided = Buffer.from(signature, "base64");
  return (
    provided.length === expected.length &&
    crypto.timingSafeEqual(provided, expected)
  );
};

/** Random server ephemeral b in [1, N), and the matching B != 0 mod N. */
export const generateServerEphemeral = (
  v: bigint,
): { b: bigint; B: bigint } => {
  for (;;) {
    const b = BigInt(`0x${crypto.randomBytes(64).toString("hex")}`) % N;
    if (b === ZERO) continue;
    const B = computeB(b, v);
    if (B % N !== ZERO) return { b, B };
  }
};
