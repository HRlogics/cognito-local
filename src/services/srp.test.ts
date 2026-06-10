import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  computeB,
  computeM1,
  computeServerS,
  computeU,
  decodeSecretBlock,
  deriveKey,
  deriveVerifier,
  encodeSecretBlock,
  g,
  generateServerEphemeral,
  modPow,
  N,
  padHex,
  poolNameFromId,
} from "./srp";

describe("srp", () => {
  describe("modPow", () => {
    it("computes modular exponentiation", () => {
      expect(modPow(BigInt(2), BigInt(10), BigInt(1000))).toBe(BigInt(24)); // 1024 % 1000
      expect(modPow(BigInt(4), BigInt(13), BigInt(497))).toBe(BigInt(445));
    });
  });

  describe("padHex", () => {
    it("pads odd-length hex to even", () => {
      expect(padHex(BigInt(0x123))).toBe("0123");
    });

    it("prepends 00 when the top nibble has the sign bit set", () => {
      expect(padHex(BigInt(0x80))).toBe("0080");
      expect(padHex(BigInt(0xff))).toBe("00ff");
    });

    it("leaves unambiguous values untouched", () => {
      expect(padHex(BigInt(0x14))).toBe("14");
    });
  });

  describe("poolNameFromId", () => {
    it("strips the region prefix", () => {
      expect(poolNameFromId("us-east-1_AbC123")).toBe("AbC123");
    });

    it("returns the id unchanged when there is no prefix", () => {
      expect(poolNameFromId("AbC123")).toBe("AbC123");
    });
  });

  describe("deriveVerifier", () => {
    it("is deterministic for the same inputs", () => {
      const saltHex = "00112233445566778899aabbccddeeff";
      const a = deriveVerifier("pool", "alice", "Password123!", saltHex);
      const b = deriveVerifier("pool", "alice", "Password123!", saltHex);
      expect(a).toBe(b);
      expect(a).toBeGreaterThan(BigInt(0));
      expect(a).toBeLessThan(N);
    });

    it("changes when the password changes", () => {
      const saltHex = "00112233445566778899aabbccddeeff";
      expect(deriveVerifier("pool", "alice", "right", saltHex)).not.toBe(
        deriveVerifier("pool", "alice", "wrong", saltHex),
      );
    });
  });

  describe("generateServerEphemeral", () => {
    it("produces B that is non-zero mod N", () => {
      const v = deriveVerifier("pool", "alice", "Password123!", "abcdef01");
      for (let i = 0; i < 10; i++) {
        const { b, B } = generateServerEphemeral(v);
        expect(b).toBeGreaterThan(BigInt(0));
        expect(b).toBeLessThan(N);
        expect(B % N).not.toBe(BigInt(0));
        expect(B).toBe(computeB(b, v)); // B is reproducible from b + v
      }
    });
  });

  describe("M1 signature", () => {
    // A full client/server exchange: server picks salt + b, client (here also
    // computed with the SRP math) proves knowledge of the password via M1.
    const poolName = "testpool";
    const username = "alice";
    const password = "Password123!";

    const exchange = (clientPassword: string) => {
      const saltHex = "00112233445566778899aabbccddeeff";
      const v = deriveVerifier(poolName, username, password, saltHex);
      const { b, B } = generateServerEphemeral(v);

      // client ephemeral
      const a = BigInt(`0x${crypto.randomBytes(64).toString("hex")}`) % N;
      const A = modPow(g, a, N);
      const u = computeU(A, B);

      // client-side shared secret using the *entered* password
      const xClient = deriveVerifier(
        poolName,
        username,
        clientPassword,
        saltHex,
      );
      void xClient;
      const secretBlock = Buffer.from("opaque").toString("base64");
      const timestamp = "Mon Jun 10 00:00:00 UTC 2026";

      // server M1
      const S = computeServerS(A, v, u, b);
      const serverKey = deriveKey(S, u);
      const serverM1 = computeM1(
        serverKey,
        poolName,
        username,
        secretBlock,
        timestamp,
      );

      // client M1 (recomputes S from the entered password)
      const xEntered = clientX(poolName, username, clientPassword, saltHex);
      const gx = modPow(g, xEntered, N);
      const kv = (getKForTest() * gx) % N;
      let base = (B - kv) % N;
      if (base < BigInt(0)) base += N;
      const sClient = modPow(base, a + u * xEntered, N);
      const clientKey = deriveKey(sClient, u);
      const clientM1 = computeM1(
        clientKey,
        poolName,
        username,
        secretBlock,
        timestamp,
      );

      return { serverM1, clientM1 };
    };

    it("matches when the entered password is correct", () => {
      const { serverM1, clientM1 } = exchange(password);
      expect(clientM1).toBe(serverM1);
    });

    it("does not match when the entered password is wrong", () => {
      const { serverM1, clientM1 } = exchange("WrongPassword!");
      expect(clientM1).not.toBe(serverM1);
    });
  });

  describe("SECRET_BLOCK", () => {
    it("round-trips server state", () => {
      const state = {
        username: "alice",
        saltHex: "abcd",
        bHex: "01ff",
        aHex: "deadbeef",
      };
      expect(decodeSecretBlock(encodeSecretBlock(state))).toEqual(state);
    });

    it("rejects a tampered block", () => {
      const block = encodeSecretBlock({
        username: "alice",
        saltHex: "abcd",
        bHex: "01ff",
        aHex: "deadbeef",
      });
      const wrapper = JSON.parse(
        Buffer.from(block, "base64").toString("utf8"),
      ) as { d: string; m: string };
      wrapper.d = wrapper.d.replace("alice", "mallory");
      const tampered = Buffer.from(JSON.stringify(wrapper), "utf8").toString(
        "base64",
      );
      expect(() => decodeSecretBlock(tampered)).toThrow();
    });
  });
});

// Local SRP-6a client helpers, kept in the test so the assertions don't depend
// on the production module exporting client-only math.
const clientX = deriveX;
function deriveX(
  poolName: string,
  username: string,
  password: string,
  saltHex: string,
): bigint {
  const credHash = crypto
    .createHash("sha256")
    .update(Buffer.from(`${poolName}${username}:${password}`, "utf8"))
    .digest("hex");
  const saltPadded = padHex(BigInt(`0x${saltHex}`));
  const xHex = crypto
    .createHash("sha256")
    .update(Buffer.from(saltPadded + credHash, "hex"))
    .digest("hex");
  return BigInt(`0x${xHex}`);
}

function getKForTest(): bigint {
  const hexHash = (hexStr: string) =>
    crypto
      .createHash("sha256")
      .update(Buffer.from(hexStr, "hex"))
      .digest("hex");
  return BigInt(`0x${hexHash(padHex(N) + padHex(g))}`);
}
