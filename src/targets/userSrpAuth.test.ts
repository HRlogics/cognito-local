import crypto from "node:crypto";
import AuthenticationHelperModule from "amazon-cognito-identity-js/lib/AuthenticationHelper.js";
import BigIntegerModule from "amazon-cognito-identity-js/lib/BigInteger.js";
import {
  createSrpSession,
  signSrpSession,
  wrapAuthChallenge,
  wrapInitiateAuth,
} from "cognito-srp-helper";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError } from "../errors";
import type { UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import type { User } from "../services/userPoolService";
import { InitiateAuth, type InitiateAuthTarget } from "./initiateAuth";
import {
  RespondToAuthChallenge,
  type RespondToAuthChallengeTarget,
} from "./respondToAuthChallenge";

// amazon-cognito-identity-js ships BigInteger + AuthenticationHelper without
// public types, so reach them through casts.
const BigInteger = ((BigIntegerModule as { default?: unknown }).default ??
  BigIntegerModule) as new (
  value: string,
  radix: number,
) => unknown;

interface AuthHelper {
  getLargeAValue(
    cb: (err: unknown, a: { toString(radix: number): string }) => void,
  ): void;
  getPasswordAuthenticationKey(
    username: string,
    password: string,
    serverB: unknown,
    salt: unknown,
    cb: (err: unknown, key: Buffer) => void,
  ): void;
}
const AuthenticationHelper = ((
  AuthenticationHelperModule as { default?: unknown }
).default ?? AuthenticationHelperModule) as new (
  poolName: string,
) => AuthHelper;

const POOL_ID = "us-east-1_testpool";
const POOL_NAME = "testpool";
const PASSWORD = "Password123!";

describe("USER_SRP_AUTH end-to-end", () => {
  let initiateAuth: InitiateAuthTarget;
  let respondToAuthChallenge: RespondToAuthChallengeTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let user: User;
  const userPoolClient = TDB.appClient({ UserPoolId: POOL_ID });

  beforeEach(() => {
    user = TDB.user({ Username: "alice", Password: PASSWORD });

    mockUserPoolService = newMockUserPoolService({ Id: POOL_ID });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    mockTokenGenerator = newMockTokenGenerator();
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
    });

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    initiateAuth = InitiateAuth({
      cognito: mockCognitoService,
      messages: newMockMessages(),
      otp: () => "123456",
      triggers: newMockTriggers(),
      tokenGenerator: mockTokenGenerator,
    });
    respondToAuthChallenge = RespondToAuthChallenge({
      clock: new ClockFake(new Date()),
      cognito: mockCognitoService,
      messages: newMockMessages(),
      otp: () => "123456",
      triggers: newMockTriggers(),
      tokenGenerator: mockTokenGenerator,
    });
  });

  describe("cognito-srp-helper client", () => {
    it("returns tokens for the correct password", async () => {
      const session = createSrpSession(user.Username, PASSWORD, POOL_ID, false);

      const initResp = await initiateAuth(
        TestContext,
        wrapInitiateAuth(session, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_SRP_AUTH",
          AuthParameters: { USERNAME: user.Username },
        }),
      );
      expect(initResp.ChallengeName).toBe("PASSWORD_VERIFIER");

      const signed = signSrpSession(session, initResp);
      const resp = await respondToAuthChallenge(
        TestContext,
        wrapAuthChallenge(signed, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeResponses: { USERNAME: user.Username },
        }),
      );

      expect(resp.AuthenticationResult?.AccessToken).toBe("access");
      expect(resp.AuthenticationResult?.ExpiresIn).toBe(3600);
    });

    it("rejects the wrong password with NotAuthorizedException", async () => {
      const session = createSrpSession(
        user.Username,
        "WrongPassword!",
        POOL_ID,
        false,
      );

      const initResp = await initiateAuth(
        TestContext,
        wrapInitiateAuth(session, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_SRP_AUTH",
          AuthParameters: { USERNAME: user.Username },
        }),
      );

      const signed = signSrpSession(session, initResp);
      await expect(
        respondToAuthChallenge(
          TestContext,
          wrapAuthChallenge(signed, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "PASSWORD_VERIFIER",
            ChallengeResponses: { USERNAME: user.Username },
          }),
        ),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });
    it("rejects a SECRET_BLOCK issued for another user", async () => {
      const session = createSrpSession(user.Username, PASSWORD, POOL_ID, false);
      const initResp = await initiateAuth(
        TestContext,
        wrapInitiateAuth(session, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_SRP_AUTH",
          AuthParameters: { USERNAME: user.Username },
        }),
      );
      const signed = signSrpSession(session, initResp);

      mockUserPoolService.getUserByUsername.mockResolvedValue(
        TDB.user({ Username: "bob", Password: PASSWORD }),
      );
      await expect(
        respondToAuthChallenge(
          TestContext,
          wrapAuthChallenge(signed, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "PASSWORD_VERIFIER",
            ChallengeResponses: { USERNAME: "bob" },
          }),
        ),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });
  });

  describe("amazon-cognito-identity-js (Amplify) client", () => {
    const TIMESTAMP = "Mon Jun 10 00:00:00 UTC 2026";

    it("returns tokens for the correct password", async () => {
      const helper = new AuthenticationHelper(POOL_NAME);
      const srpA: string = await new Promise((res, rej) =>
        helper.getLargeAValue(
          (err: unknown, a: { toString(radix: number): string }) =>
            err ? rej(err) : res(a.toString(16)),
        ),
      );

      const initResp = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "USER_SRP_AUTH",
        AuthParameters: { USERNAME: user.Username, SRP_A: srpA },
      });
      const challenge = initResp.ChallengeParameters as Record<string, string>;

      const key: Buffer = await new Promise((res, rej) =>
        helper.getPasswordAuthenticationKey(
          user.Username,
          PASSWORD,
          new BigInteger(challenge.SRP_B, 16),
          new BigInteger(challenge.SALT, 16),
          (err: unknown, k: Buffer) => (err ? rej(err) : res(k)),
        ),
      );
      const signature = crypto
        .createHmac("sha256", key)
        .update(
          Buffer.concat([
            Buffer.from(POOL_NAME, "utf8"),
            Buffer.from(user.Username, "utf8"),
            Buffer.from(challenge.SECRET_BLOCK, "base64"),
            Buffer.from(TIMESTAMP, "utf8"),
          ]),
        )
        .digest("base64");

      const resp = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "PASSWORD_VERIFIER",
        ChallengeResponses: {
          USERNAME: user.Username,
          PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
          PASSWORD_CLAIM_SIGNATURE: signature,
          TIMESTAMP,
        },
      });

      expect(resp.AuthenticationResult?.AccessToken).toBe("access");
      expect(resp.AuthenticationResult?.ExpiresIn).toBe(3600);
    });

    it("rejects the wrong password with NotAuthorizedException", async () => {
      const helper = new AuthenticationHelper(POOL_NAME);
      const srpA: string = await new Promise((res, rej) =>
        helper.getLargeAValue(
          (err: unknown, a: { toString(radix: number): string }) =>
            err ? rej(err) : res(a.toString(16)),
        ),
      );

      const initResp = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "USER_SRP_AUTH",
        AuthParameters: { USERNAME: user.Username, SRP_A: srpA },
      });
      const challenge = initResp.ChallengeParameters as Record<string, string>;

      const key: Buffer = await new Promise((res, rej) =>
        helper.getPasswordAuthenticationKey(
          user.Username,
          "WrongPassword!",
          new BigInteger(challenge.SRP_B, 16),
          new BigInteger(challenge.SALT, 16),
          (err: unknown, k: Buffer) => (err ? rej(err) : res(k)),
        ),
      );
      const signature = crypto
        .createHmac("sha256", key)
        .update(
          Buffer.concat([
            Buffer.from(POOL_NAME, "utf8"),
            Buffer.from(user.Username, "utf8"),
            Buffer.from(challenge.SECRET_BLOCK, "base64"),
            Buffer.from(TIMESTAMP, "utf8"),
          ]),
        )
        .digest("base64");

      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeResponses: {
            USERNAME: user.Username,
            PASSWORD_CLAIM_SECRET_BLOCK: challenge.SECRET_BLOCK,
            PASSWORD_CLAIM_SIGNATURE: signature,
            TIMESTAMP,
          },
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });
  });
});
