import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UnsupportedError } from "../errors";
import type { Services } from "../services";
import { Targets } from "../targets/targets";
import { Router } from "./Router";

describe("Router", () => {
  it("returns an error handler for an invalid target", async () => {
    const services = {} as Services;
    const route = Router(services)("invalid");

    await expect(route(TestContext, null as any)).rejects.toEqual(
      new UnsupportedError('Unsupported x-amz-target header "invalid"'),
    );
  });

  it.each(Object.keys(Targets))("supports the %s target", (target) => {
    const services = {} as Services;
    const route = Router(services)(target);

    expect(route).toBeDefined();
  });

  describe("revoked access tokens", () => {
    const revokedAt = 1_700_000_000;
    const token = (iat: number) =>
      jwt.sign({ client_id: "client", sub: "user", iat }, "secret");

    const route = () => {
      const userPool = newMockUserPoolService();
      userPool.getUserByUsername.mockResolvedValue(
        TDB.user({ AccessTokensRevokedAt: revokedAt }),
      );
      const services = {
        cognito: newMockCognitoService(userPool),
      } as unknown as Services;
      // GetUser resolves the user from the pool; the mock returns the same user
      return Router(services)("GetUser");
    };

    it("rejects a token issued before the last global sign-out", async () => {
      await expect(
        route()(TestContext, { AccessToken: token(revokedAt - 10) }),
      ).rejects.toEqual(
        new NotAuthorizedError("Access Token has been revoked"),
      );
    });

    it("passes a token issued after the last global sign-out", async () => {
      await expect(
        route()(TestContext, { AccessToken: token(revokedAt + 1) }),
      ).resolves.toBeDefined();
    });

    it("leaves an undecodable token to the target", async () => {
      await expect(
        route()(TestContext, { AccessToken: "garbage" }),
      ).rejects.not.toEqual(
        new NotAuthorizedError("Access Token has been revoked"),
      );
    });
  });
});
