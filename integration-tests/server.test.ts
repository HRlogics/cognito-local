import supertest from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createServer } from "../src";
import { MockLogger } from "../src/__tests__/mockLogger";
import {
  CodeMismatchError,
  CognitoError,
  InvalidPasswordError,
  NotAuthorizedError,
  UnsupportedError,
  UsernameExistsError,
} from "../src/errors";

describe("HTTP server", () => {
  describe("/", () => {
    it("errors with missing x-azm-target header", async () => {
      const router = vi.fn();
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application).post("/");

      expect(response.status).toEqual(400);
      expect(response.body).toEqual({ message: "Missing x-amz-target header" });
    });

    it("errors with an poorly formatted x-azm-target header", async () => {
      const router = vi.fn();
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application)
        .post("/")
        .set("x-amz-target", "bad-format");

      expect(response.status).toEqual(400);
      expect(response.body).toEqual({
        message: "Invalid x-amz-target header",
      });
    });

    describe("a handled target", () => {
      it("returns the output of a matched target", async () => {
        const route = vi.fn().mockResolvedValue({
          ok: true,
        });
        const router = (target: string) =>
          target === "valid" ? route : () => Promise.reject();
        const server = createServer(router, MockLogger as any, {});

        const response = await supertest(server.application)
          .post("/")
          .set("x-amz-target", "prefix.valid");

        expect(response.status).toEqual(200);
        expect(response.text).toEqual('{"ok":true}');
      });

      it("converts UnsupportedErrors from within a target route to a 500 error", async () => {
        const route = vi
          .fn()
          .mockRejectedValue(new UnsupportedError("integration test"));
        const router = (target: string) =>
          target === "valid" ? route : () => Promise.reject();
        const server = createServer(router, MockLogger as any, {});

        const response = await supertest(server.application)
          .post("/")
          .set("x-amz-target", "prefix.valid");

        expect(response.status).toEqual(500);
        expect(response.body).toEqual({
          __type: "CognitoLocal#Unsupported",
          message: "Cognito Local unsupported feature: integration test",
        });
      });

      it.each`
        error                                          | code                          | message
        ${new CognitoError("CognitoError", "message")} | ${"CognitoError"}             | ${"message"}
        ${new NotAuthorizedError()}                    | ${"NotAuthorizedException"}   | ${"User not authorized"}
        ${new UsernameExistsError()}                   | ${"UsernameExistsException"}  | ${"User already exists"}
        ${new CodeMismatchError()}                     | ${"CodeMismatchException"}    | ${"Incorrect confirmation code"}
        ${new InvalidPasswordError()}                  | ${"InvalidPasswordException"} | ${"Invalid password"}
      `(
        "it converts $code to the format Cognito SDK expects",
        async ({ error, code, message }) => {
          const route = vi.fn().mockRejectedValue(error);
          const router = (target: string) =>
            target === "valid" ? route : () => Promise.reject();
          const server = createServer(router, MockLogger as any, {});

          const response = await supertest(server.application)
            .post("/")
            .set("x-amz-target", "prefix.valid");

          expect(response.status).toEqual(400);
          expect(response.body).toEqual({
            __type: `${code}`,
            message,
          });
        },
      );
    });
  });

  describe("jwks endpoint", () => {
    it("responds with our public key", async () => {
      const server = createServer(vi.fn(), MockLogger as any, {});

      const response = await supertest(server.application).get(
        "/any-user-pool/.well-known/jwks.json",
      );

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        keys: [
          {
            alg: "RS256",
            e: "AQAB",
            kid: "CognitoLocal",
            kty: "RSA",
            n: "2uLO7yh1_6Icfd89V3nNTc_qhfpDN7vEmOYlmJQlc9_RmOns26lg88fXXFntZESwHOm7_homO2Ih6NOtu4P5eskGs8d8VQMOQfF4YrP-pawVz-gh1S7eSvzZRDHBT4ItUuoiVP1B9HN_uScKxIqjmitpPqEQB_o2NJv8npCfqUAU-4KmxquGtjdmfctswSZGdz59M3CAYKDfuvLH9_vV6TRGgbUaUAXWC2WJrbbEXzK3XUDBrmF3Xo-yw8f3SgD3JOPl3HaaWMKL1zGVAsge7gQaGiJBzBurg5vwN61uDGGz0QZC1JqcUTl3cZnrx_L8isIR7074SJEuljIZRnCcjQ",
            use: "sig",
          },
        ],
      });
    });
  });

  describe("OpenId Configuration Endpoint", () => {
    it("responds with open id configuration", async () => {
      const server = createServer(vi.fn(), MockLogger as any, {});

      const response = await supertest(server.application).get(
        "/any-user-pool/.well-known/openid-configuration",
      );
      expect(response.status).toEqual(200);
      expect(response.body).toMatchObject({
        id_token_signing_alg_values_supported: ["RS256"],
        issuer: expect.stringContaining("/any-user-pool"),
        jwks_uri: expect.stringContaining(
          "/any-user-pool/.well-known/jwks.json",
        ),
        authorization_endpoint: expect.stringContaining("/oauth2/authorize"),
        token_endpoint: expect.stringContaining("/oauth2/token"),
        userinfo_endpoint: expect.stringContaining("/oauth2/userInfo"),
        revocation_endpoint: expect.stringContaining("/oauth2/revoke"),
        end_session_endpoint: expect.stringContaining("/logout"),
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        scopes_supported: ["openid", "email", "phone", "profile"],
        code_challenge_methods_supported: ["S256"],
      });
    });
  });

  describe("/_/users", () => {
    const seedRouter = (existing: { Username: string }[] = []) => {
      const routes = {
        ListUsers: vi.fn().mockResolvedValue({ Users: existing }),
        AdminCreateUser: vi
          .fn()
          .mockResolvedValue({ User: { Username: "new-uuid" } }),
        AdminSetUserPassword: vi.fn().mockResolvedValue({}),
      };
      const router = (target: string) =>
        routes[target as keyof typeof routes] ?? (() => Promise.reject());
      return { router, routes };
    };
    const seed = {
      UserPoolId: "pool",
      Users: [{ Email: "a@example.com", Password: "pw" }],
    };

    it("creates each user with a verified email and a permanent password", async () => {
      const { router, routes } = seedRouter();
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application)
        .post("/_/users")
        .send(seed);

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        Users: [{ Email: "a@example.com", Username: "new-uuid" }],
      });
      expect(routes.AdminCreateUser).toHaveBeenCalledWith(expect.anything(), {
        UserPoolId: "pool",
        Username: "a@example.com",
        MessageAction: "SUPPRESS",
        UserAttributes: [
          { Name: "email", Value: "a@example.com" },
          { Name: "email_verified", Value: "true" },
        ],
      });
      expect(routes.AdminSetUserPassword).toHaveBeenCalledWith(
        expect.anything(),
        {
          UserPoolId: "pool",
          Username: "new-uuid",
          Password: "pw",
          Permanent: true,
        },
      );
    });

    it("keeps an existing user and only sets the password", async () => {
      const { router, routes } = seedRouter([{ Username: "old-uuid" }]);
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application)
        .post("/_/users")
        .send(seed);

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        Users: [{ Email: "a@example.com", Username: "old-uuid" }],
      });
      expect(routes.AdminCreateUser).not.toHaveBeenCalled();
      expect(routes.AdminSetUserPassword).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ Username: "old-uuid", Permanent: true }),
      );
    });

    it("rejects a malformed body", async () => {
      const { router } = seedRouter();
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application)
        .post("/_/users")
        .send({ UserPoolId: "pool", Users: [{ Email: "a@example.com" }] });

      expect(response.status).toEqual(400);
    });

    it("reports a Cognito error the way the API does", async () => {
      const { router, routes } = seedRouter();
      routes.AdminSetUserPassword.mockRejectedValue(new InvalidPasswordError());
      const server = createServer(router, MockLogger as any, {});

      const response = await supertest(server.application)
        .post("/_/users")
        .send(seed);

      expect(response.status).toEqual(400);
      expect(response.body).toEqual({
        __type: "InvalidPasswordException",
        message: "Invalid password",
      });
    });
  });
});
