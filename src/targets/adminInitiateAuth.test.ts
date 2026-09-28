import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  NotAuthorizedError,
  PasswordResetRequiredError,
  UserNotFoundError,
} from "../errors";
import type { CognitoService, Triggers, UserPoolService } from "../services";
import type { TokenGenerator } from "../services/tokenGenerator";
import {
  AdminInitiateAuth,
  type AdminInitiateAuthTarget,
} from "./adminInitiateAuth";

describe("AdminInitiateAuth target", () => {
  let adminInitiateAuth: AdminInitiateAuthTarget;

  let mockCognitoService: MockedObject<CognitoService>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    adminInitiateAuth = AdminInitiateAuth({
      triggers: mockTriggers,
      cognito: mockCognitoService,
      tokenGenerator: mockTokenGenerator,
    });
  });

  describe("when user status is FORCE_CHANGE_PASSWORD", () => {
    const user = TDB.user({ UserStatus: "FORCE_CHANGE_PASSWORD" });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("responds with a NEW_PASSWORD_REQUIRED challenge instead of tokens", async () => {
      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: { USERNAME: user.Username, PASSWORD: user.Password },
      });

      expect(response.ChallengeName).toEqual("NEW_PASSWORD_REQUIRED");
      expect(response.Session).toEqual(expect.any(String));
      expect(response.AuthenticationResult).toBeUndefined();
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("rejects a wrong temporary password", async () => {
      await expect(
        adminInitiateAuth(TestContext, {
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          AuthParameters: { USERNAME: user.Username, PASSWORD: "bad" },
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });
  });

  it("throws PasswordResetRequiredException for a RESET_REQUIRED user", async () => {
    const user = TDB.user({ UserStatus: "RESET_REQUIRED" });
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: { USERNAME: user.Username, PASSWORD: user.Password },
      }),
    ).rejects.toBeInstanceOf(PasswordResetRequiredError);
  });

  it("create tokens with username, password and admin user password auth flow", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
    });

    const existingUser = TDB.user();

    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        USERNAME: existingUser.Username,
        PASSWORD: existingUser.Password,
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockUserPoolService.storeRefreshToken).toHaveBeenCalledWith(
      TestContext,
      response.AuthenticationResult?.RefreshToken,
      existingUser,
    );

    expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    expect(response.AuthenticationResult?.IdToken).toEqual("id");
    expect(response.AuthenticationResult?.RefreshToken).toEqual("refresh");

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "Authentication",
    );
  });

  describe("MFA enforcement", () => {
    it("returns SMS_MFA challenge when MfaConfiguration is ON and user has SMS MFA", async () => {
      const existingUser = TDB.user({
        MFAOptions: [{ DeliveryMedium: "SMS", AttributeName: "phone_number" }],
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SMS_MFA");
      expect(response.ChallengeParameters).toEqual({
        USER_ID_FOR_SRP: existingUser.Username,
      });
      expect(response.AuthenticationResult).toBeUndefined();
      expect(mockTokenGenerator.generate).not.toHaveBeenCalled();
    });

    it("returns SOFTWARE_TOKEN_MFA challenge when MfaConfiguration is ON and user prefers TOTP", async () => {
      const existingUser = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("throws NotAuthorizedError when MfaConfiguration is ON but user has no MFA configured", async () => {
      const existingUser = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "ON";

      await expect(
        adminInitiateAuth(TestContext, {
          AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          AuthParameters: {
            USERNAME: existingUser.Username,
            PASSWORD: existingUser.Password,
          },
        }),
      ).rejects.toThrow("User not authorized");
    });

    it("returns MFA challenge when MfaConfiguration is OPTIONAL and user has MFA", async () => {
      const existingUser = TDB.user({
        UserMFASettingList: ["SOFTWARE_TOKEN_MFA"],
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
      });
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.options.MfaConfiguration = "OPTIONAL";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.ChallengeName).toEqual("SOFTWARE_TOKEN_MFA");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("issues tokens directly when MfaConfiguration is OPTIONAL and user has no MFA", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
        ExpiresIn: 3600,
      });
      const existingUser = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockUserPoolService.options.MfaConfiguration = "OPTIONAL";

      const response = await adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: {
          USERNAME: existingUser.Username,
          PASSWORD: existingUser.Password,
        },
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    });
  });

  it("throws UserNotFoundException for an unknown username", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: { USERNAME: "nobody", PASSWORD: "password" },
      }),
    ).rejects.toEqual(new UserNotFoundError("User does not exist."));
  });

  it("throws NotAuthorizedException on a wrong password", async () => {
    const user = TDB.user();
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await expect(
      adminInitiateAuth(TestContext, {
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        ClientId: userPoolClient.ClientId,
        UserPoolId: userPoolClient.UserPoolId,
        AuthParameters: { USERNAME: user.Username, PASSWORD: "bad-password" },
      }),
    ).rejects.toEqual(
      new NotAuthorizedError("Incorrect username or password."),
    );
  });

  it.each(["ADMIN_USER_PASSWORD_AUTH", "REFRESH_TOKEN_AUTH"])(
    "throws if the user is disabled (%s)",
    async (authFlow) => {
      const user = TDB.user({ Enabled: false });
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.getUserByRefreshToken.mockResolvedValue(user);

      await expect(
        adminInitiateAuth(TestContext, {
          AuthFlow: authFlow,
          ClientId: userPoolClient.ClientId,
          UserPoolId: userPoolClient.UserPoolId,
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: user.Password,
            REFRESH_TOKEN: "refresh token",
          },
        }),
      ).rejects.toEqual(new NotAuthorizedError("User is disabled."));
    },
  );

  it("supports REFRESH_TOKEN_AUTH", async () => {
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
      ExpiresIn: 3600,
    });

    const existingUser = TDB.user({
      RefreshTokens: ["refresh token"],
    });

    mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

    const response = await adminInitiateAuth(TestContext, {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: userPoolClient.ClientId,
      UserPoolId: userPoolClient.UserPoolId,
      AuthParameters: {
        REFRESH_TOKEN: "refresh token",
      },
      ClientMetadata: {
        client: "metadata",
      },
    });

    expect(mockUserPoolService.getUserByRefreshToken).toHaveBeenCalledWith(
      TestContext,
      "refresh token",
    );
    expect(mockUserPoolService.storeRefreshToken).not.toHaveBeenCalled();

    expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    expect(response.AuthenticationResult?.IdToken).toEqual("id");

    // does not return a refresh token as part of a refresh token flow
    expect(response.AuthenticationResult?.RefreshToken).not.toBeDefined();

    expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
      TestContext,
      existingUser,
      [],
      userPoolClient,
      {
        client: "metadata",
      },
      "RefreshTokens",
    );
  });
});
