import { randomUUID } from "node:crypto";
import type {
  DeliveryMediumType,
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { Services } from "../services";
import * as srp from "../services/srp";
import { verify as verifyTotp } from "../services/totp";
import {
  attributesToRecord,
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";
import { assertCanSignIn } from "./challenges";
import type { Target } from "./Target";

export type RespondToAuthChallengeTarget = Target<
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse
>;

type RespondToAuthChallengeService = Pick<
  Services,
  "clock" | "cognito" | "messages" | "otp" | "triggers" | "tokenGenerator"
>;

const sendSmsMfaChallenge = async (
  ctx: Parameters<RespondToAuthChallengeTarget>[0],
  req: RespondToAuthChallengeRequest,
  user: User,
  userPoolId: string,
  services: RespondToAuthChallengeService,
  saveUser: (u: User) => Promise<void>,
): Promise<RespondToAuthChallengeResponse> => {
  const smsMfaOption = user.MFAOptions?.find(
    (x): x is MFAOption & { DeliveryMedium: DeliveryMediumType } =>
      x.DeliveryMedium === "SMS",
  );
  if (!smsMfaOption) {
    throw new UnsupportedError("SMS_MFA without SMS MFAOption");
  }
  const deliveryDestination = attributeValue(
    smsMfaOption.AttributeName,
    user.Attributes,
  );
  if (!deliveryDestination) {
    throw new UnsupportedError(`SMS_MFA without ${smsMfaOption.AttributeName}`);
  }

  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    req.ClientId,
    userPoolId,
    user,
    code,
    req.ClientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await saveUser({ ...user, MFACode: code });

  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: deliveryDestination,
      USER_ID_FOR_SRP: user.Username,
    },
    Session: randomUUID(),
  };
};

export const RespondToAuthChallenge =
  (services: RespondToAuthChallengeService): RespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const { clock, cognito, triggers, tokenGenerator } = services;

    if (!req.ChallengeResponses) {
      throw new InvalidParameterError(
        "Missing required parameter challenge responses",
      );
    }
    if (!req.ChallengeResponses.USERNAME) {
      throw new InvalidParameterError("Missing required parameter USERNAME");
    }
    // PASSWORD_VERIFIER carries its state in SECRET_BLOCK, SRP clients send no Session
    if (!req.Session && req.ChallengeName !== "PASSWORD_VERIFIER") {
      throw new InvalidParameterError("Missing required parameter Session");
    }

    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const userPoolClient = await cognito.getAppClient(ctx, req.ClientId);

    const user = await userPool.getUserByUsername(
      ctx,
      req.ChallengeResponses.USERNAME,
    );
    if (!user || !userPoolClient) {
      throw new NotAuthorizedError();
    }
    if (!user.Enabled) {
      throw new NotAuthorizedError("User is disabled.");
    }

    if (req.ChallengeName === "SELECT_MFA_TYPE") {
      const answer = req.ChallengeResponses.ANSWER;
      if (answer === "SMS_MFA") {
        return sendSmsMfaChallenge(
          ctx,
          req,
          user,
          userPool.options.Id,
          services,
          (u) => userPool.saveUser(ctx, u),
        );
      }
      if (answer === "SOFTWARE_TOKEN_MFA") {
        return {
          ChallengeName: "SOFTWARE_TOKEN_MFA",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            ...(user.SoftwareTokenMfaConfiguration?.FriendlyDeviceName
              ? {
                  FRIENDLY_DEVICE_NAME:
                    user.SoftwareTokenMfaConfiguration.FriendlyDeviceName,
                }
              : {}),
          },
          Session: randomUUID(),
        };
      }
      throw new InvalidParameterError(
        "SELECT_MFA_TYPE requires ANSWER of SMS_MFA or SOFTWARE_TOKEN_MFA",
      );
    }

    if (req.ChallengeName === "SMS_MFA") {
      if (user.MFACode !== req.ChallengeResponses.SMS_MFA_CODE) {
        throw new CodeMismatchError();
      }

      await userPool.saveUser(ctx, {
        ...user,
        MFACode: undefined,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      const code = req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE;
      const secret = user.SoftwareTokenMfaConfiguration?.Secret;
      if (
        !code ||
        !secret ||
        !user.SoftwareTokenMfaConfiguration?.Verified ||
        !verifyTotp(secret, code)
      ) {
        throw new CodeMismatchError();
      }
      await userPool.saveUser(ctx, {
        ...user,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      if (!req.ChallengeResponses.NEW_PASSWORD) {
        throw new InvalidParameterError(
          "Missing required parameter NEW_PASSWORD",
        );
      }

      // TODO: validate the password?
      await userPool.saveUser(ctx, {
        ...user,
        Password: req.ChallengeResponses.NEW_PASSWORD,
        UserLastModifiedDate: clock.get(),
        UserStatus: "CONFIRMED",
      });
    } else if (req.ChallengeName === "PASSWORD_VERIFIER") {
      const secretBlock = req.ChallengeResponses.PASSWORD_CLAIM_SECRET_BLOCK;
      if (!secretBlock) {
        throw new InvalidParameterError(
          "Missing required parameter PASSWORD_CLAIM_SECRET_BLOCK",
        );
      }
      if (!req.ChallengeResponses.TIMESTAMP) {
        throw new InvalidParameterError("Missing required parameter TIMESTAMP");
      }
      if (!req.ChallengeResponses.PASSWORD_CLAIM_SIGNATURE) {
        throw new InvalidParameterError(
          "Missing required parameter PASSWORD_CLAIM_SIGNATURE",
        );
      }

      if (
        !srp.verifyPasswordClaim(
          userPool.options.Id,
          user,
          secretBlock,
          req.ChallengeResponses.TIMESTAMP,
          req.ChallengeResponses.PASSWORD_CLAIM_SIGNATURE,
        )
      ) {
        throw new NotAuthorizedError("Incorrect username or password.");
      }
      // the block may predate a status change (e.g. AdminResetUserPassword)
      assertCanSignIn(user);

      // Check if MFA is required
      if (
        (userPool.options.MfaConfiguration === "OPTIONAL" &&
          ((user.MFAOptions ?? []).length > 0 ||
            (user.UserMFASettingList ?? []).length > 0)) ||
        userPool.options.MfaConfiguration === "ON"
      ) {
        return {
          ChallengeName:
            user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA"
              ? "SOFTWARE_TOKEN_MFA"
              : "SMS_MFA",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
          } as RespondToAuthChallengeResponse["ChallengeParameters"],
          Session: randomUUID(),
        };
      }

      if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
        return {
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            requiredAttributes: JSON.stringify([]),
            // amazon-cognito-identity-js JSON.parses userAttributes, so it must be present
            userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
          } as RespondToAuthChallengeResponse["ChallengeParameters"],
          Session: randomUUID(),
        };
      }
    } else if (req.ChallengeName === "MFA_SETUP") {
      // MFA_SETUP is returned when a user needs to set up TOTP MFA
      // The client calls AssociateSoftwareToken + VerifySoftwareToken
      // then responds to MFA_SETUP. For the emulator, just mark setup complete.
      if (!req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE) {
        throw new InvalidParameterError(
          "Missing required parameter SOFTWARE_TOKEN_MFA_CODE",
        );
      }

      const mfaSettingList = user.UserMFASettingList ?? [];
      if (!mfaSettingList.includes("SOFTWARE_TOKEN_MFA")) {
        mfaSettingList.push("SOFTWARE_TOKEN_MFA");
      }

      await userPool.saveUser(ctx, {
        ...user,
        UserMFASettingList: mfaSettingList,
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "CUSTOM_CHALLENGE") {
      if (!triggers.enabled("VerifyAuthChallengeResponse")) {
        throw new UnsupportedError(
          "CUSTOM_CHALLENGE requires VerifyAuthChallengeResponse trigger",
        );
      }

      const verifyResult = await triggers.verifyAuthChallengeResponse(ctx, {
        clientId: req.ClientId,
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
        challengeAnswer: req.ChallengeResponses.ANSWER ?? "",
        clientMetadata: req.ClientMetadata,
      });

      if (!verifyResult.answerCorrect) {
        throw new CodeMismatchError();
      }
    } else {
      throw new UnsupportedError(
        `respondToAuthChallenge with ChallengeName=${req.ChallengeName}`,
      );
    }

    if (triggers.enabled("PostAuthentication")) {
      await triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
      });
    }

    // the branches above may have saved the user (new password, MFA settings), and
    // storeRefreshToken writes back the object it gets, so use the stored copy
    const latestUser =
      (await userPool.getUserByUsername(ctx, user.Username)) ?? user;
    const userGroups = await userPool.listUserGroupMembership(ctx, latestUser);
    const tokens = await tokenGenerator.generate(
      ctx,
      latestUser,
      userGroups,
      userPoolClient,
      req.ClientMetadata,
      "Authentication",
    );
    await userPool.storeRefreshToken(ctx, tokens.RefreshToken, latestUser);

    return {
      ChallengeParameters: {},
      AuthenticationResult: tokens,
    };
  };
