import type {
  AdminCreateUserRequest,
  AdminCreateUserResponse,
  DeliveryMediumListType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { createTranslator } from "short-uuid";
import * as uuid from "uuid";
import { InvalidParameterError, UsernameExistsError } from "../errors";
import type { Messages, Services, UserPoolService } from "../services";
import type { Context } from "../services/context";
import type { DeliveryDetails } from "../services/messageDelivery/messageDelivery";
import {
  attributesInclude,
  attributesToRecord,
  attributeValue,
  type User,
  validateEmailAttribute,
  validatePhoneNumberAttribute,
} from "../services/userPoolService";
import { userToResponseObject } from "./responses";
import type { Target } from "./Target";

const generator = createTranslator(
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!",
);

export type AdminCreateUserTarget = Target<
  AdminCreateUserRequest,
  AdminCreateUserResponse
>;

type AdminCreateUserServices = Pick<
  Services,
  "clock" | "cognito" | "messages" | "config" | "triggers"
>;

const selectAppropriateDeliveryMethod = (
  desiredDeliveryMediums: DeliveryMediumListType,
  user: User,
): DeliveryDetails | null => {
  if (desiredDeliveryMediums.includes("SMS")) {
    const phoneNumber = attributeValue("phone_number", user.Attributes);
    if (phoneNumber) {
      return {
        AttributeName: "phone_number",
        DeliveryMedium: "SMS",
        Destination: phoneNumber,
      };
    }
  }

  if (desiredDeliveryMediums.includes("EMAIL")) {
    const email = attributeValue("email", user.Attributes);
    if (email) {
      return {
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
        Destination: email,
      };
    }
  }

  return null;
};

const deliverWelcomeMessage = async (
  ctx: Context,
  req: AdminCreateUserRequest,
  temporaryPassword: string,
  user: User,
  messages: Messages,
  userPool: UserPoolService,
) => {
  const deliveryDetails = selectAppropriateDeliveryMethod(
    req.DesiredDeliveryMediums ?? ["SMS"],
    user,
  );
  if (!deliveryDetails) {
    // TODO: I don't know what the real error message should be for this
    throw new InvalidParameterError(
      "User has no attribute matching desired delivery mediums",
    );
  }

  await messages.deliver(
    ctx,
    "AdminCreateUser",
    null,
    userPool.options.Id,
    user,
    temporaryPassword,
    req.ClientMetadata,
    deliveryDetails,
  );
};

export const AdminCreateUser =
  ({
    clock,
    cognito,
    messages,
    triggers,
  }: AdminCreateUserServices): AdminCreateUserTarget =>
  async (ctx, req) => {
    validatePhoneNumberAttribute(req.UserAttributes);
    validateEmailAttribute(req.UserAttributes);

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const existingUser = await userPool.getUserByUsername(ctx, req.Username);
    const supressWelcomeMessage = req.MessageAction === "SUPPRESS";

    if (existingUser && req.MessageAction === "RESEND") {
      const temporaryPassword =
        req.TemporaryPassword ??
        process.env.CODE ??
        generator.generate().slice(0, 6);

      const updatedUser = {
        ...existingUser,
        Password: temporaryPassword,
        UserLastModifiedDate: clock.get(),
      };
      await userPool.saveUser(ctx, updatedUser);

      await deliverWelcomeMessage(
        ctx,
        req,
        temporaryPassword,
        updatedUser,
        messages,
        userPool,
      );

      return {
        User: userToResponseObject(updatedUser),
      };
    } else if (existingUser) {
      throw new UsernameExistsError();
    }

    const sub = uuid.v4();
    const attributes = attributesInclude("sub", req.UserAttributes)
      ? (req.UserAttributes ?? [])
      : [{ Name: "sub", Value: sub }, ...(req.UserAttributes ?? [])];

    const now = clock.get();

    const temporaryPassword =
      req.TemporaryPassword ??
      process.env.CODE ??
      generator.generate().slice(0, 6);

    let username = req.Username;
    if (userPool.options.UsernameAttributes?.includes("email")) {
      // user pool is configured to use the email attribute as the user's username
      if (!req.Username.includes("@")) {
        // naive validation that the username is an email
        throw new InvalidParameterError("Username should be an email.");
      }

      if (!attributesInclude("email", attributes)) {
        attributes.push({ Name: "email", Value: req.Username });
      }

      // when the username is an email address, cognito uses the sub as the username in
      // requests/responses, triggers etc...
      username = sub;
    }

    if (triggers.enabled("PreSignUp")) {
      // runs for validation only: Cognito ignores autoConfirmUser, autoVerifyEmail and
      // autoVerifyPhone for AdminCreateUser, so the attributes stay as the admin sent them
      await triggers.preSignUp(ctx, {
        clientId: "CLIENT_ID_NOT_APPLICABLE",
        clientMetadata: req.ClientMetadata,
        source: "PreSignUp_AdminCreateUser",
        userAttributes: [...attributes],
        username,
        userPoolId: userPool.options.Id,
        validationData: req.ValidationData
          ? attributesToRecord(req.ValidationData)
          : undefined,
      });
    }

    const user: User = {
      Username: username,
      Password: temporaryPassword,
      Attributes: attributes.sort((a, b) => a.Name.localeCompare(b.Name)),
      Enabled: true,
      UserStatus: "FORCE_CHANGE_PASSWORD",
      ConfirmationCode: undefined,
      UserCreateDate: now,
      UserLastModifiedDate: now,
      RefreshTokens: [],
    };
    await userPool.saveUser(ctx, user);

    // TODO: should throw InvalidParameterException when a non-email is supplied as the Username when the pool has email as a UsernameAttribute
    // TODO: support MessageAction=="RESEND"
    // TODO: should generate a TemporaryPassword if one isn't set
    // TODO: support ForceAliasCreation

    if (!supressWelcomeMessage) {
      await deliverWelcomeMessage(
        ctx,
        req,
        temporaryPassword,
        user,
        messages,
        userPool,
      );
    }

    return {
      User: userToResponseObject(user),
    };
  };
