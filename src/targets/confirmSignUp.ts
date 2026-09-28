import type {
  ConfirmSignUpRequest,
  ConfirmSignUpResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  AliasExistsError,
  CodeMismatchError,
  ExpiredCodeError,
  INVALID_VERIFICATION_CODE,
  NotAuthorizedError,
} from "../errors";
import type { Services } from "../services";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import {
  attribute,
  attributesAppend,
  attributeValue,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type ConfirmSignUpTarget = Target<
  ConfirmSignUpRequest,
  ConfirmSignUpResponse
>;

export const ConfirmSignUp =
  ({
    cognito,
    clock,
    triggers,
  }: Pick<Services, "cognito" | "clock" | "triggers">): ConfirmSignUpTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new NotAuthorizedError();
    }

    if (!user.ConfirmationCode) {
      throw new ExpiredCodeError();
    }

    if (user.ConfirmationCode !== req.ConfirmationCode) {
      throw new CodeMismatchError(INVALID_VERIFICATION_CODE);
    }

    // the code went to this attribute (same choice as SignUp), so confirming proves it
    const verifiedBy = selectAppropriateDeliveryMethod(
      userPool.options.AutoVerifiedAttributes ?? [],
      user,
    );

    const updatedUser = {
      ...user,
      Attributes: verifiedBy
        ? attributesAppend(
            user.Attributes,
            attribute(`${verifiedBy.AttributeName}_verified`, "true"),
          )
        : user.Attributes,
      UserStatus: "CONFIRMED",
      ConfirmationCode: undefined,
      UserLastModifiedDate: clock.get(),
    };

    // Handle alias attributes (email, phone_number, preferred_username)
    if (userPool.options.AliasAttributes?.length) {
      const allUsers = await userPool.listUsers(ctx);
      for (const aliasAttr of userPool.options.AliasAttributes) {
        const aliasValue = attributeValue(aliasAttr, updatedUser.Attributes);
        if (!aliasValue) continue;

        const conflictingUser = allUsers.find(
          (u) =>
            u.Username !== updatedUser.Username &&
            attributeValue(aliasAttr, u.Attributes) === aliasValue,
        );
        if (conflictingUser) {
          if (!req.ForceAliasCreation) {
            throw new AliasExistsError();
          }
          // Remove the conflicting attribute from the other user
          await userPool.saveUser(ctx, {
            ...conflictingUser,
            Attributes: conflictingUser.Attributes.filter(
              (a) => a.Name !== aliasAttr,
            ),
            UserLastModifiedDate: clock.get(),
          });
        }
      }
    }

    await userPool.saveUser(ctx, updatedUser);

    if (triggers.enabled("PostConfirmation")) {
      await triggers.postConfirmation(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostConfirmation_ConfirmSignUp",
        username: updatedUser.Username,
        userPoolId: userPool.options.Id,

        // not sure whether this is a one off for PostConfirmation, or whether we should be adding cognito:user_status
        // into every place we send attributes to lambdas
        userAttributes: attributesAppend(
          updatedUser.Attributes,
          attribute("cognito:user_status", updatedUser.UserStatus),
        ),
      });
    }

    return {};
  };
