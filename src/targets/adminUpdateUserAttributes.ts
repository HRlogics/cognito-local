import type {
  AdminUpdateUserAttributesRequest,
  AdminUpdateUserAttributesResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  AliasExistsError,
  InvalidParameterError,
  NotAuthorizedError,
} from "../errors";
import type { Messages, Services, UserPoolService } from "../services";
import { USER_POOL_AWS_DEFAULTS } from "../services/cognitoService";
import type { Context } from "../services/context";
import { selectAppropriateDeliveryMethod } from "../services/messageDelivery/deliveryMethod";
import {
  attributesAppend,
  attributesIncludeMatch,
  attributeValue,
  hasUnverifiedContactAttributes,
  splitImmediateAndDelayedAttributes,
  type User,
  validateEmailAttribute,
  validatePermittedAttributeChanges,
  validatePhoneNumberAttribute,
} from "../services/userPoolService";
import type { Target } from "./Target";

const sendAttributeVerificationCode = async (
  ctx: Context,
  userPool: UserPoolService,
  user: User,
  messages: Messages,
  req: AdminUpdateUserAttributesRequest,
  code: string,
) => {
  const deliveryDetails = selectAppropriateDeliveryMethod(
    userPool.options.AutoVerifiedAttributes ?? [],
    user,
  );
  if (!deliveryDetails) {
    // TODO: I don't know what the real error message should be for this
    throw new InvalidParameterError(
      "User has no attribute matching desired auto verified attributes",
    );
  }

  await messages.deliver(
    ctx,
    "UpdateUserAttribute",
    null,
    userPool.options.Id,
    user,
    code,
    req.ClientMetadata,
    deliveryDetails,
  );
};

export type AdminUpdateUserAttributesTarget = Target<
  AdminUpdateUserAttributesRequest,
  AdminUpdateUserAttributesResponse
>;

type AdminUpdateUserAttributesServices = Pick<
  Services,
  "clock" | "cognito" | "otp" | "messages"
>;

export const AdminUpdateUserAttributes =
  ({
    clock,
    cognito,
    otp,
    messages,
  }: AdminUpdateUserAttributesServices): AdminUpdateUserAttributesTarget =>
  async (ctx, req) => {
    validatePhoneNumberAttribute(req.UserAttributes);
    validateEmailAttribute(req.UserAttributes);

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(ctx, req.Username);
    if (!user) {
      throw new NotAuthorizedError();
    }

    const permittedAttributeChanges = validatePermittedAttributeChanges(
      req.UserAttributes,
      // if the user pool doesn't have any SchemaAttributes it was probably created manually
      // or before we started explicitly saving the defaults. Fallback on the AWS defaults in
      // this case, otherwise checks against the schema for default attributes like email will
      // fail.
      userPool.options.SchemaAttributes ??
        USER_POOL_AWS_DEFAULTS.SchemaAttributes ??
        [],
    );

    // email / phone_number double as sign-in names, so another user must not hold the new value
    const signInAttributes = [
      ...(userPool.options.UsernameAttributes ?? []),
      ...(userPool.options.AliasAttributes ?? []),
    ];
    const signInChanges = permittedAttributeChanges.filter(
      (attr) => attr.Value && signInAttributes.includes(attr.Name),
    );
    if (signInChanges.length) {
      const users = await userPool.listUsers(ctx);
      const taken = signInChanges.some((attr) =>
        users.some(
          (other) =>
            other.Username !== user.Username &&
            attributesIncludeMatch(
              attr.Name,
              attr.Value as string,
              other.Attributes,
            ),
        ),
      );
      if (taken) {
        throw new AliasExistsError();
      }
    }

    // An admin can skip verification by sending the contact with its *_verified flag set to
    // true, and a blank value deletes the attribute; neither waits for a verification code.
    const requireVerification = (
      userPool.options.UserAttributeUpdateSettings
        ?.AttributesRequireVerificationBeforeUpdate ?? []
    ).filter(
      (name) =>
        attributeValue(`${name}_verified`, permittedAttributeChanges) !==
          "true" && attributeValue(name, permittedAttributeChanges) !== "",
    );
    // deleting a contact deletes its *_verified flag too, instead of marking it unverified
    const deletedContactFlags = ["email", "phone_number"]
      .filter((name) => attributeValue(name, permittedAttributeChanges) === "")
      .map((name) => ({ Name: `${name}_verified`, Value: "" }));
    const [immediateAttributes, delayedAttributes] =
      splitImmediateAndDelayedAttributes(
        [...permittedAttributeChanges, ...deletedContactFlags],
        requireVerification,
      );

    // keep pending changes this request doesn't touch
    const touched = new Set(
      permittedAttributeChanges.flatMap((attr) => [
        attr.Name,
        `${attr.Name}_verified`,
      ]),
    );
    const pending = [
      ...(user.UnverifiedAttributeChanges ?? []).filter(
        (attr) => !touched.has(attr.Name),
      ),
      ...delayedAttributes,
    ];

    const updatedUser: User = {
      ...user,
      Attributes: attributesAppend(user.Attributes, ...immediateAttributes),
      UserLastModifiedDate: clock.get(),
      UnverifiedAttributeChanges: pending.length > 0 ? pending : undefined,
    };

    await userPool.saveUser(ctx, updatedUser);

    // deliberately only check the affected user attributes, not the combined attributes
    // e.g. a user with email_verified=false that you don't touch the email attributes won't get notified
    if (
      userPool.options.AutoVerifiedAttributes?.length &&
      (hasUnverifiedContactAttributes(immediateAttributes) ||
        hasUnverifiedContactAttributes(delayedAttributes))
    ) {
      const code = otp();

      await userPool.saveUser(ctx, {
        ...updatedUser,
        AttributeVerificationCode: code,
      });

      await sendAttributeVerificationCode(
        ctx,
        userPool,
        updatedUser,
        messages,
        req,
        code,
      );
    }

    return {};
  };
