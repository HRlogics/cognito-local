import type {
  CreateUserPoolClientRequest,
  CreateUserPoolClientResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { type AppClient, newId } from "../services/appClient";
import { appClientToResponseObject } from "./responses";
import type { Target } from "./Target";

export type CreateUserPoolClientTarget = Target<
  CreateUserPoolClientRequest,
  CreateUserPoolClientResponse
>;

type CreateUserPoolClientServices = Pick<Services, "clock" | "cognito">;

export const CreateUserPoolClient =
  ({
    clock,
    cognito,
  }: CreateUserPoolClientServices): CreateUserPoolClientTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    const pinned = userPool.options._pinnedClientId;
    const clientId =
      pinned === "use-name" ? req.ClientName : (pinned ?? newId());
    if (pinned) {
      // a client left behind by a deleted pool may be replaced, a live one may not
      const existing = await cognito.getAppClient(ctx, clientId);
      const pools = existing ? await cognito.listUserPools(ctx) : [];
      if (pools.some((p) => p.Id === existing?.UserPoolId)) {
        throw new InvalidParameterError(
          `App Client ${clientId} already exists`,
        );
      }
    }

    const appClient: AppClient = {
      AccessTokenValidity: req.AccessTokenValidity,
      AllowedOAuthFlows: req.AllowedOAuthFlows,
      AllowedOAuthFlowsUserPoolClient: req.AllowedOAuthFlowsUserPoolClient,
      AllowedOAuthScopes: req.AllowedOAuthScopes,
      AnalyticsConfiguration: req.AnalyticsConfiguration,
      CallbackURLs: req.CallbackURLs,
      ClientId: clientId,
      ClientName: req.ClientName,
      ClientSecret: req.GenerateSecret ? newId() : undefined,
      CreationDate: clock.get(),
      DefaultRedirectURI: req.DefaultRedirectURI,
      EnableTokenRevocation: req.EnableTokenRevocation,
      ExplicitAuthFlows: req.ExplicitAuthFlows,
      IdTokenValidity: req.IdTokenValidity,
      LastModifiedDate: clock.get(),
      LogoutURLs: req.LogoutURLs,
      PreventUserExistenceErrors: req.PreventUserExistenceErrors,
      ReadAttributes: req.ReadAttributes,
      RefreshTokenValidity: req.RefreshTokenValidity,
      SupportedIdentityProviders: req.SupportedIdentityProviders,
      TokenValidityUnits: {
        AccessToken: req.TokenValidityUnits?.AccessToken ?? "hours",
        IdToken: req.TokenValidityUnits?.IdToken ?? "minutes",
        RefreshToken: req.TokenValidityUnits?.RefreshToken ?? "days",
      },
      UserPoolId: req.UserPoolId,
      WriteAttributes: req.WriteAttributes,
    };

    await userPool.saveAppClient(ctx, appClient);

    return {
      UserPoolClient: appClientToResponseObject(appClient),
    };
  };
