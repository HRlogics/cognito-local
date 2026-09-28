import type {
  CreateIdentityProviderRequest,
  CreateIdentityProviderResponse,
  IdentityProviderType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type CreateIdentityProviderTarget = Target<
  CreateIdentityProviderRequest,
  CreateIdentityProviderResponse
>;

type CreateIdentityProviderServices = Pick<Services, "cognito" | "clock">;

export const CreateIdentityProvider =
  ({
    cognito,
    clock,
  }: CreateIdentityProviderServices): CreateIdentityProviderTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const now = clock.get();

    const provider: IdentityProviderType = {
      UserPoolId: req.UserPoolId,
      ProviderName: req.ProviderName,
      ProviderType: req.ProviderType,
      ProviderDetails: req.ProviderDetails,
      AttributeMapping: req.AttributeMapping,
      IdpIdentifiers: req.IdpIdentifiers,
      CreationDate: now,
      LastModifiedDate: now,
    };

    const providers: IdentityProviderType[] =
      userPool.options._identityProviders ?? [];
    providers.push(provider);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _identityProviders: providers,
    });

    return {
      IdentityProvider: provider,
    };
  };
