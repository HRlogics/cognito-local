import type {
  CreateResourceServerRequest,
  CreateResourceServerResponse,
  ResourceServerType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type CreateResourceServerTarget = Target<
  CreateResourceServerRequest,
  CreateResourceServerResponse
>;

type CreateResourceServerServices = Pick<Services, "cognito">;

export const CreateResourceServer =
  ({ cognito }: CreateResourceServerServices): CreateResourceServerTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    const server: ResourceServerType = {
      UserPoolId: req.UserPoolId,
      Identifier: req.Identifier,
      Name: req.Name,
      Scopes: req.Scopes,
    };

    const servers: ResourceServerType[] =
      userPool.options._resourceServers ?? [];
    servers.push(server);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _resourceServers: servers,
    });

    return {
      ResourceServer: server,
    };
  };
