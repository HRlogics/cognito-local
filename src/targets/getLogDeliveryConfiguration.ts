import type { LogDeliveryConfigurationType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Services } from "../services";
import type { Target } from "./Target";

interface GetLogDeliveryConfigurationRequest {
  UserPoolId: string;
}
interface GetLogDeliveryConfigurationResponse {
  LogDeliveryConfiguration?: LogDeliveryConfigurationType;
}

export type GetLogDeliveryConfigurationTarget = Target<
  GetLogDeliveryConfigurationRequest,
  GetLogDeliveryConfigurationResponse
>;

export const GetLogDeliveryConfiguration =
  ({ cognito }: Pick<Services, "cognito">): GetLogDeliveryConfigurationTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const config = userPool.options._logDeliveryConfiguration ?? {
      UserPoolId: req.UserPoolId,
      LogConfigurations: [],
    };

    return { LogDeliveryConfiguration: config };
  };
