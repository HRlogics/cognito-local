import type { Services } from "../services";
import { paginate } from "../services/pagination";
import type { Terms } from "../services/userPoolService";
import type { Target } from "./Target";

interface ListTermsRequest {
  UserPoolId: string;
  NextToken?: string;
  MaxResults?: number;
}
interface ListTermsResponse {
  Terms?: Terms[];
  NextToken?: string;
}

export type ListTermsTarget = Target<ListTermsRequest, ListTermsResponse>;

export const ListTerms =
  ({ cognito }: Pick<Services, "cognito">): ListTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = userPool.options._terms ?? [];

    const { items: page, nextToken } = paginate(
      items,
      req.MaxResults,
      req.NextToken,
    );

    return {
      Terms: page,
      NextToken: nextToken,
    };
  };
