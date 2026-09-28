import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

interface DeleteTermsRequest {
  UserPoolId: string;
  TermsId: string;
}
type DeleteTermsResponse = Record<string, never>;

export type DeleteTermsTarget = Target<DeleteTermsRequest, DeleteTermsResponse>;

export const DeleteTerms =
  ({ cognito }: Pick<Services, "cognito">): DeleteTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = userPool.options._terms ?? [];
    const idx = items.findIndex((t) => t.TermsId === req.TermsId);
    if (idx < 0) {
      throw new ResourceNotFoundError("Terms not found");
    }

    items.splice(idx, 1);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _terms: items,
    });

    return {};
  };
