import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Terms } from "../services/userPoolService";
import type { Target } from "./Target";

interface UpdateTermsRequest {
  UserPoolId: string;
  TermsId: string;
  TermsText?: string;
}
interface UpdateTermsResponse {
  Terms?: Terms;
}

export type UpdateTermsTarget = Target<UpdateTermsRequest, UpdateTermsResponse>;

export const UpdateTerms =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): UpdateTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = userPool.options._terms ?? [];
    const idx = items.findIndex((t) => t.TermsId === req.TermsId);
    if (idx < 0) {
      throw new ResourceNotFoundError("Terms not found");
    }

    items[idx] = {
      ...items[idx],
      TermsText: req.TermsText ?? items[idx].TermsText,
      LastModifiedDate: clock.get(),
    };

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _terms: items,
    });

    return { Terms: items[idx] };
  };
