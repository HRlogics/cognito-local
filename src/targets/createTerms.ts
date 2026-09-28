import * as uuid from "uuid";
import type { Services } from "../services";
import type { Terms } from "../services/userPoolService";
import type { Target } from "./Target";

interface CreateTermsRequest {
  UserPoolId: string;
  TermsText?: string;
  Version?: string;
}
interface CreateTermsResponse {
  Terms?: Terms;
}

export type CreateTermsTarget = Target<CreateTermsRequest, CreateTermsResponse>;

export const CreateTerms =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): CreateTermsTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const now = clock.get();

    const terms = {
      TermsId: uuid.v4(),
      UserPoolId: req.UserPoolId,
      TermsText: req.TermsText,
      Version: req.Version,
      CreationDate: now,
      LastModifiedDate: now,
    };

    const existing = userPool.options._terms ?? [];
    existing.push(terms);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _terms: existing,
    });

    return { Terms: terms };
  };
