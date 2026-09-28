import { ResourceNotFoundError } from "../errors";
import type { Services } from "../services";
import type { Target } from "./Target";

interface DeleteManagedLoginBrandingRequest {
  UserPoolId: string;
  ManagedLoginBrandingId: string;
}
type DeleteManagedLoginBrandingResponse = Record<string, never>;

export type DeleteManagedLoginBrandingTarget = Target<
  DeleteManagedLoginBrandingRequest,
  DeleteManagedLoginBrandingResponse
>;

export const DeleteManagedLoginBranding =
  ({ cognito }: Pick<Services, "cognito">): DeleteManagedLoginBrandingTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const items = userPool.options._managedLoginBranding ?? [];
    const idx = items.findIndex(
      (b) => b.ManagedLoginBrandingId === req.ManagedLoginBrandingId,
    );
    if (idx < 0) {
      throw new ResourceNotFoundError("Managed login branding not found");
    }

    items.splice(idx, 1);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _managedLoginBranding: items,
    });

    return {};
  };
