import jwt from "jsonwebtoken";
import { NotAuthorizedError, UnsupportedError } from "../errors";
import type { Services } from "../services";
import type { Context } from "../services/context";
import type { Token } from "../services/tokenGenerator";
import { isSupportedTarget } from "../targets/Target";
import { Targets } from "../targets/targets";

// biome-ignore lint/suspicious/noExplicitAny: generic route handler
export type Route = (ctx: Context, req: any) => Promise<any>;
export type Router = (target: string) => Route;

/**
 * Rejects an access token issued at or before the user's last global sign-out. Tokens are only
 * decoded, like the targets do; anything that does not resolve to a user is left to the target.
 * Resolution is one second (the iat claim), so a token issued in the same second as the sign-out
 * is revoked too; a millisecond issue-time claim would remove that.
 */
const assertAccessTokenNotRevoked = async (
  ctx: Context,
  services: Services,
  accessToken: unknown,
) => {
  if (typeof accessToken !== "string") return;
  const token = jwt.decode(accessToken) as Token | null;
  if (!token?.client_id || !token.sub || typeof token.iat !== "number") return;

  const user = await services.cognito
    .getUserPoolForClientId(ctx, token.client_id)
    .then((userPool) => userPool.getUserByUsername(ctx, token.sub))
    .catch(() => null);
  if (user?.AccessTokensRevokedAt && token.iat <= user.AccessTokensRevokedAt) {
    throw new NotAuthorizedError("Access Token has been revoked");
  }
};

export const Router =
  (services: Services): Router =>
  (target: string) => {
    if (!isSupportedTarget(target)) {
      return () =>
        Promise.reject(
          new UnsupportedError(`Unsupported x-amz-target header "${target}"`),
        );
    }

    const t = Targets[target](services);

    return async (ctx, req) => {
      const targetLogger = ctx.logger.child({
        target,
      });

      targetLogger.debug("start");
      await assertAccessTokenNotRevoked(ctx, services, req?.AccessToken);
      const res = await t(
        {
          ...ctx,
          logger: targetLogger,
        },
        req,
      );
      targetLogger.debug("end");
      return res;
    };
  };
