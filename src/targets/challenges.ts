import {
  NotAuthorizedError,
  PasswordResetRequiredError,
  UserNotConfirmedException,
} from "../errors";
import type { User } from "../services/userPoolService";

/** The account checks every password sign-in makes before issuing a challenge or tokens. */
export const assertCanSignIn = (user: User): void => {
  if (!user.Enabled) {
    throw new NotAuthorizedError("User is disabled.");
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }
};
