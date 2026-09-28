import { randomUUID } from "node:crypto";
import {
  NotAuthorizedError,
  PasswordResetRequiredError,
  UserNotConfirmedException,
} from "../errors";
import { attributesToRecord, type User } from "../services/userPoolService";

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

/**
 * The NEW_PASSWORD_REQUIRED challenge for a FORCE_CHANGE_PASSWORD user. amazon-cognito-identity-js
 * JSON.parses both requiredAttributes and userAttributes, so both must be present.
 */
export const newPasswordChallenge = (user: User) => ({
  ChallengeName: "NEW_PASSWORD_REQUIRED",
  ChallengeParameters: {
    USER_ID_FOR_SRP: user.Username,
    requiredAttributes: JSON.stringify([]),
    userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
  },
  Session: randomUUID(),
});
