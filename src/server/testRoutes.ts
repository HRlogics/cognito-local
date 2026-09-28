import express, { type Application } from "express";
import { CognitoError } from "../errors";
import type { Router } from "./Router";

/**
 * Test helpers under `/_`, outside the Cognito API surface. Pool ids never start with `_` and the
 * pool routes have two segments, so nothing collides.
 */
type SeedUser = { Email: string; Password: string };

const isSeedUser = (value: unknown): value is SeedUser =>
  typeof value === "object" &&
  value !== null &&
  "Email" in value &&
  typeof value.Email === "string" &&
  "Password" in value &&
  typeof value.Password === "string";

export const attachTestRoutes = (app: Application, router: Router) => {
  /**
   * Seeds confirmed users with a verified email and a permanent password in one call, the same
   * way `AdminCreateUser` + `AdminSetUserPassword` would. A user whose email already exists keeps
   * its Username and gets the password, so a suite can re-seed without checking first.
   */
  app.post("/_/users", express.json(), async (req, res) => {
    const { UserPoolId, Users } = req.body ?? {};
    if (
      typeof UserPoolId !== "string" ||
      !Array.isArray(Users) ||
      !Users.every(isSeedUser)
    ) {
      res.status(400).json({
        message:
          "Expected { UserPoolId: string, Users: [{ Email: string, Password: string }] }",
      });
      return;
    }

    const ctx = { logger: req.log };
    try {
      const seeded: { Email: string; Username: string }[] = [];
      for (const { Email, Password } of Users) {
        const existing = await router("ListUsers")(ctx, {
          UserPoolId,
          Filter: `email = "${Email}"`,
        });
        const Username: string =
          existing.Users[0]?.Username ??
          (
            await router("AdminCreateUser")(ctx, {
              UserPoolId,
              Username: Email,
              MessageAction: "SUPPRESS",
              UserAttributes: [
                { Name: "email", Value: Email },
                { Name: "email_verified", Value: "true" },
              ],
            })
          ).User.Username;
        await router("AdminSetUserPassword")(ctx, {
          UserPoolId,
          Username,
          Password,
          Permanent: true,
        });
        seeded.push({ Email, Username });
      }
      res.status(200).json({ Users: seeded });
    } catch (ex) {
      if (ex instanceof CognitoError) {
        res.status(400).json({ __type: ex.code, message: ex.message });
        return;
      }
      req.log.error(ex, "Error seeding users");
      res.status(500).json({ message: "Error seeding users" });
    }
  });
};
