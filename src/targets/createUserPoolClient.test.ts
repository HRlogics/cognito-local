import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError } from "../errors";
import type { CognitoService, UserPoolService } from "../services";
import {
  CreateUserPoolClient,
  type CreateUserPoolClientTarget,
} from "./createUserPoolClient";

const originalDate = new Date();

describe("CreateUserPoolClient target", () => {
  let createUserPoolClient: CreateUserPoolClientTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockCognitoService: MockedObject<CognitoService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    mockCognitoService = newMockCognitoService(mockUserPoolService);
    createUserPoolClient = CreateUserPoolClient({
      clock: new ClockFake(originalDate),
      cognito: mockCognitoService,
    });
  });

  it.each`
    pinned        | expected
    ${"use-name"} | ${"clientName"}
    ${"fixed-id"} | ${"fixed-id"}
  `("uses the pinned client id $pinned", async ({ pinned, expected }) => {
    mockCognitoService.getUserPool.mockResolvedValue(
      newMockUserPoolService({ Id: "userPoolId", _pinnedClientId: pinned }),
    );

    const result = await createUserPoolClient(TestContext, {
      ClientName: "clientName",
      UserPoolId: "userPoolId",
    });

    expect(result.UserPoolClient?.ClientId).toEqual(expected);
  });

  it("rejects a pinned client id that already exists", async () => {
    mockCognitoService.getUserPool.mockResolvedValue(
      newMockUserPoolService({ Id: "userPoolId", _pinnedClientId: "fixed-id" }),
    );
    mockCognitoService.getAppClient.mockResolvedValue(
      TDB.appClient({ ClientId: "fixed-id", UserPoolId: "userPoolId" }),
    );

    await expect(
      createUserPoolClient(TestContext, {
        ClientName: "clientName",
        UserPoolId: "userPoolId",
      }),
    ).rejects.toEqual(
      new InvalidParameterError("App Client fixed-id already exists"),
    );
  });

  it("creates a new app client", async () => {
    const result = await createUserPoolClient(TestContext, {
      ClientName: "clientName",
      UserPoolId: "userPoolId",
    });

    expect(mockUserPoolService.saveAppClient).toHaveBeenCalledWith(
      TestContext,
      {
        ClientId: expect.any(String),
        ClientName: "clientName",
        CreationDate: originalDate,
        LastModifiedDate: originalDate,
        UserPoolId: "userPoolId",
        TokenValidityUnits: {
          AccessToken: "hours",
          IdToken: "minutes",
          RefreshToken: "days",
        },
      },
    );

    expect(result).toEqual({
      UserPoolClient: {
        ClientId: expect.any(String),
        ClientName: "clientName",
        CreationDate: originalDate,
        LastModifiedDate: originalDate,
        UserPoolId: "userPoolId",
        TokenValidityUnits: {
          AccessToken: "hours",
          IdToken: "minutes",
          RefreshToken: "days",
        },
      },
    });
  });
});
