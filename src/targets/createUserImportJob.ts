import { randomUUID } from "node:crypto";
import type {
  CreateUserImportJobRequest,
  CreateUserImportJobResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Services } from "../services";
import type { Target } from "./Target";

export type CreateUserImportJobTarget = Target<
  CreateUserImportJobRequest,
  CreateUserImportJobResponse
>;

export const CreateUserImportJob =
  ({
    cognito,
    clock,
  }: Pick<Services, "cognito" | "clock">): CreateUserImportJobTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const now = clock.get();

    const job = {
      JobName: req.JobName,
      JobId: randomUUID(),
      UserPoolId: req.UserPoolId,
      PreSignedUrl: `https://cognito-local.example.com/import/${randomUUID()}`,
      CreationDate: now,
      Status: "Created" as const,
      CloudWatchLogsRoleArn: req.CloudWatchLogsRoleArn,
      ImportedUsers: 0,
      SkippedUsers: 0,
      FailedUsers: 0,
    };

    const jobs = userPool.options._importJobs ?? [];
    jobs.push(job);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      _importJobs: jobs,
    });

    return { UserImportJob: job };
  };
