# Cognito Local

**122 SDK targets + 7 OAuth2/OIDC endpoints = 100% AWS Cognito User Pool API coverage**

`Build: passing` | `Tests: 801 passing` | `License: MIT` | `Node >= 24.21`

A local Amazon Cognito User Pool emulator for development and testing. Drop-in replacement for the real service -- point your SDK at `http://localhost:9229` and go.

> Fork of [jagregory/cognito-local](https://github.com/jagregory/cognito-local), upgraded from partial coverage to full API parity.

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Quick Start](#quick-start)
  - [npm](#npm)
  - [Docker](#docker)
  - [Point your SDK at it](#point-your-sdk-at-it)
  - [Create a User Pool](#create-a-user-pool)
- [What's Supported](#whats-supported)
  - [Authentication](#authentication)
  - [MFA](#mfa)
  - [User CRUD](#user-crud)
  - [Groups](#groups)
  - [User Pools & Clients](#user-pools--clients)
  - [Identity Providers (Federation)](#identity-providers-federation)
  - [Resource Servers](#resource-servers)
  - [Devices](#devices)
  - [Domains & Branding](#domains--branding)
  - [WebAuthn (Passkeys)](#webauthn-passkeys)
  - [Import Jobs](#import-jobs)
  - [Tags, Terms, Risk, Logging](#tags-terms-risk-logging)
  - [Other](#other)
  - [Pagination](#pagination)
- [OAuth2 / OIDC Endpoints](#oauth2--oidc-endpoints)
- [Configuration](#configuration)
  - [Lambda Triggers](#lambda-triggers)
  - [Environment Variables](#environment-variables)
  - [Data Storage](#data-storage)
- [API Parity Summary](#api-parity-summary)
- [Tech Stack](#tech-stack)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick Start

### npm

```bash
npm start
# Listening on http://localhost:9229
```

### Docker

```bash
docker compose up
# Listening on http://localhost:9229
```

Prebuilt multi-arch image (amd64, arm64), published from `master`:

```bash
docker run --rm -p 9229:9229 -v cognito-data:/app/.cognito ghcr.io/hrlogics/cognito-local:latest
```

### Point your SDK at it

```js
const client = new CognitoIdentityProviderClient({
  region: "us-east-1",
  endpoint: "http://localhost:9229",
});
```

### Create a User Pool

```bash
aws --endpoint http://localhost:9229 cognito-idp create-user-pool --pool-name MyPool
```

> Credentials are required by the CLI but not validated. Use dummy values if needed:
> `AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local aws --endpoint http://localhost:9229 cognito-idp ...`

---

## What's Supported

### Authentication

| Category | Targets |
|----------|---------|
| Auth flows | InitiateAuth, AdminInitiateAuth, RespondToAuthChallenge, AdminRespondToAuthChallenge |
| SRP auth | USER_SRP_AUTH, PASSWORD_VERIFIER (simplified -- verifies password directly) |
| Password auth | USER_PASSWORD_AUTH |
| Custom auth | CUSTOM_AUTH with DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse triggers |
| Refresh tokens | GetTokensFromRefreshToken, REFRESH_TOKEN / REFRESH_TOKEN_AUTH |
| Sign-up | SignUp, ConfirmSignUp, ResendConfirmationCode |
| Password reset | ForgotPassword, ConfirmForgotPassword, AdminResetUserPassword |
| Sign-out | GlobalSignOut, AdminUserGlobalSignOut, RevokeToken |

**Challenge types:** SMS_MFA, SOFTWARE_TOKEN_MFA, NEW_PASSWORD_REQUIRED, PASSWORD_VERIFIER, MFA_SETUP, CUSTOM_CHALLENGE

**Errors match AWS:** a wrong password is `NotAuthorizedException: Incorrect username or password.`, an unknown username is `UserNotFoundException` (or `NotAuthorizedException` when the client sets `PreventUserExistenceErrors: ENABLED`), and a user disabled with AdminDisableUser gets `NotAuthorizedException: User is disabled.` in every flow.

**Sign-out revokes access tokens:** after GlobalSignOut or AdminUserGlobalSignOut, requests that carry an access token issued at or before the sign-out fail with `NotAuthorizedException: Access Token has been revoked`. Resolution is one second, and `/oauth2/userInfo` does not check revocation.

### MFA

| Target | Description |
|--------|-------------|
| AssociateSoftwareToken | Begin TOTP setup, returns secret |
| VerifySoftwareToken | Verify TOTP code |
| SetUserMFAPreference | Set per-user MFA preference |
| AdminSetUserMFAPreference | Admin variant |
| SetUserPoolMfaConfig | Pool-level MFA config |
| GetUserPoolMfaConfig | Read pool-level MFA config |
| GetUserAuthFactors | List user's auth factors |

### User CRUD

AdminCreateUser, AdminGetUser, AdminDeleteUser, AdminEnableUser, AdminDisableUser, AdminSetUserPassword, AdminUpdateUserAttributes, AdminDeleteUserAttributes, AdminConfirmSignUp, GetUser, DeleteUser, ChangePassword, UpdateUserAttributes, DeleteUserAttributes, GetUserAttributeVerificationCode, VerifyUserAttribute, AdminSetUserSettings, SetUserSettings

ListUsers takes AWS filter syntax with `=` and `^=`, with or without spaces around the operator and with an optionally quoted attribute name (`email="a@example.com"`, `"email" ^= "a"`). AdminUpdateUserAttributes answers `AliasExistsException` when another user already holds the new email or phone number.

### Groups

CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups, AdminAddUserToGroup, AdminRemoveUserFromGroup, AdminListGroupsForUser, ListUsersInGroup

### User Pools & Clients

CreateUserPool, DescribeUserPool, UpdateUserPool, DeleteUserPool, ListUserPools, CreateUserPoolClient, DescribeUserPoolClient, UpdateUserPoolClient, DeleteUserPoolClient, ListUserPoolClients, AddCustomAttributes, AddUserPoolClientSecret, DeleteUserPoolClientSecret, ListUserPoolClientSecrets

Pool and client ids are random unless pinned with reserved tags on `CreateUserPool`. `cognito-local:pool-id` sets the pool id as given; `cognito-local:client-id` sets the id of every client created in that pool later, and `use-name` makes it reuse the `ClientName`. Both tags are dropped from the stored pool. Pinning an id that is already in use fails with `InvalidParameterException`. DeleteUserPool deletes the pool's clients too, so a pinned pool can be deleted and created again with the same ids.

```bash
aws --endpoint http://localhost:9229 cognito-idp create-user-pool --pool-name MyPool \
  --user-pool-tags cognito-local:pool-id=us-east-1_mypool,cognito-local:client-id=use-name
aws --endpoint http://localhost:9229 cognito-idp create-user-pool-client \
  --user-pool-id us-east-1_mypool --client-name my-app   # ClientId: my-app
```

### Identity Providers (Federation)

CreateIdentityProvider, DescribeIdentityProvider, UpdateIdentityProvider, DeleteIdentityProvider, ListIdentityProviders, GetIdentityProviderByIdentifier, AdminLinkProviderForUser, AdminDisableProviderForUser

### Resource Servers

CreateResourceServer, DescribeResourceServer, UpdateResourceServer, DeleteResourceServer, ListResourceServers

### Devices

ConfirmDevice, GetDevice, AdminGetDevice, ForgetDevice, AdminForgetDevice, UpdateDeviceStatus, AdminUpdateDeviceStatus, ListDevices, AdminListDevices

### Domains & Branding

CreateUserPoolDomain, DescribeUserPoolDomain, UpdateUserPoolDomain, DeleteUserPoolDomain, CreateManagedLoginBranding, DescribeManagedLoginBranding, DescribeManagedLoginBrandingByClient, UpdateManagedLoginBranding, DeleteManagedLoginBranding, GetUICustomization, SetUICustomization

### WebAuthn (Passkeys)

StartWebAuthnRegistration, CompleteWebAuthnRegistration, ListWebAuthnCredentials, DeleteWebAuthnCredential

### Import Jobs

CreateUserImportJob, DescribeUserImportJob, StartUserImportJob, StopUserImportJob, ListUserImportJobs, GetCSVHeader

### Tags, Terms, Risk, Logging

TagResource, UntagResource, ListTagsForResource, CreateTerms, DescribeTerms, UpdateTerms, DeleteTerms, ListTerms, DescribeRiskConfiguration, SetRiskConfiguration, GetLogDeliveryConfiguration, SetLogDeliveryConfiguration

### Other

AdminListUserAuthEvents, AdminUpdateAuthEventFeedback, UpdateAuthEventFeedback, GetSigningCertificate

### Pagination

All `List*` APIs support pagination via `NextToken` / `MaxResults`.

---

## OAuth2 / OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/authorize` | GET, POST | Authorization endpoint with PKCE support |
| `/oauth2/token` | POST | Token exchange (authorization_code, refresh_token, client_credentials) |
| `/oauth2/userInfo` | GET | OpenID Connect UserInfo |
| `/oauth2/revoke` | POST | Token revocation |
| `/logout` | GET | End session / logout |
| `/{poolId}/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/{poolId}/.well-known/openid-configuration` | GET | OIDC discovery document |

---

## Configuration

Configuration lives in `.cognito/config.json`. Create it only if you need to customize behavior:

```bash
mkdir -p .cognito && echo '{}' > .cognito/config.json
```

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ServerConfig.hostname` | string | `localhost` | Hostname to bind |
| `ServerConfig.port` | number | `9229` | Port to listen on |
| `ServerConfig.https` | boolean | `false` | Enable TLS |
| `ServerConfig.cert` | string | -- | Path to TLS cert |
| `ServerConfig.key` | string | -- | Path to TLS key |
| `TokenConfig.IssuerDomain` | string | `http://localhost:9229` | JWT issuer domain |
| `LambdaClient.endpoint` | string | -- | Local Lambda endpoint (e.g. serverless-offline) |
| `LambdaClient.region` | string | `local` | Lambda region |
| `TriggerFunctions` | object | `{}` | Trigger-to-function mapping |
| `UserPoolDefaults.UsernameAttributes` | string[] | `["email"]` | Default username attributes |
| `KMSConfig.endpoint` | string | -- | Local KMS endpoint |

### Lambda Triggers

Configure triggers by mapping trigger names to Lambda function names:

```json
{
  "LambdaClient": {
    "endpoint": "http://localhost:3002"
  },
  "TriggerFunctions": {
    "PreSignUp": "my-presignup-fn",
    "PostConfirmation": "my-postconfirm-fn",
    "CustomMessage": "my-custom-message-fn",
    "DefineAuthChallenge": "my-define-auth-fn",
    "CreateAuthChallenge": "my-create-auth-fn",
    "VerifyAuthChallengeResponse": "my-verify-auth-fn"
  }
}
```

Supported triggers: PreSignUp, PostConfirmation, PostAuthentication, PreAuthentication, PreTokenGeneration, CustomMessage, CustomEmailSender, UserMigration, DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Override listen port |
| `HOST` | Override listen hostname |
| `DEBUG` | Enable verbose logging |
| `CODE` | Fixed confirmation code (instead of random) |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | Accept self-signed certs for Lambda endpoints |

### Data Storage

User Pools are stored as JSON files in `.cognito/db/`. Clients are stored in `.cognito/db/clients.json`. In Docker, mount a volume at `/app/.cognito` to persist data between runs. The container runs as the `node` user (uid 1000), so a host bind mount must be writable by uid 1000 (rootless podman: add `--userns=keep-id`).

---

## API Parity Summary

| Category | Targets | Status |
|----------|--------:|--------|
| Authentication & sign-up | 14 | All implemented |
| MFA (TOTP) | 7 | All implemented |
| User CRUD (admin + self-service) | 18 | All implemented |
| Groups | 9 | All implemented |
| User pools & clients | 14 | All implemented |
| Identity providers | 8 | All implemented |
| Resource servers | 5 | All implemented |
| Devices | 9 | All implemented |
| Domains & branding | 10 | All implemented |
| WebAuthn | 4 | All implemented |
| Import jobs | 6 | All implemented |
| Tags, terms, risk, logging | 12 | All implemented |
| Other | 4 | All implemented |
| OAuth2/OIDC endpoints | 7 | All implemented |
| **Total** | **~129** | **100%** |

---

## Tech Stack

| Component | Version |
|-----------|---------|
| Node.js | 24.21+ |
| TypeScript | 7 |
| Express | 5 |
| Test runner | Vitest 5 |
| Linter | Biome 2 |
| Build | esbuild |

---

## Roadmap

This project will become `@nimbus/plugin-cognito` as part of the [Nimbus](https://github.com/your-org/nimbus) local AWS emulator suite.

---

## Contributing

1. Fork the repo and create a feature branch.
2. Write tests for new targets (see existing `*.test.ts` files for patterns).
3. Run `npm test` and ensure all 801+ tests pass.
4. Submit a pull request.

---

## License

MIT
