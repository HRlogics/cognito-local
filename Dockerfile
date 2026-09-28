ARG NODE_VERSION=24.21
# The bundle is plain JS, so build on the runner's native platform, no emulation
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS builder
WORKDIR /app

ADD package.json package-lock.json ./
RUN npm ci --ignore-scripts

ADD src src
ADD tsconfig.json tsconfig.build.json ./

RUN npx esbuild src/bin/start.ts --outdir=lib --platform=node --target=node24.21 --bundle
# runtime stage has no RUN, so create the writable data dir here
RUN mkdir -p /out/.cognito

FROM node:${NODE_VERSION}-alpine
WORKDIR /app
COPY --from=builder /app/lib .
COPY --from=builder --chown=node:node /out/.cognito /app/.cognito

EXPOSE 9229
ENV HOST=0.0.0.0
ENV PORT=9229
VOLUME /app/.cognito
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO /dev/null "http://127.0.0.1:${PORT}/health" || exit 1
USER node
ENTRYPOINT ["node", "/app/start.js"]
