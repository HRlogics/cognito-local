FROM node:24-alpine AS builder
WORKDIR /app

ADD package.json package-lock.json ./
RUN npm ci --ignore-scripts

ADD src src
ADD tsconfig.json tsconfig.build.json ./

RUN npx esbuild src/bin/start.ts --outdir=lib --platform=node --target=node24 --bundle

FROM node:24-alpine
WORKDIR /app
COPY --from=builder /app/lib .

EXPOSE 9229
ENV HOST=0.0.0.0
ENV PORT=9229
VOLUME /app/.cognito
ENTRYPOINT ["node", "/app/start.js"]
