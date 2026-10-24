FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY scripts/build.mjs ./scripts/build.mjs
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM build AS test
COPY test ./test
RUN node --test test/*.test.mjs

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /data /config && chown node:node /data /config
USER node
VOLUME ["/data"]
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["start", "--config", "/config/security-watch.yaml"]
