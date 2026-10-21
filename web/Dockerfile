FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY web/package.json web/pnpm-lock.yaml ./
RUN npm install --global pnpm@10.34.5 && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build && mkdir -p public

FROM gcr.io/distroless/nodejs24-debian13:nonroot
WORKDIR /app
ENV NODE_ENV=production HOSTNAME=0.0.0.0 PORT=3000
COPY --from=build --chown=65532:65532 /app/.next/standalone ./
COPY --from=build --chown=65532:65532 /app/.next/static ./.next/static
COPY --from=build --chown=65532:65532 /app/public ./public
EXPOSE 3000
CMD ["server.js"]
