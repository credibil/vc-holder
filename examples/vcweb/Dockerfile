FROM node:23.4-alpine3.20 AS base

# Install pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME/bin:$PATH"
RUN corepack enable

# Copy source code
COPY ./public /app/public
COPY ./src /app/src
COPY ./index.html /app/index.html
COPY ./package.json /app/package.json
COPY ./tsconfig.app.json /app/tsconfig.app.json
COPY ./tsconfig.json /app/tsconfig.json
COPY ./tsconfig.node.json /app/tsconfig.node.json
COPY ./vite.config.ts /app/vite.config.ts

WORKDIR /app

# Build
FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --no-frozen-lockfile
RUN pnpm run build

# Final image
FROM nginx:1-alpine

COPY ./nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /var/www/html/

EXPOSE 3000
ENTRYPOINT ["nginx", "-g", "daemon off;"]
