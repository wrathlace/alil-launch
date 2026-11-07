FROM node:22.11-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci && npx tsc

FROM node:22.11-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json ./
COPY --from=build /app/dist ./dist
RUN git config --system --add safe.directory '*'
USER node
WORKDIR /project
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["."]
