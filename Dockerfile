# syntax=docker/dockerfile:1
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json vite.config.ts eslint.config.js index.html ./
COPY src ./src
COPY tests ./tests

RUN npm run lint && npm test && npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

COPY --from=builder /app/dist ./dist
COPY server.js package.json ./

USER node
EXPOSE 8080

CMD ["node", "server.js"]
