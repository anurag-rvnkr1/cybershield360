# ─────────────────────────────────────────────────────────────
#  Dockerfile — CyberShield 360 FREE
#  Optimised for Railway.app free tier (512MB RAM, shared CPU)
#  Single container serves BOTH API + frontend (no nginx needed)
# ─────────────────────────────────────────────────────────────

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

FROM node:20-alpine AS runner
WORKDIR /app

# Non-root user for security
RUN addgroup -g 1001 -S app && adduser -u 1001 -S app -G app

COPY --from=deps --chown=app:app /app/node_modules ./node_modules
COPY --chown=app:app src/ ./src/
COPY --chown=app:app public/ ./public/
COPY --chown=app:app package.json ./

USER app

LABEL org.opencontainers.image.title="CyberShield 360 Free"
LABEL org.opencontainers.image.description="100% free-tier cybersecurity platform"

ENV NODE_ENV=production
# Railway injects PORT automatically — we read it in server.js
EXPOSE 3001

# Minimal healthcheck (Railway also does HTTP checks)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3001}/api/health || exit 1

CMD ["node", "src/server.js"]
