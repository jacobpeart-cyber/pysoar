# PySOAR Frontend Dockerfile

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Build identity (OCI labels). The release workflow also sets these itself;
# the build arguments give a local build the same keys. Without them the
# values stay "unknown".
ARG PYSOAR_COMMIT=unknown
ARG PYSOAR_VERSION=unknown
ARG PYSOAR_BUILD_DATE=unknown
LABEL org.opencontainers.image.title="pysoar-frontend" \
      org.opencontainers.image.description="PySOAR web UI: the built frontend served by nginx" \
      org.opencontainers.image.source="https://github.com/jacobpeart-cyber/pysoar" \
      org.opencontainers.image.revision="${PYSOAR_COMMIT}" \
      org.opencontainers.image.version="${PYSOAR_VERSION}" \
      org.opencontainers.image.created="${PYSOAR_BUILD_DATE}"

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
