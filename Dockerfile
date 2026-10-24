FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy application source
COPY bin/ ./bin/
COPY README.md LICENSE ./

# Run as non-root user for security compliance
USER node

# Start DarkLens stdio MCP server
ENTRYPOINT ["node", "bin/index.js"]
