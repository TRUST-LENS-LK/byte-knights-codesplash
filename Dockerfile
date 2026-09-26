FROM node:22-alpine

# Set working directory
WORKDIR /app

# Copy the entire monorepo
COPY . .

# Install dependencies for all workspaces
RUN npm ci

# The command will be overridden by docker-compose.yml for each service
CMD ["npm", "start"]
