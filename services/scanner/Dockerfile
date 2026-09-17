FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive
# Tell playwright-core to skip downloading its own browser
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
# Tell the scanner where to find the system-installed chromium
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

RUN apt-get update && apt-get install -y \
    chromium \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Use built-in 'node' non-root user (equivalent to the old pwuser)
RUN chown node:node /app
USER node

COPY --chown=node:node package.json package-lock.json* ./
RUN npm install

COPY --chown=node:node src/ ./src/

ENV PORT=8788
EXPOSE 8788

CMD ["node", "src/server.mjs"]
