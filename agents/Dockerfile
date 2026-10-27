FROM node:22-alpine
WORKDIR /agent
COPY worker.mjs ./worker.mjs
USER node
ENTRYPOINT ["node", "/agent/worker.mjs"]
