FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=latest

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && mkdir -p /workspace \
    && chown node:node /workspace

USER node
WORKDIR /workspace

CMD ["sleep", "infinity"]
