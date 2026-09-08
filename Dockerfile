FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
RUN mkdir -p /app/data/transfers /app/data/tmp
EXPOSE 3000
VOLUME ["/app/data"]
CMD ["node", "server.js"]
