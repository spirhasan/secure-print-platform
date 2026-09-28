FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p storage/uploads
ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
