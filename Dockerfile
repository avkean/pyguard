# Step 1: Use an official Node image as the builder
FROM node:18-alpine AS builder

# Step 2: Set working directory
WORKDIR /app

# Step 3: Install build-time dependencies. The Next.js prebuild step
# (`npm run gen:v5`) shells out to python3 to obfuscate and minify the
# interpreter source — alpine doesn't ship python3 by default.
RUN apk add --no-cache python3

# Step 4: Copy package.json and package-lock.json (or yarn.lock)
COPY package*.json ./

# Step 5: Install dependencies
RUN npm install

# Step 6: Copy the rest of the application code
COPY . .

# Step 7: Build the Next.js app (runs `prebuild` -> gen:v5 first)
RUN npm run build

# Step 8: Use a smaller Node image for the production build
FROM node:18-alpine AS runner

WORKDIR /app

# Step 9: Copy the built app and necessary files from the builder.
# The runtime image does NOT need python3 — obfuscation runs entirely in
# the browser via Pyodide.
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/public ./public

# Step 10: Set environment variable to production
ENV NODE_ENV=production

# Step 11: Expose the port the app runs on
EXPOSE 3000

# Step 12: Command to run the app
CMD ["npm", "run", "start"]
