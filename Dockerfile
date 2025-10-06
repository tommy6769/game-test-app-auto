
# use a lightweight Node.js image 
FROM node:18-alpine

# set working directory
WORKDIR /app

# Copy package files first and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the code
COPY . .

# Expose Port 3000
EXPOSE 3000

# Start application
CMD ["node", "app.js"]

