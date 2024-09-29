ARG NODE_VERSION=18.5.0
FROM node:${NODE_VERSION}

# Set the work directory
WORKDIR /phishviewer

# Copy and install dependencies
COPY phishviewer/package*.json ./
RUN npm install -g npm@8.19.4 && npm install --omit=dev

# Install PM2 for better NodeJS serving
RUN npm install pm2 -g

# Copy BigPhish code
COPY ./phishviewer .

# Add custom certificates for TLS connections, consistent with compose file!
# ADD certificate.pem /path/in/container/to/certificate.pem

CMD ["pm2-runtime", "start", "./bin/www"]