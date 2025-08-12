ARG NODE_IMAGE=node:lts
FROM ${NODE_IMAGE}

# install build tools for native modules (re2) and git
RUN apt update -y && apt upgrade -y && apt install -y git python3 make g++ && rm -rf /var/lib/apt/lists/*

ARG GL_TOKEN
RUN git config --global url."https://git-push-pull:${GL_TOKEN}@gitlab.reclaimprotocol.org".insteadOf "https://gitlab.reclaimprotocol.org"

COPY ./package.json /app/
COPY ./package-lock.json /app/
RUN mkdir -p /app/src/scripts
RUN echo '' > /app/src/scripts/prepare.sh

WORKDIR /app

RUN npm ci --include=optional

COPY ./ /app

RUN npm run build
RUN npm run download:zk-files
RUN npm run build:browser
RUN npm prune --production

CMD ["npm", "run", "start"]
EXPOSE 8001