FROM node:8.11-alpine

RUN apk update && apk upgrade && apk add nmap nmap-scripts

COPY package.json package-lock.json /src/

WORKDIR /src

RUN ls

RUN npm install --production

COPY . /src

RUN addgroup -S nmap_group && adduser -S -g nmap_group nmap_user 

USER nmap_user

EXPOSE 3000

ARG COMMIT_ID=unkown
ARG REPOSITORY_URL=unkown
ARG BRANCH=unkown

ENV SCB_COMMIT_ID ${COMMIT_ID}
ENV SCB_REPOSITORY_URL ${REPOSITORY_URL}
ENV SCB_BRANCH ${BRANCH}

ENTRYPOINT [ "npm", "start" ]