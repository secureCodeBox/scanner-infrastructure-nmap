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

ENTRYPOINT [ "npm", "start" ]