FROM alpine:3.9

COPY ./nmap /nmap

WORKDIR /nmap

RUN apk update && \
    apk upgrade && \
    apk add build-base && \
    apk add libpcap && \
    apk add flex && \
    apk add bison && \
    apk add linux-headers && \
    apk add openssl-dev && \
    apk add libssh2-dev

FROM node:10-buster

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y alien && \
    wget https://nmap.org/dist/nmap-7.80-1.x86_64.rpm && \
    alien nmap-7.80-1.x86_64.rpm && \
    dpkg -i nmap_7.80-2_amd64.deb && \
    npm install --production && \
    addgroup --system nmap_group && \
    adduser --system --gecos nmap_group nmap_user 


COPY package.json package-lock.json /src/

WORKDIR /src

COPY . /src

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD node healthcheck.js || exit 1

USER nmap_user

EXPOSE 8080

ENV NMAP_UNPRIVILEGED=true

ARG COMMIT_ID=unkown
ARG REPOSITORY_URL=unkown
ARG BRANCH=unkown
ARG BUILD_DATE
ARG VERSION

ENV SCB_COMMIT_ID ${COMMIT_ID}
ENV SCB_REPOSITORY_URL ${REPOSITORY_URL}
ENV SCB_BRANCH ${BRANCH}

LABEL org.opencontainers.image.title="secureCodeBox scanner-infrastructure-nmap" \
    org.opencontainers.image.description="Nmap integration for secureCodeBox" \
    org.opencontainers.image.authors="iteratec GmbH" \
    org.opencontainers.image.vendor="iteratec GmbH" \
    org.opencontainers.image.documentation="https://github.com/secureCodeBox/secureCodeBox" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.url=$REPOSITORY_URL \
    org.opencontainers.image.source=$REPOSITORY_URL \
    org.opencontainers.image.revision=$COMMIT_ID \
    org.opencontainers.image.created=$BUILD_DATE

ENTRYPOINT [ "npm", "start" ]
