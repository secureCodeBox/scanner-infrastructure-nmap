FROM alpine:3.10 AS buildcontainer

ARG  NMAP_SHA256SUM="fcfa5a0e42099e12e4bf7a68ebe6fde05553383a682e816a7ec9256ab4773faa"
ARG  NMAP_VERSION=7.80

WORKDIR /nmap

ENV NMAP_PACKAGE="nmap-${NMAP_VERSION}.tar.bz2"
ENV NMAP_URI="https://nmap.org/dist/${NMAP_PACKAGE}"

RUN echo "Installing Nmap ${NMAP_VERSION}" && \
    apk update && \
    apk upgrade && \
    apk add build-base && \
    apk add flex && \
    apk add libcap-dev && \
    apk add openssl-dev && \
    apk add libssh2-dev && \
    apk add bison && \
    apk add curl
RUN curl -fsSLO ${NMAP_URI}
RUN echo "${NMAP_SHA256SUM}  ${NMAP_PACKAGE}" | sha256sum -c -
RUN bzip2 -cd "${NMAP_PACKAGE}" | tar xvf -
WORKDIR /nmap/nmap-${NMAP_VERSION}
RUN ./configure && \
    make -s -j "$(nproc)" && \
    make -s install

FROM node:12-alpine

ARG NMAP_VERSION=7.80

COPY package.json package-lock.json /src/ 
COPY --from=buildcontainer /usr/local/ /usr/local
COPY . /src

WORKDIR /src

RUN apk update && \
    apk upgrade --no-cache && \
    apk add libssh2 --no-cache
RUN npm install --production
RUN addgroup -S nmap_group && \
    adduser -S -g nmap_group nmap_user

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

