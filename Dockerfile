FROM node:10-alpine

RUN apk update && apk upgrade && apk add nmap nmap-scripts

COPY package.json package-lock.json /src/

WORKDIR /src

RUN ls

RUN npm install --production

COPY . /src

HEALTHCHECK --interval=5s --timeout=5s --start-period=30s --retries=3 CMD node healthcheck.js || exit 1

RUN addgroup -S nmap_group && adduser -S -g nmap_group nmap_user 

USER nmap_user

EXPOSE 8080

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