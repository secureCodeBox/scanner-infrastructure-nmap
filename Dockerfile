FROM node:10-buster AS buildcontainer

ENV  NMAP_SHA256SUM="fcfa5a0e42099e12e4bf7a68ebe6fde05553383a682e816a7ec9256ab4773faa" \
     NMAP_VERSION=7.80

WORKDIR /nmap

ARG NMAP_PACKAGE="nmap-${NMAP_VERSION}.tar.bz2"
ARG NMAP_URI="https://nmap.org/dist/${NMAP_PACKAGE}"

RUN echo "Installing Nmap ${NMAP_VERSION}" && \
    apt-get update && \
    apt-get install -y --no-install-recommends >/dev/null \
    build-essential \
    libexpat1-dev \
    libffi-dev \
    libssl-dev \
    xz-utils \
    zlib1g-dev \
    flex \
    libbison-dev \
    libcap-dev \
    bison \
    && set -ex \
    && curl -fsSLO ${NMAP_URI} \
    && echo "${NMAP_SHA256SUM} ${NMAP_PACKAGE}" | sha256sum -c - \
    && bzip2 -cd "${NMAP_PACKAGE}" | tar xvf - \
    && cd "nmap-${NMAP_VERSION}" \
    && ./configure \
    && make -s -j "$(nproc)" \
    && make -s install > /dev/null \
    && ldconfig \
    && apt-get -y remove >/dev/null \
    build-essential \
    libexpat1-dev \
    libffi-dev \
    libssl-dev \
    xz-utils \
    zlib1g-dev \
    flex \
    libbison-dev \ 
    libcap-dev \
    bison \
    && apt-get autoremove -y >/dev/null \
    && addgroup --system nmap_group && adduser --system --gecos nmap_group nmap_user

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

FROM node:10-buster

ARG NMAP_VERSION=7.80

COPY package.json package-lock.json /src/ 
COPY --from=buildcontainer /nmap/nmap-${NMAP_VERSION} /nmap/nmap-${NMAP_VERSION}
COPY . /src

RUN apt-get update && \
    apt-get upgrade -y && \
    cd /nmap/nmap-${NMAP_VERSION} && \
    make -s install > /dev/null && \
    cd /src && \
    rm -rf /nmap && \
    npm install --production && \ 
    addgroup --system nmap_group && \
    adduser --system --gecos nmap_group nmap_user 

WORKDIR /src

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