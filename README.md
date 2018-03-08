# About secureBoxNmap

secureBoxNmap is a self contained µService utilizing the Nmap Networkscanner for the secureBox Application.

## Configuration Options

You can configure this service by specifing the following environment variables:

| Environment Variable       | Value Example                |
| -------------------------- | ---------------------------- |
| ENGINE_ADDRESS             | http://securebox/engine-rest |
| ENGINE_BASIC_AUTH_USER     | username                     |
| ENGINE_BASIC_AUTH_PASSWORD | 123456                       |

## Build

Build the docker container:

`docker build -t CONTAINER_NAME .`

## Test

Run the testsuite:

`npm test`
