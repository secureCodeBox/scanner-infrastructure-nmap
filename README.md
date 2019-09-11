---
title: "Nmap"
path: "scanner/Nmap"
category: "scanner"
usecase: "Network Scanner"
release: "https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-nmap.svg"

---

![Nmap logo](https://nmap.org/images/sitelogo.png)

Nmap ("Network Mapper") is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. 

<!-- end -->

# About
This repository contains a self contained µService utilizing the NMAP Networkscanner for the secureCodeBox project. To learn more about the WPScan scanner itself visit [https://nmap.org/].

## Nmap parameters

When the scanner is started the following variables need to be configured:

* `NMAP_CONTEXT`: The business context under which the scan should be executed
* `NMAP_TARGET`: The scanner target (e.g. localhost, 132.145.77.11, example.com, etc.)
* `NMAP_TARGET_NAME`: Specifies a name for the target (Used in the Results).
* `NMAP_CONFIGURATION_TYPE`: _default_ or _advanced_. When set to _advanced_, additional
options can be specified. 
* `PROCESS_MARK_FALSE_POSITIVE`: Specifies if an additional task should be executed, which checks
for false-positive results

For information how to start a scanner see [Starting Scan Processes](https://github.com/secureCodeBox/engine/wiki/Starting-Scan-Processes)

### Advanced Configuration

If the `NMAP_CONFIGURATION_TYPE` is set to _advanced_, you have the 
option to change the `NMAP_TARGET` again.
Furthermore additional options for the Nmap parameters 
can be defined. The most important options are: 

* `-p` xx: Scan ports of the target. Replace xx with a single port number or
a range of ports.
* `-PS`, `-PA`, `-PU` xx: Replace xx with the ports to scan. TCP SYN/ACK or 
UDP discovery.
* `-sV`: Determine service and version info.
* `-O`: Determine OS info.
* `-A`: Determine service/version and OS info.
* `-script` xx: Replace xx with the script name. Start the scan with the given script.
* `--script` xx: Replace xx with a coma-separated list of scripts. Start the scan with the given scripts.

A list of options is available in the input form of the scanner configuration.
For a detailed explanation refer to the [Nmap Reference Guide](https://nmap.org/book/man.html).

## Example
Example configuration:

```json
[
  {
    "name": "nmap",
    "context": "Example Test",
    "target": {
      "name": "BodgeIT on OpenShift",
      "location": "bodgeit-scb.cloudapps.iterashift.com",
      "attributes": {
        "NMAP_PARAMTER": ""  
      }
    }
  }
]
```

Example Output:

```json
{
    "findings": [
      {
        "id": "40d62ef5-81ca-4880-b59f-bd541f5d7c60",
        "name": "http",
        "description": "Port 80 is open using tcp protocol.",
        "category": "Open Port",
        "osi_layer": "NETWORK",
        "severity": "INFORMATIONAL",
        "attributes": {
          "port": 80,
          "state": "open",
          "ip_address": "52.58.225.89",
          "mac_address": null,
          "protocol": "tcp",
          "hostname": "bodgeit-scb.cloudapps.iterashift.com",
          "method": "table",
          "operating_system": null,
          "service": "http",
          "serviceProduct": null,
          "serviceVersion": null,
          "scripts": null
        },
        "location": "tcp://52.58.225.89:80",
        "false_positive": false
      },
      {
        "id": "120b6403-fb95-4794-92a6-af6ec53ecc54",
        "name": "https",
        "description": "Port 443 is open using tcp protocol.",
        "category": "Open Port",
        "osi_layer": "NETWORK",
        "severity": "INFORMATIONAL",
        "attributes": {
          "port": 443,
          "state": "open",
          "ip_address": "52.58.225.89",
          "mac_address": null,
          "protocol": "tcp",
          "hostname": "bodgeit-scb.cloudapps.iterashift.com",
          "method": "table",
          "operating_system": null,
          "service": "https",
          "serviceProduct": null,
          "serviceVersion": null,
          "scripts": null
        },
        "location": "tcp://52.58.225.89:443",
        "false_positive": false
      },
      {
        "id": "a24c9e95-536f-4374-9ef8-a76e4ac526c4",
        "name": "https-alt",
        "description": "Port 8443 is open using tcp protocol.",
        "category": "Open Port",
        "osi_layer": "NETWORK",
        "severity": "INFORMATIONAL",
        "attributes": {
          "port": 8443,
          "state": "open",
          "ip_address": "52.58.225.89",
          "mac_address": null,
          "protocol": "tcp",
          "hostname": "bodgeit-scb.cloudapps.iterashift.com",
          "method": "table",
          "operating_system": null,
          "service": "https-alt",
          "serviceProduct": null,
          "serviceVersion": null,
          "scripts": null
        },
        "location": "tcp://52.58.225.89:8443",
        "false_positive": false
      },
      {
        "id": "9260dd97-a571-4a25-a253-d6ca9ccbb234",
        "name": "dynamid",
        "description": "Port 9002 is open using tcp protocol.",
        "category": "Open Port",
        "osi_layer": "NETWORK",
        "severity": "INFORMATIONAL",
        "attributes": {
          "port": 9002,
          "state": "open",
          "ip_address": "52.58.225.89",
          "mac_address": null,
          "protocol": "tcp",
          "hostname": "bodgeit-scb.cloudapps.iterashift.com",
          "method": "table",
          "operating_system": null,
          "service": "dynamid",
          "serviceProduct": null,
          "serviceVersion": null,
          "scripts": null
        },
        "location": "tcp://52.58.225.89:9002",
        "false_positive": false
      },
      {
        "id": "c98330a6-b2b3-4d12-b0f5-d41af0a13dbe",
        "name": "Host: bodgeit-scb.cloudapps.iterashift.com",
        "description": "Found a host",
        "category": "Host",
        "osi_layer": "NETWORK",
        "severity": "INFORMATIONAL",
        "attributes": {
          "ip_address": "52.58.225.89",
          "hostname": "bodgeit-scb.cloudapps.iterashift.com",
          "operating_system": null
        },
        "location": "bodgeit-scb.cloudapps.iterashift.com",
        "false_positive": false
      }
    ]
  }
```

## Development

### Configuration Options
To configure this service specify the following environment variables:

| Environment Variable       | Value Example         |
| -------------------------- | --------------------- |
| ENGINE_ADDRESS             | http://engine         |
| ENGINE_BASIC_AUTH_USER     | username              |
| ENGINE_BASIC_AUTH_PASSWORD | 123456                |

### Local setup

1.  Clone the repository
2.  Install the dependencies `npm install`
3.  Run localy `npm start`

### Test

To run the testsuite run:

`npm test`

### Build with docker
To build the docker container run: `docker build -t CONTAINER_NAME:LABEL .`

[![Build Status](https://travis-ci.com/secureCodeBox/scanner-infrastructure-nmap.svg?branch=master)](https://travis-ci.com/secureCodeBox/scanner-infrastructure-nmap)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Known Vulnerabilities](https://snyk.io/test/github/secureCodeBox/scanner-infrastructure-nmap/badge.svg)](https://snyk.io/test/github/secureCodeBox/scanner-infrastructure-nmap)
[![GitHub release](https://img.shields.io/github/release/secureCodeBox/scanner-infrastructure-nmap.svg)](https://github.com/secureCodeBox/scanner-infrastructure-nmap/releases/latest)

[nmap.org]: https://nmap.org/
