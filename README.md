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
This repository contains a self contained µService utilizing the NMAP Networkscanner for the secureCodeBox project. To learn more about the Nmap scanner itself visit [nmap.org].

## Nmap Configuration

The nmap scan target is set via the targets location of the securityTest. The target should be a Hostname or an IP Address.

Additional nmap scan features can be configured via the `NMAP_PARAMTER` attribute. For a detailed explanation to which parameters are availible refer to the [Nmap Reference Guide](https://nmap.org/book/man.html).

Some usefull example parameters listed below:

* `-p` xx: Scan ports of the target. Replace xx with a single port number or
a range of ports.
* `-PS`, `-PA`, `-PU` xx: Replace xx with the ports to scan. TCP SYN/ACK or 
UDP discovery.
* `-sV`: Determine service and version info.
* `-O`: Determine OS info. **Note:** This requires the the user to be run as root or the system capabilities to be extended to allow nmap to send raw sockets. See more information on [how to deploy the secureCodeBox nmap container to allow this](https://github.com/secureCodeBox/scanner-infrastructure-nmap/pull/20) and the [nmap docs about priviliged scans](https://secwiki.org/w/Running_nmap_as_an_unprivileged_user)
* `-A`: Determine service/version and OS info.
* `-script` xx: Replace xx with the script name. Start the scan with the given script.
* `--script` xx: Replace xx with a coma-separated list of scripts. Start the scan with the given scripts.


## Example

Example configuration:

```json
[
    {
        "name": "nmap",
        "context": "BodgeIt",
        "target": {
            "name": "BodgeIt",
            "location": "bodgeit.example.com",
            "attributes": {
                "NMAP_PARAMTER": "-Pn"
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
                "ip_address": "192.168.0.1",
                "mac_address": null,
                "protocol": "tcp",
                "hostname": "bodgeit.example.com",
                "method": "table",
                "operating_system": null,
                "service": "http",
                "serviceProduct": null,
                "serviceVersion": null,
                "scripts": null
            },
            "location": "tcp://192.168.0.1:80",
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
                "ip_address": "192.168.0.1",
                "mac_address": null,
                "protocol": "tcp",
                "hostname": "bodgeit.example.com",
                "method": "table",
                "operating_system": null,
                "service": "https",
                "serviceProduct": null,
                "serviceVersion": null,
                "scripts": null
            },
            "location": "tcp://192.168.0.1:443",
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
                "ip_address": "192.168.0.1",
                "mac_address": null,
                "protocol": "tcp",
                "hostname": "bodgeit.example.com",
                "method": "table",
                "operating_system": null,
                "service": "https-alt",
                "serviceProduct": null,
                "serviceVersion": null,
                "scripts": null
            },
            "location": "tcp://192.168.0.1:8443",
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
                "ip_address": "192.168.0.1",
                "mac_address": null,
                "protocol": "tcp",
                "hostname": "bodgeit.example.com",
                "method": "table",
                "operating_system": null,
                "service": "dynamid",
                "serviceProduct": null,
                "serviceVersion": null,
                "scripts": null
            },
            "location": "tcp://192.168.0.1:9002",
            "false_positive": false
        },
        {
            "id": "c98330a6-b2b3-4d12-b0f5-d41af0a13dbe",
            "name": "Host: bodgeit.example.com",
            "description": "Found a host",
            "category": "Host",
            "osi_layer": "NETWORK",
            "severity": "INFORMATIONAL",
            "attributes": {
                "ip_address": "192.168.0.1",
                "hostname": "bodgeit.example.com",
                "operating_system": null
            },
            "location": "bodgeit.example.com",
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
