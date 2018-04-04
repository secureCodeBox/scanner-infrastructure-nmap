/*
 *
 *  SecureCodeBox (SCB)
 *  Copyright 2015-2018 iteratec GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */
const nodeNmap = require('node-nmap');
const _ = require('lodash');
const uuid = require('uuid/v4');

function portscan(target, params) {
    return new Promise((resolve, reject) => {
        const nmapscan = new nodeNmap.NmapScan(target, params);

        nmapscan.on('complete', hosts => resolve({ hosts, raw: nmapscan.rawData }));
        nmapscan.on('error', reject);

        nmapscan.startScan();
    });
}

/**
 * Transforms the array of hosts into an array of open ports with host information included in each port entry.
 *
 * @param {array<host>} hosts An array of hosts
 */
function transform(hosts = []) {
    return _.flatMap(hosts, ({ openPorts = [], ...hostInfo }) => {
        return _.map(openPorts, openPort => {
            return {
                id: uuid(),
                name: openPort.service,
                description: `Port ${openPort.port} is open using ${openPort.protocol} protocol.`,
                osi_layer: 'NETWORK',
                reference: null,
                severity: 'INFORMATIONAL',
                attributes: {
                    port: openPort.port,
                    ip_address: hostInfo.ip,
                    mac_address: hostInfo.mac,
                    protocol: openPort.protocol,
                    hostname: hostInfo.hostname,
                    method: openPort.method,
                    operating_system: hostInfo.osNmap,
                    service: openPort.service,
                },
                hint: null,
                category: 'Open Port',
                location: `${openPort.protocol}://${hostInfo.ip}:${openPort.port}`,
            };
        });
    });
}

async function worker({ NMAP_TARGET, NMAP_PARAMETER }) {
    try {
        const { hosts, raw } = await portscan(NMAP_TARGET, NMAP_PARAMETER);
        const result = transform(hosts);

        return { PROCESS_FINDINGS: JSON.stringify(result), PROCESS_RAW_FINDINGS: { content: raw } };
    } catch (err) {
        console.error(err);
        throw new Error('Failed to execute nmap portscan.');
    }
}

module.exports.transform = transform;
module.exports.worker = worker;
