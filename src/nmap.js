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

const _ = require('lodash');
const uuid = require('uuid/v4');

const portscan = require('../lib/portscan');
/**
 * Transforms the array of hosts into an array of open ports with host information included in each port entry.
 *
 * @param {Hosty[]} hosts An array of hosts
 * @returns {Finding[]}
 */
function transform(hosts) {
    const portFindings = _.flatMap(hosts, ({ openPorts = [], ...hostInfo }) => {
        return _.map(openPorts, openPort => {
            console.log(`creating finding for port "${openPort.port}"`);
            return {
                id: uuid(),
                name: openPort.service,
                description: `Port ${openPort.port} is ${openPort.state} using ${openPort.protocol} protocol.`,
                category: 'Open Port',
                location: `${openPort.protocol}://${hostInfo.ip}:${openPort.port}`,
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                attributes: {
                    port: openPort.port,
                    state: openPort.state,
                    ip_address: hostInfo.ip,
                    mac_address: hostInfo.mac,
                    protocol: openPort.protocol,
                    hostname: hostInfo.hostname,
                    method: openPort.method,
                    operating_system: hostInfo.osNmap,
                    service: openPort.service,
                    scripts: openPort.scriptOutputs || null,
                },
            };
        });
    });

    const hostFindings = _.map(hosts, ({ hostname, ip, osNmap }) => {
        return {
            id: uuid(),
            name: `Host: ${hostname}`,
            category: 'Host',
            description: 'Found a host',
            location: hostname,
            severity: 'INFORMATIONAL',
            osi_layer: 'NETWORK',
            attributes: {
                ip_address: ip,
                hostname: hostname,
                operating_system: osNmap,
            },
        };
    });

    return [...portFindings, ...hostFindings];
}

function joinResults(results) {
    const findings = _.flatMap(results, result => result.findings);
    const rawFindings = _.map(results, result => result.raw);

    return {
        result: findings,
        raw: rawFindings,
    };
}

async function worker(targets) {
    const results = [];
    console.log(`SCANNING ${targets.length} locations`);
    for (const { location, attributes } of targets) {
        try {
            const parameter = _.get(attributes, ['NMAP_PARAMETER'], '');

            if (location.startsWith('-')) {
                console.warn(
                    `Skipping the target '${location}', targets starting with an '-' would be picked up as an nmap arg.`
                );
                continue;
            }

            console.log(`SCANNING location: "${location}", parameters: "${parameter}"`);
            const { hosts, raw } = await portscan(location, parameter);
            const result = transform(hosts);
            console.log(`FOUND: "${result.length}" findings`);

            results.push({ findings: result, raw });
        } catch (err) {
            const stringErr = extractErrorMessage(err);
            if (stringErr.startsWith(`Failed to resolve "${location}".`) || stringErr === '\n') {
                console.warn(err);
                results.push({
                    findings: [
                        {
                            id: uuid(),
                            name: `Can not resolve host "${location}"`,
                            description:
                                'The hostname cannot be resolved by DNS from the nmap scanner.',
                            category: 'Host Unresolvable',
                            location,
                            severity: 'INFORMATIONAL',
                            osi_layer: 'NETWORK',
                            attributes: {
                                hostname: location,
                            },
                        },
                    ],
                    raw: '',
                });
            } else if (stringErr.startsWith('Error converting XML to JSON in xml2js')) {
                const error = new Error('Failed to transform nmap xml to json.');
                error.name = 'TransformationError';
                throw error;
            } else {
                console.error(err);
                throw new Error('Failed to execute nmap portscan.');
            }
        }
    }

    return joinResults(results);
}

function extractErrorMessage(err) {
    if (err.message) return err.message;
    if (err.toString) return err.toString();
    return '' + err;
}

module.exports.transform = transform;
module.exports.worker = worker;
