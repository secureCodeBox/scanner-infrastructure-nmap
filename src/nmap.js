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

/**
 * @typedef {{ id: string, name: string, description: string, osi_layer: string, reference: any, severity: string, attributes: { port: any, ip_address: any, mac_address: any, protocol: any, hostname: any, method: any, operating_system: any, service: any, scripts: [scriptname: string]: string }, hint: any, category: any, location: any }} Finding
 */

const _ = require('lodash');
const uuid = require('uuid/v4');

const portscan = require('../lib/portscan');

const resultsXmlParser = require('./results-xml');

function createFinding({
    id = uuid(),
    name,
    description,
    osi_layer = 'NETWORK',
    reference = null,
    severity = 'INFORMATIONAL',
    port = null,
    ip_address = null,
    mac_address = null,
    protocol = null,
    hostname = null,
    method = null,
    operating_system = null,
    service = null,
    hint = null,
    category = null,
    location = null,
}) {
    return {
        id,
        name,
        description,
        osi_layer,
        reference,
        severity,
        attributes: {
            port,
            ip_address,
            mac_address,
            protocol,
            hostname,
            method,
            operating_system,
            service,
            scripts: null,
        },
        hint,
        category,
        location,
    };
}

/**
 * Transforms the array of hosts into an array of open ports with host information included in each port entry.
 *
 * @param {array<host>} hosts An array of hosts
 * @returns {Finding[]}
 */
function transform(hosts) {
    return _.flatMap(hosts, ({ openPorts = [], ...hostInfo }) => {
        return _.map(openPorts, openPort => {
            return createFinding({
                name: openPort.service,
                description: `Port ${openPort.port} is open using ${openPort.protocol} protocol.`,
                port: openPort.port,
                ip_address: hostInfo.ip,
                mac_address: hostInfo.mac,
                protocol: openPort.protocol,
                hostname: hostInfo.hostname,
                method: openPort.method,
                operating_system: hostInfo.osNmap,
                service: openPort.service,
                category: 'Open Port',
                location: `${openPort.protocol}://${hostInfo.ip}:${openPort.port}`,
            });
        });
    });
}

/**
 *
 * @param {{ ip: string, hostname: string, port: number, scriptOutputs: {[scriptName:string]:string} }} findingFromXml
 * @param {Finding[]} findings
 */
function addScriptOutputsToFindings(findingFromXml, findings) {
    var res = findings.find(
        finding =>
            finding.attributes.port === findingFromXml.port &&
            finding.attributes.hostname === findingFromXml.hostname
    );
    if (res) {
        if (res.attributes.scripts === null) {
            res.attributes.scripts = findingFromXml.scriptOutputs;
        } else {
            Object.assign(res.attributes.scripts, findingFromXml.scriptOutputs);
        }
    } else {
        console.warn('found script outputs for ports that are not in the findings');
    }
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

            if (
                typeof parameter === 'string' &&
                (parameter.includes('--script=') || parameter.includes('-s'))
            ) {
                const findingsWithScriptOutput = await resultsXmlParser(raw);
                findingsWithScriptOutput.forEach(xmlFinding =>
                    addScriptOutputsToFindings(xmlFinding, result)
                );
            }

            results.push({ findings: result, raw });
        } catch (err) {
            var stringErr = extractErrorMessage(err);
            if (stringErr.startsWith(`Failed to resolve "${location}".`) || stringErr === '\n') {
                console.warn(err);
                results.push({
                    findings: [
                        createFinding({
                            name: `Canot resolve host "${location}"`,
                            description:
                                'The hostname cannot be resolved by DNS from the nmap scanner.',
                            hostname: location,
                            category: 'Host Unresolvable',
                            location,
                        }),
                    ],
                    raw: '',
                });
            } else if (err.startsWith('Error converting XML to JSON in xml2js')) {
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
