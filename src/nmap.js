const nodeNmap = require('node-nmap');
const _ = require('lodash');
const uuid = require('uuid/v4');

function portscan(target, params) {
    return new Promise((resolve, reject) => {
        const nmapscan = new nodeNmap.NmapScan(target, params);

        nmapscan.on('complete', resolve);
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
                osiLayer: 'NETWORK',
                reference: null,
                severity: 'INFORMATIONAL',
                attributes: {
                    port: openPort.port,
                    ipAddress: hostInfo.ip,
                    macAddress: hostInfo.mac,
                    protocol: openPort.protocol,
                    hostname: hostInfo.hostname,
                    method: openPort.method,
                    operatingSystem: hostInfo.osNmap,
                    service: openPort.service,
                },
                hint: null,
                category: 'Open Port',
                location: `${openPort.protocol}://${hostInfo.ip}:${openPort.port}`,
            };
        });
    });
}

async function worker({ nmap_target, nmap_parameter }) {
    try {
        const hosts = await portscan(nmap_target, nmap_parameter);
        const result = transform(hosts);

        return { raw: hosts, result: { content: result } };
    } catch (err) {
        console.trace(err);
        throw new Error('Failed to execute nmap portscan.');
    }
}

module.exports.transform = transform;
module.exports.worker = worker;
