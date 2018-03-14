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
 * Transforms a array of hosts to a array of open ports with the host information included in the port entry
 *
 * @param {array<host>} hosts A array of hosts
 */
function transform(hosts = []) {
    if (!hosts) {
        return [];
    }

    const findings = _.flatMap(hosts, ({ openPorts = [], ...hostInfo }) => {
        if (!openPorts) {
            return [];
        }

        return openPorts.map(port => {
            return { ...hostInfo, ...port };
        });
    }).map(finding => ({
        id: uuid(),
        name: finding.service,
        description: `Port ${finding.port} is open using ${
            finding.protocol
        } protocol.`,
        osiLayer: 'NETWORK',
        reference: null,
        severity: 'INFORMATIONAL',
        attributes: {
            port: finding.port,
            ipAddress: finding.ip,
            macAddress: finding.mac,
            protocol: finding.protocol,
            hostname: finding.hostname,
            method: finding.method,
            operatingSystem: finding.osNmap,
            service: finding.service,
        },
        hint: null,
        category: 'Open Port',
        location: `${finding.protocol}://${finding.ip}:${finding.port}`,
    }));

    return findings;
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
