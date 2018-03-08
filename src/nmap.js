const nodeNmap = require('node-nmap');
const _ = require('lodash');

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
            return {
                ...hostInfo,
                ...port,
            };
        });
    });

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
