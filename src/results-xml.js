const xml2js = require('xml2js');
const _ = require('lodash');

/**
 * @typedef {{scanner:string,args:string,start:string,startstr:string,version:string,xmloutputversion:string}} nmaprunParams
 * @typedef {[{$: { type: string, protocol: string, numservices: string, services: string}}]} scaninfo
 * @typedef {[{$: { level: "string" }}]} levelDef
 * @typedef {[{$: {time: string, timestr: string, elapsed: string, summary: string, exit: string}}]} statsFinishedDef
 * @typedef {[{$: { up: string, down: string, total: string }}]} statsHostsDef
 * @typedef {[{ finished: statsFinishedDef, hosts: statsHostsDef}]} runstats
 * @typedef {{starttime: string, endtime: string}} hostTimings
 * @typedef {[{$: { state: string, reason: string, reason_ttl: string}}]} hostStatus
 * @typedef {[{$: { addr: string, addrtype: string}}]} hostAddress
 * @typedef {[{hostname: [{ $: { name: string, type: string}}]}]} hostnamesDef
 * @typedef {[{$: { srtt: string, rttvar: string, to: string }}]} hostTimesDef
 * @typedef {[{$:{state:string,reason:string,reason_ttl:string}}]} portStateDef
 * @typedef {[{$:{name:string,method:string,conf:string}}]} portServiceDef
 * @typedef {[{$: { id: string, output: string }}]} portScriptDef
 * @typedef {[{$:{protocol: string, portid: string}, state: portStateDef, service: portServiceDef, script: portScriptDef}]} portDef
 * @typedef {[{ $: hostTimings, status: hostStatus, address: hostAddress, hostnames: hostnamesDef, ports: [{port:portDef}], times: hostTimesDef }]} hostDef
 * @typedef {{ nmaprun: {$:nmaprunParams, scaninfo: scaninfo, verbose: levelDef, host: hostDef, debugging: levelDef, runstats: runstats } }} xmlDef
 * @typedef {{ ip: string, hostname: string, port: number, scriptOutputs: {[scriptName:string]:string} }} scriptInfo
 */

/**
 * @param {string} xml
 * @returns {Promise<xmlDef>}
 */
async function parseRawXml(xml) {
    return new Promise((resolve, reject) => {
        xml2js.parseString(xml, (err, parsed) => {
            if (err) reject(err);
            else resolve(parsed);
        });
    });
}

/**
 * @param {string} xml
 * @returns {Promise<[scriptInfo]>}
 */
async function getScriptOutputs(xml) {
    const parsed = await parseRawXml(xml);

    return _.flatMap(parsed.nmaprun.host, host => {
        const ip = _.get(host, ['address', 0, '$', 'addr']);
        const hostname = _.get(host, ['hostnames', 0, 'hostname', 0, '$', 'name']);
        const ports = _.get(host, ['ports', 0, 'port'], []);

        return ports
            .filter(port => port.script) // Only return ports with script outputs
            .map(port => {
                const scriptOutputs = port.script
                    //take only the xml attributes
                    .map(script => script.$)
                    //transform them into a map
                    .reduce((scripts, { id, output }) => {
                        scripts[id] = output;
                        return scripts;
                    }, {});

                return {
                    ip,
                    hostname,
                    port: _.toInteger(_.get(port, ['$', 'portid'])),
                    scriptOutputs,
                };
            });
    });
}

module.exports = getScriptOutputs;
