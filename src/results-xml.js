const xml2js = require('xml2js');
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
    return new Promise((resolve, reject) => {
        parseRawXml(xml)
            .then(parsed => {
                /**
                 * @type {Array<scriptInfo>}
                 */
                const results = [];

                parsed.nmaprun.host.forEach(host => {
                    var ip = null,
                        hostname = null;
                    try {
                        ip = host.address[0].$.addr;
                    } catch (err) {
                        console.error(err);
                    }
                    try {
                        hostname = host.hostnames[0].hostname[0].$.name;
                    } catch (err) {
                        console.error(err);
                    }
                    if (host.ports[0].port) {
                        host.ports[0].port.forEach(port => {
                            if (port.script) {
                                port.script.forEach(script => {
                                    var scriptName = script.$.id,
                                        scriptOutput = script.$.output;
                                    var portId = parseInt(port.$.portid);
                                    var resultsEntry = results.find(
                                        check =>
                                            check.port === portId &&
                                            check.hostname === hostname &&
                                            check.ip === ip
                                    );
                                    if (!resultsEntry) {
                                        results.push(
                                            (resultsEntry = {
                                                hostname,
                                                ip,
                                                port: portId,
                                                scriptOutputs: {},
                                            })
                                        );
                                    }
                                    resultsEntry.scriptOutputs[scriptName] = scriptOutput;
                                });
                            }
                        });
                    }
                });
                resolve(results);
            })
            .catch(reject);
    });
}

module.exports = getScriptOutputs;
