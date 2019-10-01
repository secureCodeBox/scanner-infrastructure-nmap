/*
 * Vendored version of node-nmap (original license MIT)
 * Original Author:
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 */

// eslint-disable-next-line security/detect-child-process
const { spawn } = require('child_process');
const EventEmitter = require('events').EventEmitter;
const xml2js = require('xml2js');

/**
 *
 * @param {*} xmlInput
 * @param {*} onFailure
 * @returns {host[]} - Array of hosts
 */
function convertRawJsonToScanResults(xmlInput) {
    let tempHostList = [];

    if (!xmlInput.nmaprun.host) {
        //onFailure("There was a problem with the supplied NMAP XML");
        return tempHostList;
    }

    xmlInput = xmlInput.nmaprun.host;

    tempHostList = xmlInput.map(host => {
        const newHost = {
            hostname: null,
            ip: null,
            mac: null,
            openPorts: null,
            osNmap: null,
        };

        //Get hostname
        if (host.hostnames && host.hostnames[0] !== '\r\n' && host.hostnames[0] !== '\n') {
            newHost.hostname = host.hostnames[0].hostname[0].$.name;
        }

        //get addresses
        host.address.forEach(address => {
            const addressType = address.$.addrtype;
            const addressAdress = address.$.addr;
            const addressVendor = address.$.vendor;

            if (addressType === 'ipv4') {
                newHost.ip = addressAdress;
            } else if (addressType === 'mac') {
                newHost.mac = addressAdress;
                newHost.vendor = addressVendor;
            }
        });

        //get ports
        if (host.ports && host.ports[0].port) {
            const portList = host.ports[0].port;

            const openPorts = portList.filter(port => {
                return port.state[0].$.state !== 'closed';
            });

            newHost.openPorts = openPorts.map(portItem => {
                // console.log(JSON.stringify(portItem, null, 4))

                const port = parseInt(portItem.$.portid, 10);
                const protocol = portItem.$.protocol;
                const service = portItem.service[0].$.name;
                const serviceProduct = portItem.service[0].$.product;
                const serviceVersion = portItem.service[0].$.version;

                const tunnel = portItem.service[0].$.tunnel;
                const method = portItem.service[0].$.method;
                const product = portItem.service[0].$.tunnel;

                const state = portItem.state[0].$.state;

                let scriptOutputs = null;

                if (portItem.script) {
                    scriptOutputs = portItem.script.reduce((carry, { $: scriptRes }) => {
                        carry[scriptRes.id] = scriptRes.output;
                        return carry;
                    }, {});
                }

                let portObject = {};
                if (port) portObject.port = port;
                if (protocol) portObject.protocol = protocol;
                if (service) portObject.service = service;
                if (serviceProduct) portObject.serviceProduct = serviceProduct;
                if (serviceVersion) portObject.serviceVersion = serviceVersion;

                if (tunnel) portObject.tunnel = tunnel;
                if (method) portObject.method = method;
                if (product) portObject.product = product;

                if (state) portObject.state = state;

                if (scriptOutputs) portObject.scriptOutputs = scriptOutputs;

                return portObject;
            });
        }

        if (host.os && host.os[0].osmatch && host.os[0].osmatch[0].$.name) {
            newHost.osNmap = host.os[0].osmatch[0].$.name;
        }
        return newHost;
    });

    return tempHostList;
}

class NmapScan extends EventEmitter {
    constructor(range, inputArguments) {
        super();
        this.nmapVersion = null;
        this.command = [];
        this.nmapoutputXML = '';
        this.timer;
        this.range = [];
        this.arguments = ['-oX', '-'];
        this.rawData = '';
        this.rawJSON;
        this.child;
        this.cancelled = false;
        this.scanTime = 0;
        this.error = null;
        this.scanResults;
        this.scanTimeout = 0;
        this.commandConstructor(range, inputArguments);
        this.initializeChildProcess();
    }

    startTimer() {
        this.timer = setInterval(() => {
            this.scanTime += 10;
            if (this.scanTime >= this.scanTimeout && this.scanTimeout !== 0) {
                this.killChild();
            }
        }, 10);
    }

    stopTimer() {
        clearInterval(this.timer);
    }

    commandConstructor(range, additionalArguments) {
        if (additionalArguments) {
            if (!Array.isArray(additionalArguments)) {
                additionalArguments = additionalArguments.split(' ');
            }
            this.command = this.arguments.concat(additionalArguments);
        } else {
            this.command = this.arguments;
        }

        if (!Array.isArray(range)) {
            range = range.split(' ');
        }
        this.range = range;
        this.command = this.command.concat(this.range);
    }

    killChild() {
        this.cancelled = true;
        if (this.child) {
            this.child.kill();
        }
    }

    initializeChildProcess() {
        this.startTimer();
        this.child = spawn(nmap.nmapLocation, this.command);
        process.on('SIGINT', this.killChild);
        process.on('uncaughtException', this.killChild);
        process.on('exit', this.killChild);
        this.child.stdout.on('data', data => {
            if (data.indexOf('percent') > -1) {
                // console.log(data.toString());
            } else {
                this.rawData += data;
            }
        });

        this.child.on('error', err => {
            console.log('Nmap encountered an error.');
            console.log(err);
            console.log(`Error message "${err.message}"`);
            if (err.message.startsWith('RTTVAR has grown to over')) {
                console.log('RTTVAR Error, should hopefully be recoverable.');
                return;
            }

            this.killChild();
            if (err.code === 'ENOENT') {
                this.emit('error', 'NMAP not found at command location: ' + nmap.nmapLocation);
            } else {
                this.emit('error', err.Error);
            }
        });

        this.child.stderr.on('data', err => {
            this.error = err.toString();
        });

        this.child.on('close', () => {
            process.removeListener('SIGINT', this.killChild);
            process.removeListener('uncaughtException', this.killChild);
            process.removeListener('exit', this.killChild);

            if (this.error) {
                this.emit('error', this.error);
            } else if (this.cancelled === true) {
                this.emit('error', 'Over scan timeout ' + this.scanTimeout);
            } else {
                this.rawDataHandler(this.rawData);
            }
        });
    }

    startScan() {
        this.child.stdin.end();
    }

    cancelScan() {
        this.killChild();
        this.emit('error', 'Scan cancelled');
    }

    scanComplete(results) {
        this.scanResults = results;
        this.stopTimer();
        this.emit('complete', this.scanResults);
    }

    rawDataHandler(data) {
        let results;
        //turn NMAP's xml output into a json object
        xml2js.parseString(data, (err, result) => {
            if (err) {
                this.emit('error', 'Error converting XML to JSON in xml2js: ' + err);
            } else {
                this.rawJSON = result;
                this.nmapVersion = result.nmaprun.$.version;
                results = convertRawJsonToScanResults(this.rawJSON, err => {
                    this.emit(
                        'error',
                        'Error converting raw json to cleans can results: ' +
                            err +
                            ': ' +
                            this.rawJSON
                    );
                });
                this.scanComplete(results);
            }
        });
    }
}

let nmap = {
    nmapLocation: 'nmap',
    NmapScan,
};

module.exports = nmap;
