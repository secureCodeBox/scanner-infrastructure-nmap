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
const { transform, worker } = require('./nmap');
const uuid = require('uuid/v4');
const portscan = require('../lib/portscan');

jest.mock('../lib/portscan');

describe('nmap', () => {
    describe('transform', () => {
        beforeAll(() => {
            jest.mock('uuid/v4');
        });

        beforeEach(() => {
            uuid.mockClear();
        });

        afterAll(() => {
            jest.unmock('uuid/v4');
        });

        it('should transform a empty host array into an empty port array', () => {
            const findings = transform([]);

            expect(findings.length).toBe(0);
        });

        it('should transform a null host array into an empty port array', () => {
            const findings = transform(null);

            expect(findings.length).toBe(0);
        });

        it('should return a empty array if openPorts isnt set', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    osNmap: null,
                },
            ]);

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: securebox',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'securebox',
                attributes: {
                    ip_address: '192.168.99.100',
                    hostname: 'securebox',
                    operating_system: null,
                },
            });

            expect(findings.length).toBe(1);
        });

        it('should transform results of a single host into a port array', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    openPorts: [
                        {
                            port: 22,
                            protocol: 'tcp',
                            service: 'ssh',
                            serviceProduct: 'OpenSSH',
                            serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                            method: 'table',
                            state: 'open',
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: securebox',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'securebox',
                attributes: {
                    ip_address: '192.168.99.100',
                    hostname: 'securebox',
                    operating_system: null,
                },
            });
            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'ssh',
                description: 'Port 22 is open using tcp protocol.',
                category: 'Open Port',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'tcp://192.168.99.100:22',
                attributes: {
                    port: 22,
                    ip_address: '192.168.99.100',
                    protocol: 'tcp',
                    service: 'ssh',
                    serviceProduct: 'OpenSSH',
                    serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                    method: 'table',
                    hostname: 'securebox',
                    mac_address: null,
                    operating_system: null,
                    scripts: null,
                    state: 'open',
                    ostype: null,
                    conf: null,
                    extrainfo: null,
                },
            });
            expect(findings.length).toBe(2);
        });

        it('should transform results if a host has multiple open ports', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    openPorts: [
                        {
                            port: 22,
                            protocol: 'tcp',
                            service: 'ssh',
                            method: 'table',
                            state: 'open',
                            serviceProduct: 'OpenSSH',
                            serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                        },
                        {
                            port: 80,
                            protocol: 'udp',
                            service: 'http',
                            method: 'table',
                            state: 'open',
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: securebox',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'securebox',
                attributes: {
                    ip_address: '192.168.99.100',
                    hostname: 'securebox',
                    operating_system: null,
                },
            });
            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'ssh',
                description: 'Port 22 is open using tcp protocol.',
                category: 'Open Port',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'tcp://192.168.99.100:22',
                attributes: {
                    port: 22,
                    ip_address: '192.168.99.100',
                    protocol: 'tcp',
                    service: 'ssh',
                    serviceProduct: 'OpenSSH',
                    serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                    method: 'table',
                    hostname: 'securebox',
                    mac_address: null,
                    operating_system: null,
                    scripts: null,
                    state: 'open',
                    ostype: null,
                    conf: null,
                    extrainfo: null,
                },
            });

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'http',
                description: 'Port 80 is open using udp protocol.',
                category: 'Open Port',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'udp://192.168.99.100:80',
                attributes: {
                    port: 80,
                    ip_address: '192.168.99.100',
                    protocol: 'udp',
                    service: 'http',
                    serviceProduct: null,
                    serviceVersion: null,
                    method: 'table',
                    hostname: 'securebox',
                    mac_address: null,
                    operating_system: null,
                    scripts: null,
                    state: 'open',
                    ostype: null,
                    conf: null,
                    extrainfo: null,
                },
            });
            expect(findings.length).toBe(3);
        });

        it('should transform results of multiple hosts into a port array', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    openPorts: [
                        {
                            port: 22,
                            protocol: 'tcp',
                            service: 'ssh',
                            serviceProduct: 'OpenSSH',
                            serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                            method: 'table',
                            state: 'open',
                        },
                    ],
                    osNmap: null,
                },
                {
                    hostname: 'test',
                    ip: '192.168.99.101',
                    mac: null,
                    openPorts: [
                        {
                            port: 80,
                            protocol: 'udp',
                            service: 'http',
                            method: 'table',
                            state: 'open',
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: securebox',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'securebox',
                attributes: {
                    ip_address: '192.168.99.100',
                    hostname: 'securebox',
                    operating_system: null,
                },
            });
            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: test',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'test',
                attributes: {
                    ip_address: '192.168.99.101',
                    hostname: 'test',
                    operating_system: null,
                },
            });
            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'ssh',
                description: 'Port 22 is open using tcp protocol.',
                category: 'Open Port',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'tcp://192.168.99.100:22',
                attributes: {
                    port: 22,
                    ip_address: '192.168.99.100',
                    protocol: 'tcp',
                    service: 'ssh',
                    serviceProduct: 'OpenSSH',
                    serviceVersion: '7.2p2 Ubuntu 4ubuntu2.4',
                    method: 'table',
                    hostname: 'securebox',
                    mac_address: null,
                    operating_system: null,
                    scripts: null,
                    state: 'open',
                    ostype: null,
                    conf: null,
                    extrainfo: null,
                },
            });
            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'http',
                description: 'Port 80 is open using udp protocol.',
                category: 'Open Port',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'udp://192.168.99.101:80',
                attributes: {
                    port: 80,
                    ip_address: '192.168.99.101',
                    protocol: 'udp',
                    service: 'http',
                    serviceProduct: null,
                    serviceVersion: null,
                    method: 'table',
                    hostname: 'test',
                    mac_address: null,
                    operating_system: null,
                    scripts: null,
                    state: 'open',
                    ostype: null,
                    conf: null,
                    extrainfo: null,
                },
            });
            expect(findings.length).toBe(4);
        });

        it('should still kind of work if the openPorts attribute of the host is not an array', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    openPorts: null,
                    osNmap: null,
                    state: 'open',
                },
            ]);

            expect(findings).toContainEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'Host: securebox',
                description: 'Found a host',
                category: 'Host',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                location: 'securebox',
                attributes: {
                    ip_address: '192.168.99.100',
                    hostname: 'securebox',
                    operating_system: null,
                },
            });
            expect(findings.length).toBe(1);
        });
    });

    describe('worker', () => {
        beforeEach(() => {
            portscan.mockClear();
        });

        it('should work with a single target', async () => {
            const result = await worker([{ location: 'localhost' }]);

            expect(portscan).toBeCalledWith('localhost', '');

            expect(result).toMatchSnapshot();
        });

        it('should take parameters', async () => {
            const result = await worker([
                { location: 'localhost', attributes: { NMAP_PARAMETER: '-oX' } },
            ]);

            expect(portscan).toBeCalledWith('localhost', '-oX');

            expect(result).toMatchSnapshot();
        });

        it('should run multiple scans when multiple targets are configured', async () => {
            const result = await worker([
                { location: 'localhost' },
                { location: 'localhost', attributes: { NMAP_PARAMETER: '-oX' } },
            ]);

            expect(portscan).toHaveBeenCalledTimes(2);
            expect(portscan).toBeCalledWith('localhost', '');
            expect(portscan).toBeCalledWith('localhost', '-oX');

            expect(result).toMatchSnapshot();
        });

        it('should throw an error if a scan fails', async () => {
            portscan.mockReturnValueOnce(Promise.reject('Failed to scan properly.'));

            expect(worker([{ location: 'localhost' }])).rejects.toThrowErrorMatchingSnapshot();

            expect(portscan).toBeCalledWith('localhost', '');
        });

        it('should not throw an error if the hostname cannot be resolved', async () => {
            portscan.mockReturnValueOnce(
                Promise.reject(
                    'Failed to resolve "foobar".\nWARNING: No targets were specified, so 0 hosts scanned.'
                )
            );

            expect(await worker([{ location: 'foobar' }])).toEqual({
                raw: [''],
                result: [
                    {
                        id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                        name: 'Can not resolve host "foobar"',
                        description:
                            'The hostname cannot be resolved by DNS from the nmap scanner.',
                        category: 'Host Unresolvable',
                        attributes: {
                            hostname: 'foobar',
                        },
                        osi_layer: 'NETWORK',
                        severity: 'INFORMATIONAL',
                        location: 'foobar',
                    },
                ],
            });

            expect(portscan).toBeCalledWith('foobar', '');
        });
    });
});
