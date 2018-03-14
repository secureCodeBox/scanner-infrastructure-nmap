const { transform } = require('./nmap');

describe('nmap', () => {
    describe('transform', () => {
        beforeAll(() => {
            jest.mock('uuid/v4');
        });

        afterAll(() => {
            jest.unmock('uuid/v4');
        });

        it('should transform a empty host array into an empty port array', () => {
            const findings = transform([]);

            expect(findings).toEqual([]);
        });

        it('should transform a null host array into an empty port array', () => {
            const findings = transform(null);

            expect(findings).toEqual([]);
        });

        it('should transform results of a single host into a port array', () => {
            const [finding, ...otherFindings] = transform([
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
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(otherFindings).toEqual([]);
            expect(finding).toEqual({
                id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
                name: 'ssh',
                description: 'Port 22 is open using tcp protocol.',
                category: 'Open Port',
                osiLayer: 'NETWORK',
                severity: 'INFORMATIONAL',
                reference: null,
                hint: null,
                location: 'tcp://192.168.99.100:22',
                attributes: {
                    port: 22,
                    ipAddress: '192.168.99.100',
                    protocol: 'tcp',
                    service: 'ssh',
                    method: 'table',
                    hostname: 'securebox',
                    macAddress: null,
                    operatingSystem: null,
                },
            });
        });

        xit('should transform results if a host has multiple open ports', () => {
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
                        },
                        {
                            port: 80,
                            protocol: 'tcp',
                            service: 'http',
                            method: 'table',
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(findings).toEqual([
                {
                    port: 22,
                    protocol: 'tcp',
                    service: 'ssh',
                    method: 'table',
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    osNmap: null,
                },
                {
                    port: 80,
                    protocol: 'tcp',
                    service: 'http',
                    method: 'table',
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    osNmap: null,
                },
            ]);
        });

        xit('should transform results of multiple hosts into a port array', () => {
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
                            protocol: 'tcp',
                            service: 'http',
                            method: 'table',
                        },
                    ],
                    osNmap: null,
                },
            ]);

            expect(findings).toEqual([
                {
                    port: 22,
                    protocol: 'tcp',
                    service: 'ssh',
                    method: 'table',
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    osNmap: null,
                },
                {
                    port: 80,
                    protocol: 'tcp',
                    service: 'http',
                    method: 'table',
                    hostname: 'test',
                    ip: '192.168.99.101',
                    mac: null,
                    osNmap: null,
                },
            ]);
        });

        xit('should still kind of work if the openPorts attribute of the host is not an array', () => {
            const findings = transform([
                {
                    hostname: 'securebox',
                    ip: '192.168.99.100',
                    mac: null,
                    openPorts: null,
                    osNmap: null,
                },
            ]);

            expect(findings).toEqual([]);
        });
    });
});
