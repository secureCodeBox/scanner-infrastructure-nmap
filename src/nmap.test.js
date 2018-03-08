const { transform } = require('./nmap');

describe('nmap', () => {
    describe('transform', () => {
        it('should transform a empty host array into an empty port array', () => {
            const findings = transform([]);

            expect(findings).toEqual([]);
        });

        it('should transform a null host array into an empty port array', () => {
            const findings = transform(null);

            expect(findings).toEqual([]);
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
            ]);
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

        it('should still kind of work if the openPorts attribute of the host is not an array', () => {
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
