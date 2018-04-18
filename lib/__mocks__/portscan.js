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
module.exports = jest.fn((target, params) =>
    Promise.resolve({
        hosts: [
            {
                hostname: 'localhost',
                ip: '127.0.0.1',
                mac: null,
                openPorts: [
                    { port: 631, protocol: 'tcp', service: 'ipp', method: 'table' },
                    {
                        port: 7778,
                        protocol: 'tcp',
                        service: 'interwise',
                        method: 'table',
                    },
                    {
                        port: 8080,
                        protocol: 'tcp',
                        service: 'http-proxy',
                        method: 'table',
                    },
                    {
                        port: 9200,
                        protocol: 'tcp',
                        service: 'wap-wsp',
                        method: 'table',
                    },
                ],
                osNmap: null,
            },
        ],
        raw: '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun></nmaprun>',
    })
);
