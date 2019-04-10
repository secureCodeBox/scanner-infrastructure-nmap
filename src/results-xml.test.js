it('should parse xml correctly', async () => {
    const parse = require('./results-xml');
    const xmlFile = require('fs').readFileSync(
        __dirname + '/__test_data__/results-xml.test.xml',
        'utf8'
    );
    const [httpPort, httpsPort] = await parse(xmlFile);

    expect(httpPort.hostname).toEqual('sample.host');
    expect(httpPort.ip).toEqual('8.8.8.8');
    expect(httpPort.scriptOutputs).toHaveProperty('http-headers');
    expect(httpPort.scriptOutputs['http-headers'].split('\n')).toHaveLength(10);

    expect(httpsPort.hostname).toEqual('sample.host');
    expect(httpsPort.ip).toEqual('8.8.8.8');
    expect(httpsPort.scriptOutputs).toHaveProperty('http-headers');
    expect(httpsPort.scriptOutputs['http-headers'].split('\n')).toHaveLength(14);
});

it('should parse xml without ports correctly', async () => {
    const parse = require('./results-xml');
    const xmlFile = require('fs').readFileSync(
        __dirname + '/__test_data__/empty-ports-xml.test.xml',
        'utf8'
    );
    const [host] = await parse(xmlFile);

    expect(host.hostname).toEqual('sample.host');
    expect(host.ip).toEqual('8.8.8.8');
});
