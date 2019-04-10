describe('results-xml', () => {
    it('should parse xml correctly', () => {
        const parse = require('./results-xml');
        const xmlFile = require('fs').readFileSync(
            __dirname + '/__test_data__/results-xml.test.xml',
            'utf8'
        );
        return parse(xmlFile).then(output => {
            console.log(JSON.stringify(output, null, 4));
            const scan = output.pop();
            expect(scan.hostname).toEqual('sample.host');
            expect(scan.ip).toEqual('8.8.8.8');
            expect(scan.scriptOutputs).toHaveProperty('http-headers');
            expect(scan.scriptOutputs['http-headers'].split('\n')).toHaveLength(14);
        });
    });
});
