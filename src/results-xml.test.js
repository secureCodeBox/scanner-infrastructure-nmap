describe('results-xml', () => {
    it('should parse xml correctly', () => {
        const parse = require('./results-xml');
        const xmlFile = require('fs').readFileSync(__dirname + '/results-xml.test.xml', 'utf8');
        parse(xmlFile)
            .then(output => {
                console.log(JSON.stringify(output, null, 4));
                expect(xmlFile).toEqual('');
            })
            .catch(err => {
                throw err;
            });
    });
});
