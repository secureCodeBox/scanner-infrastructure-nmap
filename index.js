const ScannerScaffolding = require('@securecodebox/scanner-scaffolding');
const { worker } = require('./src/nmap');

const scannerScaffolding = new ScannerScaffolding({
    engineAddress: 'http://localhost:8080/rest',
    workername: 'nmap',
});

scannerScaffolding.registerScanner(
    'nmap_portscan',
    ['nmap_target', 'nmap_parameter'],
    worker
);

scannerScaffolding.startStatusServer();
