const SecureCodeBoxWorker = require('@securecodebox/securecodebox-worker');
const { worker } = require('./src/nmap');

const secureCodeBoxWorker = new SecureCodeBoxWorker({
    engineAddress: 'http://localhost:8080/rest',
    workername: 'nmap',
});

secureCodeBoxWorker.registerScanner(
    'nmap_portscan',
    ['nmap_target', 'nmap_parameter'],
    worker
);

secureCodeBoxWorker.startStatusServer();
