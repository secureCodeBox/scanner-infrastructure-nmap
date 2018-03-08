const SecureCodeBoxWorker = require('@securecodebox/securecodebox-worker');
const { worker } = require('./src/nmap');

const secureCodeBoxWorker = new SecureCodeBoxWorker({
    engineAddress: 'http://secureboxengine:8080/engine-rest',
    workername: 'nmap',
});

secureCodeBoxWorker.registerScanner(
    'nmap_portscan',
    ['nmap_target', 'nmap_parameter'],
    worker
);

secureCodeBoxWorker.startStatusServer();
