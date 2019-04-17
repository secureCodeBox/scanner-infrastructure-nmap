try {
    require('http')
        .request('http://localhost:8080/status', response => {
            // exit with error for any non 2xx status code
            process.exit(response.statusCode >= 300 ? 1 : 0);
        })
        .end();
} catch (err) {
    process.exit(1);
}
