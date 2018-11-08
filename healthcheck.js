const http = require ('http');

const request = http.request ('http://localhost:8080/status', response => {

	// exit with error for any non 2xx status code
	process.exit (response.statusCode >= 300 ? 1 : 0);

	/*
	const dataChunks = [];

	response.on ('data', chunk => {
		dataChunks.push (chunk);
	});

	response.on ('close', () => {
		const txtResponse = Buffer.concat (dataChunks).toString ('utf8');
		const jsonResponse = JSON.parse (txtResponse);
		if (jsonResponse.healthcheck === 'DOWN') process.exit (1);
	});
	*/

});

request.end ();
