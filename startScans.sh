#!/bin/bash
for i in {1..5}
do
   curl -X PUT "http://localhost:8080/box/securityTests" -H "accept: application/json" -H "Content-Type: application/json" -d "[ { \"context\": \"parralel debugging\", \"metaData\": {}, \"name\": \"nmap\", \"target\": { \"attributes\": { \"NMAP_PARAMETER\": \"\" }, \"location\": \"127.0.0.1\", \"name\": \"localhost\" }, \"tenant\": null }]" -u kermit:a
done
