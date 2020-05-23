#!/usr/bin/env node

"use strict";

const fs = require('fs');
const winston = require('winston');
const chalk = require('chalk');
const http = require('http');
const https = require('https');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const jwt = require('jsonwebtoken');

var privateKey;

const oneMinute = 1000 * 60;
const fiveMinutes = oneMinute * 5; // eslint-disable-line no-unused-vars
const tenMinutes = oneMinute * 10;

const CM1000EventLog = 'http://192.168.100.1/EventLog.asp';
const eventLogURL = CM1000EventLog;

const CM1000User = 'admin';
const CM1000Password = 'password';

// Wave appears to use local time at CMTS for timestamps
// Wave does not change their timestamps based on standard vs. daylight time.
// Because Javascript Date.getTimezoneOffset() will potentially change depending
// on standard vs. daylight time, we won't use that function. Instead, use a fixed offset.
// We want to communicate timestamps in UTC, so we'll do the conversion to UTC
// here before sending events to the back-end
const pstOffset = 1000*60*60*8;

const noSave = false;

const CM1000RegExp = /var xmlFormat = '(.*)'/;

const fetchEvents = fetchCM1000Events;

const auth = 'Basic ' + Buffer.from(CM1000User + ':' + CM1000Password).toString('base64');
const authHeader = {
    'Authorization': auth
};

const httpAgent = new http.Agent({
    keepAlive: true
});
const httpsAgent = new https.Agent({
    keepAlive: true
});

const options = {
    agent: function (_parsedURL) {
        if (_parsedURL.protocol == 'http:') {
            return httpAgent;
        } else {
            return httpsAgent;
        }
    },
    headers: authHeader
}

const logger = new(winston.createLogger)({
    level: 'info',
    transports: [
        new(winston.transports.Console)({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new(winston.transports.File)({
            filename: 'modem-scrape.log',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ]
});

function parseStringAsync(xmlString) {
    return new Promise(function (resolve, reject) {
        xml2js.parseString(xmlString, function (err, data) {
            if (err !== null) reject(err);
            else resolve(data);
        });
    });
}

async function fetchCM1000Events() {
    logger.info('====')
    logger.info('Fetching events from CM1000 modem at ' + new Date().toLocaleString());
    let needToRetry = true;
    while (needToRetry) {
        try {
            let response = await fetch(eventLogURL, options);
            if (response.status == 401) {
                logger.warn('Got 401 Unauthorized, retrying');
                continue;
            }
            needToRetry = false;
            let body = await response.text();
            let xmlString = body.match(CM1000RegExp)[1];
            let xml = await parseStringAsync(xmlString);
            let tableArray = xml.docsDevEventTable.tr
                .reverse()
                .map(element => {
                    if(element.docsDevEvCounts[0] != "1") {
                        logger.error("Got event count > 1")
                        // debugger;
                    };
                    let rElement = {};
                    // Not 'best practice' since modem events timestamps are not GMT
                    // But they're not local timezone either. They're (apparently) the timezone of the CMTS.
                    // And timezone isn't specified in the timestamp.
                    rElement.Time = new Date((Date.parse(element.docsDevEvFirstTime[0] + 'Z')).valueOf() + pstOffset);
                    rElement.Priority = element.docsDevEvLevel[0];
                    rElement.Description = element.docsDevEvText[0];
                    return rElement;
                });
            logger.info('Decoded ' + tableArray.length + ' entries from Event Log');
            let token = jwt.sign({ data: 'nothing to see here' }, privateKey, { expiresIn: 60 * 15, algorithm: 'RS256' });
            let postHeaders = {'Content-Type': 'applicaion/json', 'Authorization': `Bearer ${token}`};
            if (noSave)  {postHeaders['x-jay-nosave'] = 'hmm';};
            let postResponse = await fetch('https://joconor-modemlog.builtwithdark.com/log', {
                method: 'post',
                body: JSON.stringify(tableArray),
                headers: postHeaders
            });
            let responseJson = await postResponse.json();
            logger.info((responseJson.length == 0 ? (chalk.green('No')) : (chalk.bgRed(responseJson.length))) + ' events to add to database');
            if(responseJson.length != 0) {
                logger.info('Oldest: ' + responseJson[0].time + ' Newest: ' + responseJson[responseJson.length -1].time);
            }            
        } catch (e) {
            logger.error(e);
            // Not sure why, but on MacOS, every other fetch from SB8200 gets ECONNRESET
            if (!(e.name === 'FetchError' && e.code === 'ECONNRESET')) {
                needToRetry = false;
            }
        }
    }
}

(async () => {
    try {
        privateKey = fs.readFileSync('jwtRS256.key');
        // Do it once, then every ten minutes
        await fetchEvents();
        setInterval(fetchEvents, tenMinutes);

    } catch (e) {
        logger.error("Exception caught at top level: " + e);
    }

})();