//Load modules to global scope and start Violentproxy
"use strict";

/**
 * Log level configuration.
 * 0: Complete silence, not recommended.
 * 1: Errors only.
 * 2: Errors and warnings.
 * 3: Errors, warnings, and notices.
 * 4: Errors, warnings, notices, and info, this is default.
 * @const {integer}
 */
const logLevel = 4;
/**
 * Subject alternative names for the certificate authority, must be set before the first run.
 * More information:
 * https://github.com/digitalbazaar/forge/blob/80c7fd4e21ae83fa236ebb6a2f4748d54aa0dec0/lib/x509.js#L1594
 */
global.CAaltNames = [
    {
        type: 2, //Domain name or DNS name
        value: "localhost",
    },
    {
        type: 7, //IP
        ip: "127.0.0.1",
    },
];
//Other global variables:
//global.CA: The certificate authority root certificate
//global.CAcert: The certificate authority root certificate in a format that https.createServer() expects
//global.RequestDecision: The available decisions for the request patcher, more information can be found
//in ./Violentproxy/Violentengine.js

/**
 * Log controller, always use this function and not console.log().
 * @function
 * @param {integer} level - The level of the log, 1 for error, 2 for warning, 3 for notice, and 4 for info.
 * @param {Any} ...data - The data to log. Append as many arguments as you need.
 */
global.log = (type, ...data) => {
    let level;
    switch (type) {
        case "ERROR": level = 1; break;
        case "WARNING": level = 2; break;
        case "NOTICE": level = 3; break;
        case "INFO": level = 4; break;
        default: throw new TypeError(`"${type}" is not a valid type.`);
    }
    if (level <= logLevel) {
        console.log(type + data.shift(), ...data);
    }
};

//Packages are loaded to global scope so my modules can share them
global.log("INFO", "Loading modules...");

//Network utilities
global.https = require("https");
global.http = require("http");
global.net = require("net");
global.url = require("url");
global.ws = require("ws");

//Other utilities
global.forge = require("node-forge");
global.zlib = require("zlib");
global.fs = require("fs");

//Custom modules
global.agent = require("./Violentproxy/Violentagent");
global.tls = require("./Violentproxy/Violenttls");

//Load main code
global.engine = require("./Violentproxy/Violentengine");

//Start a simple proxy server
console.log("INFO: Starting Violentproxy...");
//global.engine.start(true);
global.engine.start();
