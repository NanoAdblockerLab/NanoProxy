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
 * Whether or not the proxy server itself should be started with encryption.
 * @const {boolean}
 */
const useTLS = false;
/**
 * The domains and IPs of the proxy server, must be set before the first run.
 * @const {Array.<string>}
 */
global.proxyDomains = ["localhost"];
global.proxyIPs = ["127.0.0.1"];
//Other global variables:
//global.localCert: The certificate for the proxy server itself
//global.RequestDecision: The available decisions for the request patcher, more information can be found
//                        in ./Violentproxy/Violentengine.js

/**
 * Log controller, always use this function instead of console.log().
 * @function
 * @param {integer} level - The level of the log, 1 for error, 2 for warning, 3 for notice, and 4 for info.
 * @param {Any} ...data - The data to log. Append as many arguments as you need.
 */
global.log = (type, ...data) => {
    //Skip the calculation if in silent mode
    if (logLevel === 0) {
        return;
    }
    //Process the log and print to screen
    let level;
    switch (type) {
        case "ERROR": level = 1; break;
        case "WARNING": level = 2; break;
        case "NOTICE": level = 3; break;
        case "INFO": level = 4; break;
        default: throw new Error(`global.log() does not accept "${type}" as a valid type.`);
    }
    if (!data.length) {
        throw new Error(`global.log() requires at least two arguments.`);
    }
    if (level <= logLevel) {
        data[0] = type + data[0];
        console.log(...data);
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
global.log("INFO", "Starting Violentproxy...");
global.engine.start(useTLS);
