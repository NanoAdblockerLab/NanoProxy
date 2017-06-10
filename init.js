//Initialization script, all global variables are defined here
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
 * Whether or not the proxy server should be started in TLS mode, defaults to false.
 * Unless you are going to use the proxy on another device, there is no need to encrypt the connection
 * between your user agent and the proxy.
 * @const {boolean}
 */
const useTLS = false;
/**
 * The domains and IPs of the proxy server, must be set before the first run.
 * Depending on your system and user agent, IP entries might be ignored.
 * https://ca.godaddy.com/help/can-i-request-a-certificate-for-an-intranet-name-or-ip-address-6935
 * @const {Array.<string>}
 */
global.proxyDomains = ["localhost"];
global.proxyIPs = ["127.0.0.1"];
/**
 * The certificate for the proxy server, will be initialized when global.engine.start() is called.
 * @const {Certificate}
 */
global.localCert = null;
/**
 * Possible request decisions from request patcher.
 * @const {Enumeration}
 */
global.RequestDecision = {
    /**
     * Process the request normally. The response will be processed by response patcher later.
     * No extra fields required.
     */
    Allow: 1,
    /**
     * Return a HTTP 200 response with an empty body.
     * Pass in these extra fields when needed:
     * @param {string} type - The content type, defaults to one of the requested one.
     * @param {stirng} server - The server name, defaults to "Apache/2.4.7 (Ubuntu)".
     */
    Empty: 2,
    /**
     * Immediately close the connection.
     * No extra fields required.
     */
    Deny: 3,
    /**
     * Redirect the request to another address or to a local resource, the user agent will not be able to know
     * the resource is redirected easily, a certificate for the originally requested host will be signed and used.
     * Note that the user agent can still figure it out from unexpected headers, use response patcher to fix the
     * headers if needed.
     * The following extra fields must be passed:
     * @param {string} redirectLocation - The location to redirect, pass null for redirecting to a local resource.
     * @param {string|Buffer} redirectText - The text to redirect to, this is only required if redirectLocation is null.
     * @param {Header} headers - The header of the response, this is only used if redirectLocation is null. If this is not
     ** supplied, default headers will be used, they will be similar to the default headers of global.RequestDecision.Empty.
     */
    Redirect: 4,
};

/**
 * Log controller, always use this function instead of console.log().
 * @function
 * @param {integer} type - The type of the log, can be "ERROR", "WARNING", "NOTICE", or "INFO".
 * @param {Any} ...data - The data to log, pass as many items as you need, but there must be at least 1.
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
        default: throw new Error(`global.log() does not accept "${type}" as type.`);
    }
    if (!data.length) {
        throw new Error(`global.log() requires at least two arguments.`);
    }
    if (level <= logLevel) {
        data[0] = `${type}: ${data[0]}`;
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
//Start the proxy server
global.log("INFO", "Starting Violentproxy...");
global.engine.start(useTLS);
