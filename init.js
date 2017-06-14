//Initialization script, load and initialize all modules, all global variables are defined here
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
 * The default headers look like this:
Content-Type: text/html
Server: Apache/2.4.7 (Ubuntu)
 * I will try to detect what Content-Type should be, I'll default to "text/html" if I can't figure it out.
 * REQUEST requests patcher will be triggered after CONNECT requests patcher, there isn't much you can do
 * in CONNECT requests patcher because I don't have much information at that time.
 * @const {Enumeration}
 */
global.RequestDecision = {
    /**
     * Process the request normally. The response will be processed by response patcher later.
     * This is allowed in both REQUEST and CONNECT requests patcher.
     * No extra fields required.
     */
    Allow: 1,
    /**
     * Return a HTTP 200 response with an empty body.
     * This is only allowed in REQUEST requests patcher.
     * Pass in these extra fields when needed:
     * @param {Header} headers - The headers of the response, omit to use the default one.
     */
    Empty: 2,
    /**
     * Immediately close the connection.
     * This is allowed in both REQUEST and CONNECT requests patcher.
     * No extra fields required.
     */
    Deny: 3,
    /**
     * Redirect the request to another address or to a local resource, the user agent will not be able to know
     * the resource is redirected easily, a certificate for the originally requested host will be signed and used.
     * Note that the user agent can still figure it out from unexpected headers, use response patcher to fix the
     * headers if needed.
     * This is only allowed in REQUEST requests patcher.
     * Pass in these extra fields when needed:
     * @param {string} redirectLocation - The location to redirect, pass null for redirecting to a local resource, this
     ** field is required.
     * @param {string|Buffer} redirectText - The text to redirect to, this is only required if redirectLocation is null.
     * @param {Header} headers - The header of the response, this is only used if redirectLocation is null.
     ** Omit to use the default one.
     */
    Redirect: 4,
    /**
     * Directly connect the user agent to the remote server. I'll completely lose the control over what flows in this
     * pipe, no other events will be triggered for this pipe.
     * This is only allowed in CONNECT requests patcher.
     * No extra fields required.
     */
    Pipe: 5,
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
        default: throw new Error(`global.log() does not accept ${type} as type.`);
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
//Public suffix
const publicSuffixList = require("./Pulic Suffix/publicsuffixlist");
publicSuffixList.parse(
    global.fs.readFileSync("./Pulic Suffix/public_suffix_list.dat.txt", "utf8"),
    require("./Pulic Suffix/punycode.js").toASCII,
);
/**
 * Get a domain while considering public suffix.
 * @function
 * @param {string} host - The raw host name.
 * @return {string} The domain.
 */
global.toDomain = (host) => {

};

//Load main code
global.engine = require("./Violentproxy/Violentengine");
//Start the proxy server
global.log("INFO", "Starting Violentproxy...");
global.engine.start(useTLS);
