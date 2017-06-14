//Initialization script, load and initialize all modules, all global variables are defined here
"use strict";

//=====Configuration=====
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

//=====Requests Handlers=====
//Replace these event handlers to change the behavior of Violentproxy
/**
 * REQUEST Requests patcher.
 * @var {Function}
 * @param {string} source - The referer URL, if exist. Undefined will be passed if it doesn't exist.
 * @param {string} destination - The requested URL.
 * @param {Buffer} payload - The raw POST request payload, since I can't make assumptions on what the server likes, I cannot have
 ** generic handle to beautify this.
 * @param {Header} headers - The headers object as reference, changes to it will be reflected.
 * @param {integer} id - The unique ID of this request. This can be used to associate later events of the same request. CONNECT request
 ** and its associated REQUEST request counts as two different requests.
 * @param {Function} callback - The function to call when a decision is made, the patcher can be either synchronous or asynchronous.
 ** @param {RequestDecision} result - The decision, refer to global.RequestDecision for more information.
 ** @param {Buffer|string} payload - The patched payload. If you changed it, you are also responsible in updating related headers.
 */
global.onRequest = (source, destination, payload, headers, id, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    void id;
    //This is just an example
    callback({ result: global.RequestDecision.Allow }, payload);
};
/**
 * CONNECT requests patcher. Refer to global.onRequest() for more information.
 * @var {Function}
 * @param {string} destination - The destination host and port.
 * @param {Function} callback - Refer to global.onRequest() for more information.
 */
global.onConnect = (destination, id, callback) => {
    //These parameters are not used
    void destination;
    void id;
    //This is just an example
    callback({ result: global.RequestDecision.Allow });
};
/**
 * Text responses patcher. Refer to global.onRequest() for more information.
 * @var {Function}
 * @param {string} text - The response text.
 * @param {Function} callback - Refer back to global.onRequest() for more information.
 ** @param {string} patchedText - The patched response text, if apply.
 */
global.onTextResponse = (() => {
    //Precompile RegExp
    const headMatcher = /(<head[^>]*>)/i;
    //Return closure function
    return (source, destination, text, headers, id, callback) => {
        //These parameters are not used
        void source;
        void destination;
        void headers;
        void id;
        //This is just an example
        callback(text.replace(headMatcher, `$1<script>console.log("Hello from Violentproxy :)")</script>`));
    };
})();
/**
 * Other responses (everything except text) patcher. Refer to global.onRequest() and global.onTestResponse() for more information.
 * @var {Function}
 * @param {Buffer} data - The response data. It could be still encoded, don't change it unless you plan to replace it.
 */
global.onOtherResponse = (source, destination, data, headers, id, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    void id;
    //This is just an example
    callback(data);
};

//=====WebSocket Handlers=====

global.onWebSocketConnect = () => {

};

//=====Initialization=====
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
     * Response patchers will not be triggered if redirecting to local resource.
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
//Other built in utilities
global.forge = require("node-forge");
global.zlib = require("zlib");
global.fs = require("fs");
//Other modules
global.publicsuffix = require("./Pulic Suffix/publicsuffixlist")
global.punycode = require("./Pulic Suffix/punycode.js");
global.agent = require("./Violentproxy/Violentagent");
global.tls = require("./Violentproxy/Violenttls");
//Load main code
global.engine = require("./Violentproxy/Violentengine");
//Initialize public suffix list
global.publicsuffix.parse(
    global.fs.readFileSync("./Pulic Suffix/public_suffix_list.dat.txt", "utf8"),
    punycode.toASCII,
);
//Start the proxy server
global.log("INFO", "Starting Violentproxy...");
global.engine.start(useTLS);
