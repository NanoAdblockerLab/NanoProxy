//Core engine for Violentproxy
"use strict";

/**
 * Load network modules.
 * @const {Module}
 */
const {https, http, net, url} = global;
/**
 * Load other modules
 * @const {Module}
 */
const {agent, zlib, tls} = global;

/**
 * Get MIME type from header.
 * @param {string} str - The encoding related header entry.
 * @param {string} [def="text/html"] - The default value.
 */
const getType = (str, def = "text/html") => {
    const parts = str.split(/,|;/);
    for (let i = 0; i < parts.length; i++) {
        if (!parts[i].includes("*") && parts[i].includes("/")) {
            return parts[i].trim();
        }
    }
    return def;
};
/**
 * Check if given MIME type is text.
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
 * @param {string} mimeType - The MIME type to check.
 */
const isText = (mimeType) => {
    if (!mimeType) {
        //Assume not text if the server didn't send over the content type
        return false;
    } else {
        return mimeType.startsWith("text/") || mimeType.endsWith("/xhtml+xml") || mimeType.endsWith("/xml");
    }
};

/**
 * Proxy engine for REQUEST request.
 * In this mode, the user agent gives me the full control, so I don't need to create servers on the fly.
 * This is generally used for HTTP requests.
 * TODO: Add WebSocket and WebSocket Secure handling.
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {ServerResponse} localRes - The local response object.
 */
let requestEngine = (localReq, localRes) => {
    //TODO: What about WebSocket?
    console.log(`INFO: REQUEST request received: ${localReq.url}`);
    //Prepare request
    let options
    try {
        options = url.parse(localReq.url);
    } catch (err) {
        //This is a bad request, but to prevent proxy detection, I'll just drop the connection
        localRes.destroy();
        return;
    }
    //Process options
    options.headers = localReq.headers;
    options.agent = agent.getAgent(localReq.httpVersion, localReq.headers, options.protocol === "https:");
    options.auth = localReq.auth;
    //Handle internal request loop
    //As I can't easily find out what is my common name, the first request will backloop internally
    //This isn't the most efficient way to handle it, but should be good enough if Userscripts don't spam the API
    if (!localReq.url[0] === "/") {
        //TODO: Change this to handle Userscripts API
        localRes.writeHead(500, "Not Implemented", {
            "Content-Type": "text/plain",
            "Server": "Violentproxy Proxy Server",
        });
        localRes.write("Userscript callback is not implemented.");
        localRes.end();
        return;
    }
    //Patch the request
    exports.onRequest(localReq.headers["referer"], localReq.url, localReq.headers, (requestResult) => {
        //Further process headers so response from remote server can be parsed
        localReq.headers["accept-encoding"] = "gzip, deflate";
        switch (requestResult.result) {
            case exports.RequestResult.Allow:
                //Do nothing, let the request pass
                break;
            case exports.RequestResult.Empty:
                localRes.writeHead(200, "OK", {
                    "Content-Type": requestResult.type || getType(localReq.headers["accept"]),
                    "Server": requestResult.server || "Apache/2.4.7 (Ubuntu)",
                });
                localRes.end();
                return; //Stop here
            case exports.RequestResult.Deny:
                localRes.destroy();
                return; //Stop here
            case exports.RequestResult.Redirect:
                if (requestResult.redirectLocation === null) {
                    //Just write back the redirected text
                    localRes.writeHead(200, "OK", requestResult.headers || {
                        "Content-Type": "text/plain",
                        "Server": "Apache/2.4.7 (Ubuntu)",
                    });
                    localRes.write(requestResult.redirectText);
                    localRes.end();
                    return;
                } else {
                    //I expect the patcher to return valid URL
                    options = url.parse(requestResult.redirectLocation);
                    //Copy the rest of the options again
                    options.headers = localReq.headers;
                    options.agent = agent.getAgent(localReq.httpVersion, localReq.headers, options.protocol === "https:");
                    options.auth = localReq.auth;
                    break;
                }
            default:
                throw "Unexpected request result";
        }
        //Proxy request
        let request = (options.protocol === "https:" ? https : http).request(options, (remoteRes) => {
            //remoteRes is http.IncomingMessage, which is also a Stream
            let data = [];
            remoteRes.on("data", (chunk) => {
                data.push(chunk);
            });
            remoteRes.on("end", () => {
                data = Buffer.concat(data);
                //Check content type, I can only patch text
                //I'm able to change the header of non-text response though
                if (isText(getType(remoteRes.headers["content-type"]))) {
                    //Check encoding
                    let encoding = remoteRes.headers["content-encoding"];
                    if (encoding) {
                        encoding = encoding.toLowerCase();
                    }
                    //So I don't need to encode it again
                    remoteRes.headers["content-encoding"] = "identity";
                    if (encoding === "gzip" || encoding === "deflate") {
                        zlib.unzip(data, (err, result) => {
                            if (err) {
                                //Could not parse, drop the connection
                                localRes.destroy();
                            } else {
                                requestEngine.finalize(localRes, remoteRes, localReq.headers["referer"], localReq.url, true, result);
                            }
                        });
                    } else {
                        //Assume identity
                        requestEngine.finalize(localRes, remoteRes, localReq.headers["referer"], localReq.url, true, data);
                    }
                } else {
                    //Not text
                    requestEngine.finalize(localRes, remoteRes, localReq.headers["referer"], localReq.url, false, data);
                }
            });
            remoteRes.on("error", () => {
                //Something went wrong, drop the local connection
                localRes.destroy();
            });
            remoteRes.on("aborted", () => {
                //Remote server disconnected prematurely, drop the local connection
                localRes.destroy();
            });
        });
        request.on("error", (err) => {
            console.log(`WARNING: An error occurred when handling REQUEST request to ${localReq.url}, this usually means ` +
                `the client sent an invalid request or you are not connected to the Internet.`);
            console.log(err.message);
            localRes.destroy();
        });
        request.end();
        //Abort request when local client disconnects
        localReq.on("aborted", () => { request.abort(); });
    });
};
/**
 * Process final request result of a REQUEST request and send it to client.
 * @function
 * @param {http.ServerResponse} localRes - The object that can be used to respond client request.
 * @param {http.IncomingMessage} remoteRes - The object that contains data about server response.
 * @param {string} referer - The referrer, if exist.
 * @param {string} url - The request URL.
 * @param {boolean} isText - Whether the response data is text.
 * @param {Any} responseData - The response data.
 */
requestEngine.finalize = (localRes, remoteRes, referer, url, isText, responseData) => {
    const onDone = () => {
        remoteRes.headers["content-length"] = responseData.length;
        localRes.writeHead(remoteRes.statusCode, remoteRes.statusMessage, remoteRes.headers);
        localRes.write(responseData);
        localRes.end();
    };
    if (isText) {
        exports.onResponse(referer, url, responseData.toString(), remoteRes.headers, (patchedData) => {
            responseData = patchedData;
            onDone();
        });
    } else {
        exports.onResponse(referer, url, null, remoteRes.headers, () => {
            onDone();
        });
    }
};

/**
 * Available TLS servers, they are used to proxy encrypted CONNECT requests.
 * A server key must be like "example.com".
 * TODO: Add a timer that removes servers when they are not used for extended amount of time.
 * @var {Dictionary.<Server>}
 */
let runningServers = [];
/**
 * Server object, this prevents issues that can be caused in race condition.
 * TODO: Add WebSocket and WebSocket Secure handling.
 * TODO: Implement this.
 * @class
 */
const Server = class {
    /**
     * Construct the object and initialize the server.
     * @constructor
     * @param {string} domain - The domain, must be something like "example.com".
     * 
     */
    constructor(domain) {
        this.available = false;
        this.server = null;
        this.onceAvailableCallback = [];
        tls.sign(domain, (cert) => {
            this.server = https.createServer(cert);
        });
    }
    /**
     * Schedule a function to call once the server is available again.
     * @method
     * @param {Function} func - The function to call.
     */
    onceAvailable(func) {

    }
};
/**
 * Dynamic server, this server uses SNI to server all HTTPS request to SNI capable clients.
 * @class
 */
const DynamicServer = class {
    /**
     * The constructor for SNI server.
     * @constructor
     */
    constructor() {
        this.available = false;
        this.server = https.createServer({});
        this.onceAvailableCallback = [];
    }
};
/**
 * Get a TLS server for the current host name.
 * TODO: Test out if Chrome like our shortcut, we are not checking public suffix.
 * @param {string} host - The current host name.
 * @param {Function} callback - The function to call when a TLS server is ready.
 ** @param {boolean} success - Whether host name is valid, a server will be supplied if the host name is valid.
 ** @param {TLSServer} server - A TLS server for the current host name.
 */
const getServer = (host, callback) => {
    let parts = host.split(".");
    let domain;
    if (parts.length < 2) {
        if (host === "localhost") {
            //TODO: Userscript callback in TLS mode
            throw "Not implemented";
        } else {
            //Host name not valid
            process.nextTick(() => {
                callback(false);
            });
        }
    } else if (parts.lengh === 2) {
        domain = host;
    } else {
        parts.shift();
        domain = parts.join(".");
    }
    //Check if I already have a server
    if (!runningServers[domain]) {
        //Create new one
        runningServers[domain] = new Server(domain);
        runningServers[domain].onceAvailable(() => {
            callback(true, runningServers[domain].server);
        });
    } else if (!runningServers[domain].available) {
        runningServers[domain].onceAvailable(() => {
            callback(true, runningServers[domain].server);
        });
    } else {
        process.nextTick(() => {
            callback(true, runningServers[domain].server);
        });
    }
};

//Initialize SNI server
runningServers["dynamic"] = new DynamicServer();

/**
 * Proxy engine for CONNECT requests.
 * In this mode, the user agent will ask me to establish a tunnel to the target host. As I can't decrypt the data that is going over,
 * I have to create a local server to make the user agent to believe it is speaking to a real server.
 * I need to create a server for each domain, the server for "example.com" can serve requests to "example.com" and "*.example.com",
 * but not "*.www.example.com".
 * This is generally used for HTTPS.
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {Socket} localSocket - The local socket, the user agent will ask me to connect this to a socket of the remote server,
 ** but obviously I will connect it to a local server instead.
 * @param {Buffer} localHead - The begining of message, this may or may not be present.
 */
let connectEngine = (localReq, localSocket, localHead) => {
    //If I think it's OK to give up control over the communication, I can pipe the request over like the example here:
    //https://newspaint.wordpress.com/2012/11/05/node-js-http-and-https-proxy/
    console.log(`INFO: CONNECT request received: ${localReq.url}`);
    //Parse request
    let [host, port, ...rest] = localReq.url.split(":"); //Expected to be something like example.com:443
    if (rest.length > 0 || !port || !host || host.includes("*")) {
        console.log(`WARNING: CONNECT request to ${localReq.url} is not valid.`);
        localSocket.destroy();
        return;
    }
    port = parseInt(port);
    if (isNaN(port) || port < 0 || port > 65535) {
        console.log(`WARNING: CONNECT request to ${localReq.url} is not valid.`);
        localSocket.destroy();
        return;
    }
    //CONNECT is usually used by HTTPS, WebSocket, and WebSocket Secure
    //In the case of WebSocket, there will be no TLS handshake, I need to check if there is a TLS handshake and connect the socket
    //to the correct server
    //Since SSLv2 is now prohibited and Chromium is already rejecting SSLv3 connections, in 2017, I can safely assume only TLS is used
    //https://tools.ietf.org/html/rfc6176

};
/**
 * Detect TLS handshake from incoming data.
 * http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
 * https://tools.ietf.org/html/rfc5246
 * https://github.com/openssl/openssl/blob/a9c85ceaca37b6b4d7e4c0c13c4b75a95561c2f6/include/openssl/tls1.h#L65
 * The first 2 bytes should be 0x16 0x03, and the 3rd byte should be 0x01, 0x02, 0x03, or 0x04.
 * TODO: Detect if SNI is used, mitmproxy is using Kaitai Struct to parse the handshake. I probably want to try that later, for now, I'll
 * assume all requests that uses TLS gives SNI.
 * https://github.com/mitmproxy/mitmproxy/blob/ee6ea31147428729776ea2e8fe24d1fc44c63c9b/mitmproxy/proxy/protocol/tls.py
 */
connectEngine.onHandshake = (data) => {
    //TODO
};

/**
 * Start a proxy server.
 * @function
 * @param {Object} config - The configuration object.
 ** {integer} [config.port=12345] - The port that the proxy server listens.
 ** {boolean} [useTLS=false] - Whether the proxy server should be started in HTTPS mode.
 ** {boolean} [unsafe=false] - Whether HTTPS to HTTP proxy is allowed.
 */
exports.start = (config) => {
    config = config || {};
    //Load configuration
    const port = config.port || 12345;
    const useTLS = config.useTLS || false;
    let server;
    //Check TLS configuration and create the right server
    if (useTLS) {
        console.log("INFO: Loading certificate authority root certificate...");
        tls.init((cert) => {
            server = https.createServer(cert); //Still handle REQUEST the same way
            console.log(`INFO: Violentproxy started on port ${port}, TLS is enabled.`);
        });
    } else {
        //Similar to the mode above, except the proxy server itself is started in HTTP mode
        //This is good for localhost, as it would speed up the proxy server
        console.log("WARNING: The connection between your user agent and Violentproxy is not encrypted.");
        console.log("INFO: Loading certificate authority root certificate...");
        tls.init(() => {
            server = http.createServer();
            console.log(`INFO: Violentproxy started on port ${port}, TLS is disabled but HTTPS requests are allowed.`);
        });
    }
    //Listen to REQUEST requests, this is often used for HTTP
    server.on("request", requestEngine);
    //Listen to CONNECT requests, this often used for HTTPS and WebSocket
    server.on("connect", connectEngine);
    //Ignore bad requests
    server.on("clientError", (err, socket) => {
        socket.destroy();
    });
    //Listen to the port
    server.listen(port);
};

/**
 * Request patching results.
 * @const {Enumeration}
 */
exports.RequestResult = {
    /**
     * Process the request normally. The response will be processed by response patcher later.
     */
    Allow: 0,
    /**
     * Return a HTTP 200 response with an empty body.
     * Pass in these extra fields when needed:
     * @const {string} type - The content type, defaults to one of the requested one.
     * @const {stirng} server - The server name, defaults to "Apache/2.4.7 (Ubuntu)".
     */
    Empty: 1,
    /**
     * Immediately close the connection.
     */
    Deny: 2,
    /**
     * Redirect the request to another address or to a local resource, the user agent will not be able to know
     * the resource is redirected, a certificate for the originally requested host will be signed and used.
     * The following extra fields must be passed:
     * @const {string} redirectLocation - The location to redirect, pass null for redirecting to a local resource.
     * @const {string|Buffer} redirectText - The text to redirect to, this is only required if redirectLocation is null.
     * @const {Header} headers - The headers, omit to use the default one.
     */
    Redirect: 3,
};

/**
 * Request patcher.
 * @var {Function}
 * @param {URL} source - The referrer URL, if exist. Undefined will be passed if it doesn't exist.
 * @param {URL} destination - The requested URL.
 * @param {Header} headers - The headers object as reference, changes to it will be reflected. Be aware that some fields
 ** can't be changed, and some fields will cause problems if changed.
 * @param {Function} callback - The function to call when a decision is made, the patcher can be either synchronous or asynchronous.
 ** @param {RequestResult} result - The decision.
 * An URL object contains:
 ** @const {string} domain - The domain of the URL, this is provided for convenience and performance.
 ** @const {string} path - The path of the URL, this is provided for convenience and performance.
 ** @const {string} fullURL - The full URL.
 */
exports.onRequest = (source, destination, headers, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    //This is just an example
    callback({
        result: exports.RequestResult.Allow, //The reference will be different when replacing this dummy patcher
    });
};
/**
 * Response patcher. Refer back to exports.onRequest() for more information.
 * @var {Function}
 * @param {string|undefined} text - The response text if the response is text, undefined otherwise.
 * @param {Function} callback - Refer back to exports.onRequest() for more information.
 ** @param {string} patchedText - The patched response text, if apply.
 */
exports.onResponse = (source, destination, text, headers, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    //This is just an example
    if (text) {
        callback(text.replace(/(<head[^>]*>)/i, "$1" + `<script>console.log("Hello from Violentproxy :)");</script>`));
    } else {
        callback();
    }
};
/**
 * TODO: Userscript callback handler
 */
exports.onUserscriptCallback = () => {

};

//Handle server crash
process.on("uncaughtException", (err) => {
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("!!!!! Violentproxy encountered a fatal error and is about to crash !!!!!");
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("If you believe this is caused by a bug, please inform us at https://github.com/Violentproxy/Violentproxy/issues");
    throw err;
});
