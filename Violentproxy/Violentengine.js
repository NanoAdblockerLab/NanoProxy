//Core engine for Violentproxy
"use strict";

/**
 * Load network modules.
 * @const {Module}
 */
const https = require("https"),
    http = require("http"),
    net = require("net"),
    url = require("url");
/**
 * Load other modules
 * @const {Module}
 */
const zlib = require("zlib"),
    userscript = require("./Violentscript"),
    agent = require("./Violentagent"),
    ssl = require("./Violentssl");

//Initialize some modules
agent.init({
    https: https,
    http: http,
});

/**
 * Get MIME type from header.
 * @param {string} str - The encoding related header entry.
 * @param {string} [def="text/html"] - The default value.
 */
const getType = (str, def = "text/html") => {
    const parts = str.split(",");
    for (let i = 0; i < parts.length; i++) {
        if (!parts[i].includes("*")) {
            return parts[i];
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
        return (mimeType.startsWith("text/")) || mimeType.endsWith("/xhtml+xml") || mimeType.endsWith("/xml");
    }
};

/**
 * Proxy engine for REQUEST request.
 * In this mode, the user agent gives me the full control, so I don't need to create servers on the fly.
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {ServerResponse} localRes - The local response object.
 */
const requestEngine = (localReq, localRes) => {
    console.log(`REQUEST request received: ${localReq.url}`);
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
        localRes.writeHead(400, "Bad Request", {
            "Content-Type": "text/plain",
            "Server": "Violentproxy Proxy Server",
        });
        localRes.write("The request that Violentproxy received is not valid because it would cause internal request loop.");
        localRes.end();
    } else {
        //Patch the request
        exports.requestPatcher(localReq.headers["referer"], localReq.url, localReq.headers, (requestResult) => {
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
                    //Decode response
                    let encoding = remoteRes.headers["content-encoding"];
                    if (encoding) {
                        encoding = encoding.toLowerCase();
                    }
                    if (encoding === "gzip" || encoding === "deflate") {
                        zlib.unzip(data, (err, result) => {
                            if (err) {
                                //Could not parse, drop the connection
                                localRes.destroy();
                            } else {
                                requestEngine.finalize(localRes, remoteRes, localReq.headers["referer"], localReq.url, result);
                            }
                        });
                    } else {
                        //Assume identity
                        requestEngine.finalize(localRes, remoteRes, localReq.headers["referer"], localReq.url, data);
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
            request.on("error", () => {
                //This can error out if the address is not valid
                localRes.destroy();
            });
            request.end();
            //Abort request when local client disconnects
            localReq.on("aborted", () => { request.abort(); });
        });
    }
};
/**
 * Process final request result of a REQUEST request and send it to client.
 * @param {http.ServerResponse} localRes - The object that can be used to respond client request.
 * @param {http.IncomingMessage} remoteRes - The object that contains data about server response.
 * @param {string} referer - The referrer, if exist.
 * @param {string} url - The request URL.
 * @param {Any} responseData - The response data.
 */
requestEngine.finalize = (localRes, remoteRes, referer, url, responseData) => {
    const onDone = () => {
        //So I don't need to encode it again
        remoteRes.headers["content-encoding"] = "identity";
        //The length will be changed when it is patched, let the browser figure out how long it actually is
        //I can probably count that, I'll pass in an updated length if removing the header causes problems
        delete remoteRes.headers["content-length"];
        localRes.writeHead(remoteRes.statusCode, remoteRes.statusMessage, remoteRes.headers);
        localRes.write(responseData);
        localRes.end();
    };
    //Check MIME type, I can only patch text, changing other types must be done by request patcher
    if (isText(remoteRes.headers["content-type"])) {
        exports.responsePatcher(referer, url, responseData.toString(), remoteRes.headers, (patchedData) => {
            responseData = patchedData;
            onDone();
        });
    } else {
        exports.responsePatcher(referer, url, null, remoteRes.headers, () => {
            onDone();
        });
    }
};

/**
 * Proxy engine for CONNECT (HTTPS) requests.
 * @param {IncomingMessage} localReq - 
 * @param {Socket} localSocket
 * @param {Buffer} localHead
 */
const connectEngine = (localReq, localSocket, localHead) => {
    throw "not implemented";
    //https://newspaint.wordpress.com/2012/11/05/node-js-http-and-https-proxy/
    console.log(`CONNECT request received: ${localReq.url}`);
    //Parse request
    let [host, port, ...rest] = localReq.url.split(":"); //Expected to be something like example.com:443
    if (rest.length > 0 || !port || !host) {
        localSocket.destroy();
        return;
    }
    port = parseInt(port);
    if (isNaN(port) || port < 0 || port > 65535) {
        localSocket.destroy();
        return;
    }
    //Now I need to decide what to do, if I establish a two way socket, then I have no control over what is going though the pipe
    //because the user agent and the server may agree to keep the connection alive, and I won't know when a message ends.
    //If I initiate a separate request, process it, and send back to the user agent, then I can't keep the connection alive,
    //for XMLHttpRequest, this can be very expensive. If the server is using custom software, it may cut me off, it shoudln't be a
    //problem for "standard" software, but it can slow down the connection by quite a bit.
    //There is no easy way to determine whether a request is XMLHttpRequest, but maybe I can inject some script to inform me to use
    //socket for subsequent requests.
    //In order to intercept the request, I need to sign a certificate then start a HTTPS server, which can be an expensive process.
    //For sites the user frequet, I can cache the certificates, as long as the user doesn't visite hundreds of different sites,
    //it should be OK on modern devices.

    //Connect using socket
    //const remoteSocket = new net.Socket();
    //remoteSocket.connect(port, host, () => {
    //
    //});

};

/**
 * Start a proxy server.
 * @function
 * @param {Object} config - The configuration object.
 ** {integer} [config.port=12345] - The port that the proxy server listens.
 ** {boolean} [useSSL=false] - Whether start the proxy server in HTTPS mode.
 ** {boolean} [unsafe=false] - Whether HTTPS to HTTP proxy is allowed.
 */
exports.start = (config) => { //TODO: This is completely broken now...
    config = config || {};
    //Load configuration
    const port = config.port || 12345;
    const useSSL = config.useSSL || false;
    const unsafe = config.unsafe || false;
    let server;
    //Create server
    if (useSSL) {
        console.log("Loading certificate authority...");
        ssl.init((cert) => {
            server = https.createServer(cert, requestEngine); //Still handle REQUEST the same way
            server.on("connect", connectEngine); //Handle CONNECT
            server.listen(port);
            console.log(`Violentproxy started on port ${port}, SSL is enabled.`);
        });
    } else if (unsafe) {
        //Similar to the mode above, except the proxy server is started in HTTP mode
        //This is good for localhost, as it would speed up the proxy server
        console.log("Loading certificate authority...");
        ssl.init(() => {
            server = http.createServer(requestEngine);
            server.on("connect", connectEngine);
            server.listen(port);
            console.log(`Violentproxy started on port ${port}, SSL is disabled but HTTPS requests are allowed.`);
        });
    } else {
        server = http.createServer(requestEngine); //Only handle REQUEST
        server.listen(port);
        console.log(`Violentproxy started on port ${port}, SSL is disabled and HTTPS requests are disallowed.`);
    }
};

/**
 * Request patching results.
 * @const {Enumeration}
 */
exports.RequestResult = {
    //Process the request normally
    Allow: 0,
    /**
     * Return a HTTP 200 response with an empty body.
     * Pass in these extra fields when needed:
     * @const {string} type - The content type, defaults to one of the requested one.
     * @const {stirng} server - The server name, defaults to "Apache/2.4.7 (Ubuntu)".
     */
    Empty: 1,
    //Immediately close the connection
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
 * @param {Function} callback - The function to call when a decision is made, the patcher can run asynchronously.
 ** @param {RequestResult} result - The decision.
 * An URL object contains:
 ** @const {string} domain - The domain of the URL, this is provided for convenience and performance.
 ** @const {string} path - The path of the URL, this is provided for convenience and performance.
 ** @const {string} fullURL - The full URL.
 */
exports.requestPatcher = (source, destination, headers, callback) => {
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
 * Response patcher. Refer back to exports.requestPatcher() for more information.
 * @var {Function}
 * @param {string|undefined} text - The response text if the response is text, undefined otherwise.
 * @param {Function} callback - The function to call when patching is done, the patcher can run asynchronously.
 ** @param {string} patchedText - The patched response text, if apply.
 */
exports.responsePatcher = (source, destination, text, headers, callback) => {
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

//Handle server crash
process.on("uncaughtException", (err) => {
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("!!!!!Violentproxy encountered a fatal error and is about to crash!!!!!");
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("If you believe this is a bug, please inform us at https://github.com/Violentproxy/Violentproxy/issues");
    throw err;
});
