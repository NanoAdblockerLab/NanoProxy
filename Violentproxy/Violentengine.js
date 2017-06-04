"use strict";

//Load modules
const https = require("https"),
    http = require("http"),
    zlib = require("zlib"),
    net = require("net"),
    url = require("url");

/**
 * Proxy engine for REQUEST (HTTP) request.
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {ServerResponse} localRes - The local response object.
 */
const engine = (localReq, localRes) => {
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
    //Pass through some arguments
    options.headers = localReq.headers;
    //I think this can cause problem if the user agent decides to keep the connection alive
    //options.agent = localReq.agent;
    options.auth = localReq.auth;
    //Handle internal request loop
    //As I can't easily find out what is my common name, the first proxied request will backloop internally
    //This isn't the most efficient way to handle it, but should be good enough if Userscripts don't spam the API
    if (!localReq.url.startsWith("http")) { //TODO: Change this to handle Userscripts API
        localRes.writeHead(400, "Bad Request", {
            "Content-Type": "text/plain",
            "Server": "Violentproxy Proxy Server",
        });
        localRes.write("The request that Violentproxy received is not valid because it would cause internal request loop.");
        localRes.end();
    } else {
        //Patch the request
        const requestResult = exports.requestRequestPatchingProvider(localReq.headers, localReq.url);
        //Further process headers so response from remote server can be parsed
        localReq.headers["accept-encoding"] = "gzip, deflate";
        switch (requestResult.result) {
            case exports.requestResult.Allow:
                //Do nothing, let the request pass
                break;
            case exports.requestResult.Empty:
                localRes.writeHead(200, "OK", {
                    "Content-Type": "text/plain", //TODO: Dynamically determine this
                    "Server": "Violentproxy Proxy Server", //TODO: mock as something more believable (?)
                });
                localRes.end();
                return; //Stop here
            case exports.requestResult.Deny:
                //TODO: implement this
                break;
            case exports.requestResult.Redirect:
                //TODO: implement this
                break;
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
                const encoding = remoteRes.headers["content-encoding"];
                if (encoding === "gzip" || encoding === "deflate") {
                    zlib.unzip(data, (err, result) => {
                        if (err) {
                            localRes.writeHead(500, "Data Stream Parse Error", {
                                "Content-Type": "text/plain",
                                "Server": "Violentproxy Proxy Server",
                            });
                            localRes.write("Violentproxy could not complete your request because there is a data stream parsing error.");
                            localRes.end();
                        } else {
                            finalize(localRes, remoteRes, localReq.url, result.toString()); //TODO: what about images? 
                        }
                    });
                } else {
                    //Assume identity
                    finalize(localRes, remoteRes, localReq.url, data.toString()); //TODO: what about images? 
                }
            });
            remoteRes.on("error", () => {
                //I'm not sure how to properly handle this, I think this is good
                localRes.writeHead(500, "Data Stream Read Error", {
                    "Content-Type": "text/plain",
                    "Server": "Violentproxy Proxy Server",
                });
                localRes.write("Violentproxy could not complete your request because there is a data stream read error.");
                localRes.end();
            });
            //Add server abort handling
            remoteRes.on("aborted", () => {
                //As we do not send message back unless it is ready, it's safe to do a complete response here
                localRes.writeHead(502, "Broken Pipe / Remote Server Disconnected", {
                    "Content-Type": "text/plain",
                    "Server": "Violentproxy Proxy Server",
                });
                localRes.write("Violentproxy could not complete your request because remote server closed the connection.");
                localRes.end();
            });
        });
        request.on("error", () => {
            //This can error out if the address is not valid
            localRes.destroy();
        });
        request.end();
        //Abort request when local client disconnects
        localReq.on("aborted", () => { request.abort(); });
    }
};

/**
 * Proxy engine for CONNECT (HTTPS) requests.
 * @param {IncomingMessage} localReq - 
 * @param {Socket} localSocket
 * @param {Buffer} localHead
 */
const engines = (localReq, localSocket, localHead) => {
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

    //Connect using socket
    //const remoteSocket = new net.Socket();
    //remoteSocket.connect(port, host, () => {
    //
    //});

};

/**
 * Process final request result of a REQUEST request and send it to client.
 * @param {http.ServerResponse} localRes - The object that can be used to respond client request.
 * @param {http.IncomingMessage} remoteRes - The object that contains data about server response.
 * @param {string} url - The request URL.
 * @param {string} responseText - The response text.
 */
const finalize = (localRes, remoteRes, url, responseText) => {
    const text = exports.requestResponsePatchingProvider(remoteRes.headers, url, responseText);
    //So I don't need to encode it again
    remoteRes.headers["content-encoding"] = "identity";
    //The length will be changed when it is patched, let the browser figure out how long it actually is
    //I can probably count that, I'll pass in an updated length if removing the header causes problems
    delete remoteRes.headers["content-length"];
    //TODO: Patch Content Security Policy to allow injected scripts to run
    //      Maybe this should e done by patching provider
    localRes.writeHead(remoteRes.statusCode, remoteRes.statusMessage, remoteRes.headers);
    localRes.write(text);
    localRes.end();
};

/**
 * Start a proxy server.
 * @function
 * @param {Object} config - The configuration object.
 ** {integer} [config.port=12345] - The port that the proxy server listens.
 ** {Object} [cert=undefined] - The certificate for HTTPS mode. Leave undefined to use HTTP mode.
 ** {boolean} [unsafe = false] - Whether HTTPS to HTTP proxy is allowed.
 */
exports.start = (config) => {
    config = config || {};
    //Load configuration
    const port = config.port || 12345;
    const cert = config.cert;
    let server;
    //Create server
    if (cert) {
        console.log("Encryption enabled, don't forget to install the certificate");
        server = https.createServer(cert, engine);
        server.on("connect", engines);
    } else {
        server = http.createServer(engine);
        if (config.unsafe) {
            console.log("Warning: HTTPS request will be downgraded to HTTP between user agent and Violentproxy");
            server.on("connect", engines);
        }
    }
    server.listen(port);
    console.log(`Violentproxy started on port ${port}`);
};

/**
 * Request patching results.
 * @const {Enumeration}
 */
exports.requestResult = {
    Allow: 0, //Do nothing, let the request pass
    Empty: 1, //Stop the request and return HTTP 200 with empty response body
    Deny: 2, //TODO: Reject the request
    Redirect: 3, //TODO: Redirect the request to another address or to a local resource
};

/**
 * REQUEST request patching provider.
 * This function can modify a REQUEST request. Override this function to install your provider.
 * @var {Function}
 * @param {Object} headers - The headers of the request, passed over by reference and changes will be reflected.
 ** "accept-encoding" cannot be changed as it wil causes parsing issues.
 * @param {string} url - The destination of the request.
 * @return {Object}
 ** {Enumeration} result - The request patching result.
 ** {Any} extra - Appropriate extra information for the request patching result.
 */
exports.requestRequestPatchingProvider = (headers, url) => {
    //These parameters are not used
    void headers;
    //This is just an example
    return {
        result: exports.requestResult.Allow,
        extra: null,
    };
};

/**
 * REQUEST response patching provider.
 * This function can modify a REQUEST response from remote server. Override this function to install your provider.
 * @var {Function}
 * @param {Object} headers - The headers of the response, passed over by reference and changes will be reflected.
 ** "content-encoding" and "content-length" cannot be changed as it wil causes parsing issues.
 * @param {string} url - The destination of the request.
 * @param {string} [text=undefined] - If defined, return value will be sent back to client instead,
 ** this may be undefined if the request is not text. Header patching will always be accepted.
 ** Be aware that if text is defined, and nothing is returned, then client will recive an empty body.
 * @return {string} The patched response text.
 */
exports.requestResponsePatchingProvider = (headers, url, text) => {
    //These parameters are not used
    void headers;
    void url;
    //This is just an example
    if (text) {
        return text.replace(/(<head[^>]*>)/i, "$1" + `<script>console.log("Hello from Violentproxy :)");</script>`);
    }
};

//Handle server crash
process.on("uncaughtException", (err) => {
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("!!!!!Violentproxy encountered a fatal error and is about to crash!!!!!");
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("More information will soon be printed to the screen.");
    console.log("Our support page: https://github.com/Violentproxy/Violentproxy/issues");
    throw err;
});
