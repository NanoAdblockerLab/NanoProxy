"use strict";

//Load modules
const http = require("http"),
    https = require("https"),
    zlib = require("zlib"),
    url = require("url"),
    fs = require("fs");

//Config variables, will be set later
let port, cert;
let server;

/**
 * Proxy engine.
 * @function
 * @param {http.IncomingMessage} localReq - The local request object.
 * @param {http.ServerResponse} localRes - The local response object.
 */
const engine = (localReq, localRes) => {
    console.log(`Received request: ${localReq.url}`);
    //Process header so response from remote server can be parsed
    localReq.headers["accept-encoding"] = "gzip, deflate";
    //Prepare request
    let options = url.parse(localReq.url);
    options.headers = localReq.headers;
    //Handle internal request loop
    if (!localReq.url.startsWith("http")) { //TODO: Change this to handle privileged Userscript functions
        localRes.writeHead(400, "Bad Request", {
            "Content-Type": "text/plain",
            "Server": "Violentproxy Proxy Server",
        });
        localRes.write("The request that Violentproxy received is not valid because it would cause internal request loop.");
        localRes.end();
    } else {
        //Check request blocking and redirecting
        const requestResult = exports.requestPatchingProvider("", "", "", ""); //TODO: pass in better stuff
        switch (requestResult.result) {
            case exports.requestResult.Allow:
                //Do nothing
                break;
            case exports.requestResult.Empty:
                localRes.writeHead(200, "OK", {
                    "Content-Type": "text/plain", //TODO: Dynamically determine this
                    "Server": "Violentproxy Proxy Server",
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
        //Proxy request TODO: try-catch this, bad URL can crash the server
        const request = (options.protocol === "https:" ? https : http).request(options, (remoteRes) => {
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
                            finalize(localRes, remoteRes, result.toString());
                        }
                    });
                } else {
                    //Assume identity
                    finalize(localRes, remoteRes, data.toString());
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
        request.end();
        //Abort request when local client disconnects
        localReq.on("aborted", () => { request.abort(); });
    }
};

/**
 * Process final request result and send it to client.
 * @param {http.ServerResponse} localRes - The object that can be used to respond client request.
 * @param {http.IncomingMessage} remoteRes - The object that contains data about server response.
 * @param {string} responseText - The response text.
 */
const finalize = (localRes, remoteRes, responseText) => {
    remoteRes.headers["content-encoding"] = "identity"; //So I don't need to encode it again
    //The length will be changed when it is patched, let the browser figure out how long it actually is
    //I can probably count that, I'll pass in an updated length if removing the header causes problems
    delete remoteRes.headers["content-length"];
    localRes.writeHead(remoteRes.statusCode, remoteRes.statusMessage, remoteRes.headers); //TODO: Patch Content Security Policy to allow Userscript callback
    //TODO: Pass better stuff to the patching provider
    localRes.write(exports.responsePatchingProvider("", "", "", responseText, ""));
    localRes.end();
};

/**
 * Start a proxy server.
 * @function
 * @param {Object} config - The configuration object.
 ** {integer} [config.port=12345] - The port that the proxy server listens.
 ** {string} [config.rules="./rules.json"] - The path to the rule JSON.
 ** {Object} [cert=undefined] - The certificate for HTTPS mode. Leave undefined to use HTTP mode.
 */
exports.start = (config) => {
    config = config || {};
    //Load config
    port = config.port || 12345;
    cert = config.cert;
    //Create server
    if (cert) {
        server = https.createServer(cert, engine);
    } else {
        server = http.createServer(engine);
    }
    server.listen(port);
    console.log(`Violentproxy started on port ${port}`);
};

//=====Providers=====

/**
 * Request patching results.
 * @const {Enumeration}
 */
exports.requestResult = {
    Allow: 0, //Do nothing, let the request pass
    Empty: 1, //Stop the request and return HTTP 200 with empty response
    Deny: 2, //TODO: Reject the request
    Redirect: 3, //TODO: Redirect the request to another address or to a local resource
    //TODO: Bind special patching provider (?)
};

/**
 * Request patching provider.
 * This function can reject or redirect a request.
 * @function
 * @param {string} referee - The referee of the request (if it exists).
 * @param {string} domain - The domain of the response.
 * @param {string} path - The path of the response.
 * @param {string} type - The type of the response.
 * @return {Object}
 ** {Enumeration} result - The request patching result.
 ** TODO: Extra information as appropriate. (header patching, special information for the result)
 */
exports.requestPatchingProvider = (referee, domain, path, type) => {
    return { result: exports.requestResult.Allow };
};

/**
 * Page patching provider.
 * This function can modify a server response
 * @function
 * @param {string} referee - The referee of the request (if it exists).
 * @param {string} domain - The domain of the response.
 * @param {string} path - The path of the response.
 * @param {string} text - The response text.
 * @param {string} type - The type of the response.
 * @return {string} The patched response text.
 */
exports.responsePatchingProvider = (referee, domain, path, text, type) => {
    void domain;
    void path;
    void type;
    //This is just an example
    return text.replace(/(<head[^>]*>)/i, "$1" + `<script>console.log("Hello from Violentproxy :)");</script>`);
};
