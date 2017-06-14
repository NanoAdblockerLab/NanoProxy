//Core engine for Violentproxy
"use strict";

/**
 * Load network modules.
 * @const {Module}
 */
const { https, http, net, url, ws } = global;
/**
 * Load other modules
 * @const {Module}
 */
const { agent, zlib, tls } = global;

/**
 * Get MIME type from header.
 * @param {string} str - The encoding related header entry.
 * @param {string} [def="text/html"] - The default value.
 */
const getType = (str = "", def = "text/html") => {
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
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {ServerResponse} localRes - The local response object.
 */
let requestEngine = (localReq, localRes) => {
    global.log("INFO", `Received a REQUEST request: ${localReq.url}`);
    //Prepare request
    let options
    try {
        options = url.parse(localReq.url);
    } catch (err) {
        //Bad request
        global.log("WARNING", `Received an invalid REQUEST request: ${err.message}`);
        localRes.destroy();
        return;
    }
    //Process options
    options.method = localReq.method;
    options.headers = localReq.headers;
    options.agent = agent.getAgent(localReq.httpVersion, localReq.headers, options.protocol === "https:");
    options.auth = localReq.auth;
    //Check for host
    if (localReq.url[0] === "/") {
        global.log("WARNING", "Received an invalid REQUEST request: No host give.");
        localRes.destroy();
        return;
    }
    //Only POST requests should have payloads, GET can have one but should not
    //I'll read the payload no matter what, but I'll warn the user if a GET request has a payload
    let payload = [];
    localReq.on("data", (chunk) => {
        payload.push(chunk);
    });
    localReq.on("end", () => {
        payload = Buffer.concat(payload);
        if (payload.length) {
            global.log("WARNING", "Received a GET request with a payload.");
        }
        //Patch the request
        exports.onRequest(localReq.headers["referer"], localReq.url, payload, localReq.headers, (decision, payload) => {
            //Further process headers so response from remote server can be parsed
            localReq.headers["accept-encoding"] = "gzip, deflate";
            switch (decision.result) {
                case global.RequestDecision.Allow:
                    //Do nothing, process it normally
                    break;
                case global.RequestDecision.Empty:
                    localRes.writeHead(200, "OK", decision.headers || {
                        "Content-Type": getType(localReq.headers["accept"]),
                        "Server": "Apache/2.4.7 (Ubuntu)",
                    });
                    localRes.end();
                    return; //Stop here
                case global.RequestDecision.Deny:
                    localRes.destroy();
                    return; //Stop here
                case global.RequestDecision.Redirect:
                    if (decision.redirectLocation === null) {
                        //Just write back the redirected text
                        localRes.writeHead(200, "OK", decision.headers || {
                            "Content-Type": getType(localReq.headers["accept"]),
                            "Server": "Apache/2.4.7 (Ubuntu)",
                        });
                        localRes.write(decision.redirectText);
                        localRes.end();
                        return;
                    } else {
                        //I expect the patcher to return valid URL
                        Object.assign(options, url.parse(decision.redirectLocation));
                        break;
                    }
                default:
                    throw new Error(`requestEngine() does not accept ${decision} as a request decision.`);
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
                    //I'm still able to change the header of non-text response though
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
                                    //Could not parse
                                    global.log("WARNING", `Could not parse server response: ${err.message}`);
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
                remoteRes.on("error", (err) => {
                    //Something went wrong
                    global.log("WARNING", `Could not connect to remote server: ${err.message}`);
                    localRes.destroy();
                });
                remoteRes.on("aborted", () => {
                    //Remote server disconnected prematurely, drop the local connection
                    localRes.destroy();
                });
            });
            request.on("error", (err) => {
                global.log("WARNING", `Could not connect to remote server: ${err.message}`);
                localRes.destroy();
            });
            //Forward on patched POST payload
            if (payload) {
                request.write(payload);
            }
            request.end();
            //Abort request when local client disconnects
            localReq.on("aborted", () => { request.abort(); });
        });
    });
    localReq.on("error", (err) => {
        global.log("WARNING", `Local connection failed: ${err.message}`);
        localRes.destroy();
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
        //Update content length
        remoteRes.headers["content-length"] = responseData.length;
        //Prevent public key pinning
        delete remoteRes.headers["Public-Key-Pins"];
        localRes.writeHead(remoteRes.statusCode, remoteRes.statusMessage, remoteRes.headers);
        localRes.write(responseData);
        localRes.end();
    };
    if (isText) {
        exports.onTextResponse(referer, url, responseData.toString(), remoteRes.headers, (patchedData) => {
            responseData = patchedData;
            onDone();
        });
    } else {
        exports.onOtherResponse(referer, url, responseData, remoteRes.headers, (patchedData) => {
            responseData = patchedData;
            onDone();
        });
    }
};

/**
 * The dynamic server, clients that support Sever Name Indication will be routed to this server.
 * This server will be initialized when exports.start() is called.
 * @const {DynamicServer}
 */
let dynamicServer;
/**
 * Dynamic server class.
 * @class
 */
const DynamicServer = class {
    /**
     * The constructor for SNI server.
     * @constructor
     */
    constructor() {
        //The port of this server
        this.port = 12346;
        //The host where I have certificate for
        this.knownHosts = [];
        //Initialize server
        this.server = https.createServer({});
        //Handle error
        this.server.on("error", (err) => {
            global.log("ERROR", `An error occured on the dynamic server: ${err.message}`);
        });
        this.server.on("clientError", (err, localSocket) => {
            global.log("WARNING", `A client error occured on the dynamic server: ${err.message}`)
            localSocket.destroy();
        });
        //Bind event handler
        this.server.on("request", this.onRequest);
        this.server.listen(this.port);
    }
    /**
     * Schedule a function to call once the server is ready to handle the request.
     * @method
     * @param {string} host - The host to connect to.
     * @param {Function} func - The function to call when the server is ready.
     ** @param {integer} localPort - The local port matching the given remote port.
     */
    prepare(host, callback) {
        //Check if I have the certificate for the host
        if (this.knownHosts.includes(host)) {
            process.nextTick(() => {
                callback();
            });
        } else {
            tls.sign(host, (cert) => {
                this.knownHosts.push(host);
                this.server.addContext(host, cert);
                callback();
            });
        }
    }
    /**
     * Dynamic server REQUEST request handler, slightly modify the URL and send it off to the main REQUEST request handler.
     * @method
     * @param {IncomingMessage} localReq - The local request object.
     * @param {ServerResponse} localRes - The local response object.
     */
    onRequest(localReq, localRes) {
        //Fill in the full URL and send off to request engine.
        localReq.url = "https://" + localReq.headers["host"] + localReq.url;
        requestEngine(localReq, localRes);
    }
};

/**
 * Proxy engine for CONNECT requests.
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {Socket} localSocket - The local socket, the user agent will ask me to connect this to a socket of the remote server,
 ** but I will connect it to a local server instead.
 * @param {Buffer} localHead - The begining of message, this may or may not be present.
 */
let connectEngine = (localReq, localSocket, localHead) => {
    //If I think it's OK to give up control over the communication, I can pipe the request over like the example here:
    //https://newspaint.wordpress.com/2012/11/05/node-js-http-and-https-proxy/
    global.log("INFO", `Received a CONNECT request: ${localReq.url}`);
    //Parse request
    let [host, port, ...rest] = localReq.url.split(":"); //Expected to be something like example.com:443
    if (rest.length > 0 || !host || host.includes("*") || !host.includes(".")) {
        global.log("WARNING", `Received an invalid CONNECT request: Request URL is malformed.`);
        localSocket.destroy();
        return;
    }
    port = parseInt(port);
    if (isNaN(port) || port < 0 || port > 65535) {
        //Defaults to port 443
        port = 443;
    }
    localSocket.pause();
    //See what I need to do
    exports.onConnect(`${host}:${port}`, (decision) => {
        switch (decision.result) {
            case global.RequestDecision.Allow:
                //Do nothing, process it normally
                break;
            case global.RequestDecision.Deny:
                localSocket.destroy();
                return; //Stop here
            case global.RequestDecision.Pipe:
                const connection = net.connect(port, host, () => {
                    //Pipe the connection over to the server
                    localSocket.pipe(connection);
                    connection.pipe(localSocket);
                    //Send the head that I got before over
                    localSocket.emit("data", localHead);
                    //Resume the socket that I paused before
                    localSocket.resume();
                });
                return;
            default:
                throw new Error(`connectEngine() does not accept ${decision} as a request decision.`);
        }
        //Since SSLv2 is now prohibited and Chromium is already rejecting SSLv3 connections, in 2017, I can safely assume only TLS is used
        //https://tools.ietf.org/html/rfc6176
        //I need 3 bytes of data to distinguish a TLS handshake from plain text
        if (localHead && localHead.length >= 3) {
            connectEngine.onHandshake(localReq, localSocket, localHead, host, port);
        } else {
            let data = localHead;
            const handler = () => {
                localSocket.once("data", (incomingData) => {
                    data = Buffer.concat([data, incomingData]);
                    if (data.length < 3) {
                        handler();
                    } else {
                        connectEngine.onHandshake(localReq, localSocket, data, host, port);
                    }
                });
            };
            handler();
            //Now I need to tell the user agent to send over the data
            //Line break is \r\n regardless of platform
            //https://stackoverflow.com/questions/5757290/http-header-line-break-style
            localSocket.write(`HTTP/${localReq.httpVersion} 200 Connection Established\r\n`); //Maybe I should hard code this as HTTP/1.1
            if (localReq.headers["connection"] === "keep-alive") {
                localSocket.write("Connection: keep-alive\r\n");
            }
            if (localReq.headers["proxy-connection"] === "keep-alive") {
                localSocket.write("Proxy-Connection: keep-alive\r\n");
            }
            //Write an emply line to signal the user agent that HTTP header has ended
            localSocket.write("\r\n");
            //Resume the socket so I can receive the handshake
            localSocket.resume();
        }
    });
};
/**
 * Detect TLS handshake from incoming data.
 * http://blog.bjrn.se/2012/07/fun-with-tls-handshake.html
 * https://tools.ietf.org/html/rfc5246
 * https://github.com/openssl/openssl/blob/a9c85ceaca37b6b4d7e4c0c13c4b75a95561c2f6/include/openssl/tls1.h#L65
 * The first 2 bytes should be 0x16 0x03, and the 3rd byte should be 0x01, 0x02, 0x03, or 0x04.
 * https://github.com/mitmproxy/mitmproxy/blob/ee6ea31147428729776ea2e8fe24d1fc44c63c9b/mitmproxy/proxy/protocol/tls.py
 * @function
 * @param {IncomingMessage} localReq - The local request object.
 * @param {Socket} localSocket - The local socket object.
 * @param {Buffer} localHead - The begining of message, there must be at least 3 bytes.
 * @param {string} host - The remote host to connect to.
 * @param {integer} port - The remote port to connect to.
 */
connectEngine.onHandshake = (localReq, localSocket, localHead, host, port) => {
    //Check if the connection is TLS
    const firstBytes = [localHead.readUInt8(0), localHead.readUInt8(1), localHead.readUInt8(2)];
    if (firstBytes[0] === 0x16 && firstBytes[1] === 0x03 && firstBytes[2] < 0x06) { //Testing for smaller than or equal to 0x05 just in case
        //Assuming all connection accepts SNI
        dynamicServer.prepare(host, () => {
            const connection = net.connect(dynamicServer.port, () => {
                //Pipe the connection over to the server
                localSocket.pipe(connection);
                connection.pipe(localSocket);
                //Send the head that I got before over
                localSocket.emit("data", localHead);
                //Resume the socket that I paused before
                localSocket.resume();
            });
            connection.on("error", (err) => {
                global.log("WARNING", `An error occured when connecting to dynamic server: ${err.message}`);
                localSocket.destroy();
            });
        });
    } else {
        global.log("WARNING", "Received an invalid CONNECT request: Data sent by user agent is not a TLS handshake.");
        localSocket.destroy();
    }
};

/**
 * Start a proxy server.
 * @function
 * @param {Object} config - The configuration object.
 ** {boolean} [useTLS=false] - Whether the proxy server should be started in HTTPS mode.
 */
exports.start = (useTLS = false) => {
    let server;
    const onDone = () => {
        //Initialize SNI server
        dynamicServer = new DynamicServer();
        //Listen to REQUEST requests
        server.on("request", requestEngine);
        //Listen to CONNECT requests
        server.on("connect", connectEngine);
        //Handle errors
        server.on("error", (err) => {
            global.log("ERROR", `An error occured on the main proxy server: ${err.message}`);
        });
        server.on("clientError", (err, socket) => {
            global.log("WARNING", `A client error occurred on the main proxy server: ${err.message}`);
            socket.destroy();
        });
        //Listen to the port
        server.listen(12345);
    };
    //Check TLS configuration and create the right server
    if (useTLS) {
        global.log("INFO", "Loading certificate authority root certificate...");
        tls.init(() => {
            server = https.createServer(global.localCert); //Still handle REQUEST the same way
            global.log("INFO", `Violentproxy started on port 12345, encryption is enabled.`);
            onDone();
        });
    } else {
        //Similar to the mode above, except the proxy server itself is started in HTTP mode
        //This is good for localhost, as it would speed up the proxy server
        global.log("INFO", "Loading certificate authority root certificate...");
        tls.init(() => {
            server = http.createServer();
            global.log("INFO", `Violentproxy started on port 12345, encryption is disabled.`);
            global.log("WARNING", "The connection between your user agent and Violentproxy is not encrypted.");
            onDone();
        });
    }
};

/**
 * REQUEST Requests patcher.
 * @var {Function}
 * @param {string} source - The referer URL, if exist. Undefined will be passed if it doesn't exist.
 * @param {string} destination - The requested URL.
 * @param {Buffer} payload - The raw POST request payload, since I can't make assumptions on what the server likes, I cannot have
 ** generic handle to beautify this.
 * @param {Header} headers - The headers object as reference, changes to it will be reflected.
 * @param {Function} callback - The function to call when a decision is made, the patcher can be either synchronous or asynchronous.
 ** @param {RequestDecision} result - The decision.
 ** @param {Buffer|string} payload - The patched payload. If you changed it, you are also responsible in updating related headers.
 */
exports.onRequest = (source, destination, payload, headers, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    //This is just an example
    callback({
        result: global.RequestDecision.Allow,
    }, payload);
};
/**
 * CONNECT requests patcher.
 * @var {Function}
 * @param {string} destination - The destination host and port.
 * @param {Function} callback - Refer to exports.onRequest() for more information.
 */
exports.onConnect = (destination, callback) => {
    //These parameters are not used
    void destination;
    //This is just an example
    callback({
        result: global.RequestDecision.Allow,
    });
};
/**
 * Text responses patcher. Refer back to exports.onRequest() for more information.
 * @var {Function}
 * @param {string} text - The response text.
 * @param {Function} callback - Refer back to exports.onRequest() for more information.
 ** @param {string} patchedText - The patched response text, if apply.
 */
exports.onTextResponse = (source, destination, text, headers, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    //This is just an example
    callback(text.replace(/(<head[^>]*>)/i, "$1" + `<script>console.log("Hello from Violentproxy :)");</script>`));
};
/**
 * Other responses (everything except text) patcher. Refer back to exports.onRequest() and exports.onTestResponse() for more information.
 * @var {Function}
 * @param {Buffer} data - The response data. It could be still encoded, don't change it unless you plan to replace it.
 */
exports.onOtherResponse = (source, destination, data, headers, callback) => {
    //These parameters are not used
    void source;
    void destination;
    void headers;
    //This is just an example
    callback(data);
};

//Handle server crash
process.on("uncaughtException", (err) => {
    global.log("ERROR", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    global.log("ERROR", "!!!!! Violentproxy encountered a fatal error and is about to crash !!!!!");
    global.log("ERROR", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    global.log("ERROR", "If you believe this is caused by a bug, please inform us at https://github.com/Violentproxy/Violentproxy/issues");
    throw err;
});
