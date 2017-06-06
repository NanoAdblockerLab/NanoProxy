//Agents manager for Violentproxy
"use strict";

/**
 * Modules, will be passed over from the core engine when exports.init() is called.
 * @const {Module}
 */
let https, http;

/**
 * The cache of available HTTP agents.
 * An agent key must be like "timeout,maxConnection".
 * It can be "5000," (default max connection of Node.js is used).
 * Two special cases are "close" (don't keep alive) and "default" (keep alive with all default settings).
 * TODO: Add a timer that removes agents when they are not used for extended amount of time (except special ones).
 * @var {Dictionary.<Agent>}
 */
let agentCache = [];
/**
 * The cache of available HTTPS agents. Refer to agentCache for more information.
 * @var {Dictionary.<Agent>}
 */
let tlsAgentCache = [];

/**
 * Initialize agents manager.
 * @function
 * @param {Modules} modules - The required modules.
 */
exports.init = (modules) => {
    https = modules.https;
    http = modules.http;
    //Initialize common agents
    agentCache["close"] = new http.Agent({ keepAlive: false });
    tlsAgentCache["close"] = new https.Agent({ keepAlive: false });
    agentCache["default"] = new http.Agent({ keepAlive: true });
    tlsAgentCache["default"] = new https.Agent({ keepAlive: true });
};

/**
 * Get an Agent that fits the requirements.
 * @function
 * @param {string} httpVer - The version of HTTP.
 * @param {Header} headers - The header object.
 * @param {boolean} useTLS - Whether TLS must be used. Keep in mind that this is only for the connection between the
 ** proxy and the remote server, it can be different than the connection between the proxy and the user agent.
 * @return {Agent} An agent.
 */
exports.getAgent = (httpVer, headers, useTLS) => {
    if ((httpVer === "1.0" && headers["connection"] !== "keep-alive") ||
        headers["connection"] === "close") {
        //Close connection
        return useTLS ? tlsAgentCache["close"] : agentCache["close"];
    } else {
        //Use keep alive
        //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
        if (headers["keep-alive"]) {
            //I will generate the option object along with the key, so I don't need to loop over it
            //two times
            let options = {
                keepAlive: true,
            };
            //The key is "timeout,max"
            let key = ",";
            const arr = headers["keep-alive"].split(/=|,/);
            for (let i = 0; i < arr.length; i++) {
                const entry = arr[i].trim();
                switch (entry) {
                    case "timeout":
                        options.keepAliveMsecs = arr[++i] * 1000;
                        key = options.keepAliveMsecs + key;
                        break;
                    case "max":
                        options.maxSockets = arr[++i];
                        key = key + options.maxSockets;
                        break;
                }
            }
            cache = useTLS ? tlsAgentCache : agentCache;
            if (!cache[key]) {
                cache[key] = new (useTLS ? https : http).Agent(options);
            }
            return cache[key];
        } else {
            //Use default agent, since I don't have more information
            return useTLS ? tlsAgentCache["default"] : agentCache["default"];
        }
    }
};
