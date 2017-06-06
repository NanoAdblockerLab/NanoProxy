//Agents manager for Violentproxy
"use strict";

/**
 * Modules, will be passed over from the core engine when exports.init() is called.
 * @const {Module}
 */
let https, http;

/**
 * The cache of available HTTP agents.
 * @var {Array.<Agent>}
 */
let agentCache = [];
/**
 * The cache of available HTTPS agents.
 * @var {Array.<Agent>}
 */
let sslAgentCache = [];

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
    sslAgentCache["close"] = new https.Agent({ keepAlive: false });
    agentCache["default"] = new http.Agent({ keepAlive: true });
    sslAgentCache["default"] = new https.Agent({ keepAlive: true });
};

/**
 * Get an Agent that fits the requirements.
 * @function
 * @param {string} httpVer - The version of HTTP.
 * @param {Header} headers - The header object.
 * @param {boolean} useSSL - Whether SSL is used.
 * @return {Agent} An agent.
 */
exports.getAgent = (httpVer, headers, useSSL) => {
    if ((httpVer === "1.0" && headers["connection"] !== "keep-alive") ||
        headers["connection"] === "close") {
        //Close connection
        return useSSL ? sslAgentCache["close"] : agentCache["close"];
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
            cache = useSSL ? sslAgentCache : agentCache;
            if (!cache[key]) {
                cache[key] = new (useSSL ? https : http).Agent(options);
            }
            return cache[key];
        } else {
            //Use default agent, since I don't have more information
            return useSSL ? sslAgentCache["default"] : agentCache["default"];
        }
    }
};
