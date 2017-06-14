//Agents manager for Violentproxy
"use strict";

/**
 * Load modules.
 * @const {Module}
 */
const { https, http } = global;

/**
 * The cache of available HTTP agents.
 * An agent key must be the timeout, in second, as string.
 * Two special cases are "close" (don't keep alive) and "default" (keep alive with all default settings).
 * @var {Dictionary.<Agent>}
 */
let agentCache = [];
/**
 * The cache of available HTTPS agents. Refer to agentCache for more information.
 * @var {Dictionary.<TLSAgent>}
 */
let tlsAgentCache = [];
//Initialize common agents
agentCache["close"] = new http.Agent({ keepAlive: false });
tlsAgentCache["close"] = new https.Agent({ keepAlive: false });
agentCache["default"] = new http.Agent({ keepAlive: true });
tlsAgentCache["default"] = new https.Agent({ keepAlive: true });

/**
 * Get an Agent that fits the requirements.
 * @function
 * @param {string} httpVer - The version of HTTP.
 * @param {Header} headers - The header object.
 * @param {boolean} useTLS - Whether TLS must be used. Note that this is only for the connection between the
 ** proxy and the remote server, it can be different than the connection between the proxy and the user agent.
 * @return {Agent} An agent that matches the requirements.
 */
exports.getAgent = (() => {
    //Precompile RegExp
    const splitKey = /=|,/;
    //Return closure function
    return (httpVer, headers, useTLS) => {
        if ((httpVer === "1.0" && headers["connection"] !== "keep-alive") || headers["connection"] === "close") {
            //Close connection
            return useTLS ? tlsAgentCache["close"] : agentCache["close"];
        } else {
            //Use keep alive
            //https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
            if (headers["keep-alive"]) {
                //I will generate the option object along with the key, so I don't need to loop over it two times
                let options = {
                    keepAlive: true,
                };
                let key = "default";
                //The header is expected to be something like "timeout=5, max=1000"
                const arr = headers["keep-alive"].split(splitKey);
                for (let i = 0; i < arr.length; i++) {
                    //There can be spaces
                    const entry = arr[i].trim();
                    if (entry === "timeout") {
                        const num = parseFloat(arr[++i]) * 1000;
                        if (!isNaN(num) && isFinite(num) && num > 0) {
                            options.keepAliveMsecs = num;
                            key = arr[++i];
                        }
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
})();
