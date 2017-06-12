# Violentproxy [![Dependencies](https://david-dm.org/Violentproxy/Violentproxy.svg)](https://david-dm.org/Violentproxy/Violentproxy)

Named after [Violentmonkey](https://github.com/violentmonkey/violentmonkey), 
Violentproxy is a monkey-in-the-middle proxy server that aims at doing the same monkey things but in a different way, 
it has different restrictions and can possibly work together with Violentmonkey and uBlock Origin to create a 
better browsing experience. 

Violentproxy is not able to proxy request between the local network, it also needs ports 12345 and 12346. 

It is in very early development, it may or may not start, if you want to try it out: 
```Bash
npm install
npm debug

curl -x localhost:12345 https://example.com -k
```

Please open an issue if there is something you want me to know. 

## TODO: 

1. Check if Chromium likes my shortcut in Violenttls, I am not checking public suffix. 
2. Implement POST mode and WebSocket proxy. 
3. Test out how WebRTC works with my proxy (Connecting to STUN and TURN servers, as well as direct P2P). 
4. Add support for user agents that do not support Server Name Indication. 
5. Add HTTP/2 support. 
