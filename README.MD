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

## TODO

1. Test out if Chromium accepts certificate that covers a full public suffix. 
2. XMLHttpRequest in POST mode is not working. 
3. WebSocket and WebRTC are not implemented. 
4. Server Name Indication check and HTTP/2 support are not implemented. 
