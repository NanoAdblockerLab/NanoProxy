# EinZinY Core [![Dependencies](https://david-dm.org/EinZinY/Core.svg)](https://david-dm.org/EinZinY/Core)

EinZinY is not able to proxy request between the local network, it also needs ports 12345 and 12346. 

It is in very early development, it may or may not start, if you want to try it out: 
```Bash
npm install
npm run-script debug

curl -x localhost:12345 https://example.com -k
```

You can access to the server console in `chrome://inspect/#devices`. 

Please open an issue if there is something you want me to know. 

## TODO

1. WebSocket and WebRTC
2. Server Name Indication fallback and HTTP/2 support in CONNECT mode
