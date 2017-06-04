# Violentproxy

Named after [Violentmonkey](https://github.com/violentmonkey/violentmonkey), 
Violentproxy aims at doing the same monkey things but in a different way, 
it has different restrictions and can possibly work together with Violentmonkey to create a better Userscirpt experience. 

There are quite a few technical difficulties that needs to be resolved before it can handle HTTPS and WebSocket. 
More documentation will be available later when everything is ready. It doesn't handle HTTP properly neither, 
it is far from being ready for even beta test. 

But hey, it does start, try it out: `node demo.js`. 

![screenshot](http://i.imgur.com/itQBQjq.png)

Please open an issue if there is something you want me to know. 

I probably should make this based on mitmproxy, but Python is missing a digit in performance compared to JavaScript. 
