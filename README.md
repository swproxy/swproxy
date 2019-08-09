# swproxy
Yet another summoners war exporter!

## Download
Binary release: https://github.com/swproxy/swproxy/releases

## Issues
* Install vcredist in zip if you cannot execute swproxy.exe

## Usage

1. Open swproxy.exe
2. Set proxy on your phone
3. Open http://cert/ with default browser(Safari on iOS, haven't test on android)
4. Install certificate(Important!)
5. Restart game
6. A json file will be created in the same directory once proxy got the traffic

## Note
* Step 2 and 3 only needed once.
* Do NOT forget typing in 'http://' in step2 otherwise it won't work

## Changelog
* v0.3 Completely abandon openssl stuff.
* v0.2 Add openssl auto install
 
## Reference
* https://github.com/inaz2/proxy2
