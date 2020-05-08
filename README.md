# TeaVPN
Virutal Private Network for Linux. Not documented yet.

### Project Directory Structure
#### Source Code Directory
1. Server source code directory: `src/server` (source code for server app).
2. Client source code directory: `src/client` (source code for client app).
3. Global source code directory: `src/global` (source code for server and client app).

#### Include Directory
1. `include/teavpn/server` (headers for server app).
2. `include/teavpn/client` (headers for client app).
3. `include/teavpn/global` (headers for server and client app).

### Build
1. `make` to build server and client.
2. `make client` to build client app.
3. `make server` to build server app.

### Clean Up Build
1. `make clean` to clean built server and client.
2. `make clean_server` to clean built server.
3. `make clean_client` to clean built client.

## License
[MIT](https://github.com/TeaInside/teavpn2/blob/master/LICENSE)
