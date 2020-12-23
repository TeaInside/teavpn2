

# TeaVPN2
TeaVPN2 is an open source VPN software written in C/C++.


# Installation
```
git clone https://github.com/TeaInside/teavpn2;
cd teavpn2;
make -j$(nproc) RELEASE_MODE=1;
```

# Directory Structure
1. `src/include/teavpn2/server` is a directory for teavpn2 server **header files**.
2. `src/include/teavpn2/client` is a directory for teavpn2 client **header files**.
3. `src/include/teavpn2/global` is a directory for teavpn2 **header files** (used by client and server).
4. `src/include/third_party` is a directory for third party **header files** libraries.
5. `src/teavpn2/server` is a directory for client binary **source code**.
6. `src/teavpn2/client` is a directory for server binary **source code**.
7. `src/teavpn2/global` is a directory for **source code** that are used by server and client binaries.

Third party **source code** should be in either `src/teavpn2/server`, `src/teavpn2/client` or `src/teavpn2/global` directory. Depending on which module will use such third party source code.

It is acceptable to put **header files** in source directory.


# Pull Requests
We welcome [pull requests](https://github.com/TeaInside/teavpn2/pulls) through GitHub repository. Please read the [CONTRIBUTING.md](https://github.com/TeaInside/teavpn2/blob/master/CONTRIBUTING.md) file for detailed information.


# Issues (bugs, features, questions)
We welcome bug reports, feature requests and questions through GitHub repository [issues](https://github.com/TeaInside/teavpn2/issues).


# Contact Support
Telegram group [@TeaInside](https://t.me/TeaInside)


# License
This software is licensed under the MIT License.
