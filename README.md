

# TeaVPN2
TeaVPN2 is an open source VPN software written in C/C++.


# Installation

## Simple

### Clone the repository
```sh
git clone https://github.com/TeaInside/teavpn2;
cd teavpn2;
```

### Build server and client binaries
```sh
make -j$(nproc)
```

## Custom and test

### Build server binary only
```sh
make -j$(nproc) server
```

### Build client binary only
```sh
make -j$(nproc) client
```

### Build global objects only
```sh
make -j$(nproc) global
```

### Build in release mode, add env var RELEASE_MODE=1
```sh
env RELEASE_MODE=1 make -j$(nproc)
```

### Build and run unit tests
```sh
make test
```

### Build and run gcov and run unit tests (must be clean before run this)
```sh
make gcov COVERAGE=1
```


# Directory Structure
1. `src/include/teavpn2/server` is a directory for teavpn2 server **header files**.
2. `src/include/teavpn2/client` is a directory for teavpn2 client **header files**.
3. `src/include/teavpn2/global` is a directory for teavpn2 **header files** (used by client and server).
4. `src/include/third_party` is a directory for third party **header files** libraries.
5. `src/teavpn2/server` is a directory for client binary **source code**.
6. `src/teavpn2/client` is a directory for server binary **source code**.
7. `src/teavpn2/global` is a directory for **source code** that are used by server and client binaries.

Third party **source code** should be in either `src/teavpn2/server`, `src/teavpn2/client` or `src/teavpn2/global` directory. Depending on which binary will use such third party source code.

It is acceptable to put **header files** of third party source code in source directory.


# Pull Requests
We welcome [pull requests](https://github.com/TeaInside/teavpn2/pulls) through GitHub repository. Every outside collaborator's pull request must be reviewed by at least one internal contributor or maintainer before merge.


# Issues (bugs, features, questions)
We welcome bug reports, feature requests and questions through GitHub repository [issues](https://github.com/TeaInside/teavpn2/issues).


# Support
You can ask a question on Telegram group chat too
[https://t.me/TeaInside](https://t.me/TeaInside)


# License
This software is licensed under the MIT License.
