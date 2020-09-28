
# TeaVPN2
TeaVPN2 is an open source VPN software written in C/C++.

# Installation
```sh
# Clone the repository.
git clone https://github.com/TeaInside/teavpn2;
cd teavpn2;

# Build server and client binaries
make -j$(nproc)

# Build server binary only.
make -j$(nproc) server

# Build client binary only.
make -j$(nproc) client

# Build global objects only.
make -j$(nproc) global

# Build in release mode, add env var RELEASE_MODE=1.
env RELEASE_MODE=1 make -j$(nproc)
```

# License
This software is licensed under the MIT License.
