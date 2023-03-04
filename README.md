
# TeaVPN2
TeaVPN2 is an open source VPN Software. Current supported platform is
only Linux. We plan to expand to other platforms (contributors are
welcomed).


# Build Requirements
- GNU Make 4.3
- gcc 9.3+ or clang 11+


# Build
```
sudo apt-get install gcc clang make build-essential -y;
git clone https://github.com/TeaInside/teavpn2;
cd teavpn2;
make -j$(nproc);
```

For build with GUI support:
```
./configure --gui;
make -j$(nproc);
```

# Issues
We welcome bug reports, feature requests and questions through GitHub
repository https://github.com/TeaInside/teavpn2 (kindly to open an issue).


# Project Maintainer
- Ammar Faizi ([@ammarfaizi2](https://github.com/ammarfaizi2))


# Community
We are online on Telegram, see https://t.me/TeaInside


# Contributing
We accept pull request on the GitHub repository.


# License
This software is licensed under the GNU GPL-v2 license.
