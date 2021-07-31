


# TeaVPN2
TeaVPN2 is a fast and free VPN Software. Current supported platform is only
Linux. We plan to expand to other platforms too, but that's not our priority.


# Build Requirements
- GNU Make 4.3
- libgnutls30
- gcc 9.3.0 or gcc 10.2.1 (other versions are not tested yet).


# Build
```
git clone https://github.com/TeaInside/teavpn2
cd teavpn2
make RELEASE_MODE=1 -j$(nproc)
```

# Issues
We welcome bug reports, feature requests and questions through GitHub
repository https://github.com/TeaInside/teavpn2.


# Project Maintainers
- Ammar Faizi ([@ammarfaizi2](https://github.com/ammarfaizi2))


# Community
We are usually online on Telegram, see: https://t.me/TeaInside


# Third Party Libraries

| No.   | Link                                    | Name                  | License                   |
|:-----:|:----------------------------------------|:----------------------|:--------------------------|
| 1.    | https://github.com/benhoyt/inih         | inih 53               | New BSD license           |
| 2.    | https://github.com/axboe/liburing       | liburing-2.0          | LGPL + MIT                |
| 3.    | https://www.gnutls.org/download.html    | libgnutls30           | LGPLv2.1+)                |



# Contributing
We welcome contributors through GitHub pull request. Please read the
`CONTRIBUTING.md` file for detailed information.


# License
This software is licensed under the GNU GPL-v2 license.
