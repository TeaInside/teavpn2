
# TeaVPN2
TeaVPN2 is a free VPN software written in C. Currently supported platform is
only Linux x86-64. We plan to expand to other plaforms and architectures too.


## Requirements
- GNU Make 4.3
- gcc 9.3.0 or gcc 10.2.1 (other versions are not tested yet).

#### Tested on Ubuntu 20.04
```
sudo apt-get install gcc make -y;
```

## Build
```
git clone https://github.com/TeaInside/teavpn2
cd teavpn2
make RELEASE_MODE=1 -j$(nproc)
```

## Issues
We welcome bug reports, feature requests and questions through GitHub
repository https://github.com/TeaInside/teavpn2.


## Project Maintainers
- Ammar Faizi ([@ammarfaizi2](https://github.com/ammarfaizi2))
- Louvian Lyndal ([@louvian](https://github.com/louvian))


## Community
We are usually online on Telegram, see: https://t.me/TeaInside


## Third Party Libraries
- inih (under New BSD license) (https://github.com/benhoyt/inih)


## Contributing
We welcome contributors through GitHub pull request. Please read the
`CONTRIBUTING.md` file for detailed information.


## License
This software is licensed under the GNU GPL-v3 license.

Tea Inside (2021)
