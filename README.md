
# TeaVPN2
TeaVPN2 is an open source VPN Software. Current supported platform is
only Linux. We plan to expand to other platforms (contributors are
welcomed).


# Build Requirements
- GNU Make 4.3
- libgnutls30
- gcc 9.3+ or clang 11+


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
We are online on Telegram, see: https://t.me/TeaInside


# Third Party Libraries
| No.   | Link                                    | Name                  | License                   |
|:-----:|:----------------------------------------|:----------------------|:--------------------------|
| 1.    | https://github.com/benhoyt/inih         | inih 53               | New BSD license           |
| 2.    | https://github.com/axboe/liburing       | liburing-2.0          | LGPL + MIT                |
| 3.    | https://www.gnutls.org/download.html    | libgnutls30           | LGPLv2.1+                 |



# Contributing
Please note we have a code of conduct, please follow it in all your
interactions with the project.


## Pull Request
- We follow the Linux Kernel Coding Style, read here:
https://www.kernel.org/doc/html/v5.10/process/coding-style.html

- Commits in pull request MUST contain a real email address.

- Commits in pull request MUST contain "Signed-Off-By" sign with
corresponding email address. This can be done with `git commit -s` or
manually write it at the end of commit message. Example of the sign:
```
commit b0979d16ec3357d03a3396b8c0658f7bcaceb943
Author: Ammar Faizi <ammarfaizi2@gmail.com>
Date:   Thu Dec 17 09:06:44 2020 +0700

    [server] Fix wrong size of memset
    
    Signed-off-by: Ammar Faizi <ammarfaizi2@gmail.com>

```

- Commit message SHOULD be word-wrapped 72 chars per line and has a
newline between paragraphs. Except for message that has its own format
like compiler error messages, valgrind output, long URL, etc.

- Pull request SHOULD contain explanation about the changes.

- Pull request that fixes a bug may contain extra sign-off rule
"Reported-by", "Acked-by" to give credit to people who have been
involved in other ways than just moving the patch around.


## Our Responsibility
Project maintainers are responsible for clarifying the standards of
acceptable behavior and are expected to take appropriate and fair
corrective action in response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit,
or reject comments, commits, code, wiki edits, issues, and other
contributions that are not aligned to this Code of Conduct, or to ban
temporarily or permanently any contributor for other behaviors that they
deem inappropriate, threatening, offensive, or harmful.


## Scope
This Code of Conduct applies both within project spaces and in public
spaces when an individual is representing the project or its community.
Examples of representing a project or community include using an
official project e-mail address, posting via an official social media
account, or acting as an appointed representative at an online or
offline event. Representation of a project may be further defined and
clarified by project maintainers.


# License
This software is licensed under the GNU GPL-v2 license.
