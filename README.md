
# TeaVPN2
TeaVPN2 is an open source VPN Software. Current supported platform is
only Linux. We plan to expand to other platforms (contributors are
welcomed).


# Build Requirements
- GNU Make 4.3
- gcc 9.3+ or clang 11+


# Build
```
git clone https://github.com/TeaInside/teavpn2;
cd teavpn2;
make -j$(nproc) RELEASE_MODE=1;
```

# Issues
We welcome bug reports, feature requests and questions through GitHub
repository https://github.com/TeaInside/teavpn2 (kindly to open an issue).


# Project Maintainer
- Ammar Faizi ([@ammarfaizi2](https://github.com/ammarfaizi2))


# Community
We are online on Telegram, see https://t.me/TeaInside


# Third Party Libraries
| No.   | Link                                    | Name                  | License                   |
|:-----:|:----------------------------------------|:----------------------|:--------------------------|
| 1.    | https://github.com/benhoyt/inih         | inih 53               | New BSD license           |
| 2.    | https://github.com/axboe/liburing       | liburing-2.0          | LGPL + MIT                |
| 3.    | https://www.gnutls.org/download.html    | libgnutls30           | LGPLv2.1+                 |


# Contributing
We accept pull request on the GitHub repository. Please note we have a
code of conduct, please follow it in all your interactions with the
project.


# Code of Conduct
1. We follow the Linux kernel coding style, please read:
https://www.kernel.org/doc/html/v5.10/process/coding-style.html

2. A commit author must be a real email address. We strictly refuse a
GitHub noreply email like `xxxxxxx+username@users.noreply.github.com`.

3. Commit is highly recommended to be signed with GPG. For further information, see:
  - https://docs.github.com/en/github/authenticating-to-github/telling-git-about-your-signing-key
  - https://docs.github.com/en/github/authenticating-to-github/signing-commits

4. Commit message SHOULD contain explanation about the changes.

5. Commit MUST always contain "Signed-off-by" tag with corresponding
name and email address (Except for merge commit. Merge commit may not
have sign-off, but better to have).

6. Expected commit message format is like this:
First line is title, empty line, description, empty line, then a
`Signed-off-by` with your name and email, can add more tags if necessary.

Commit message example:
```
commit 45333fead9c829b7b80b33a1b1b9be8bafa31355
Author: Ammar Faizi <ammarfaizi2@gmail.com>
Date:   Mon Aug 30 21:12:38 2021 +0700

    packet.h: new packet type TSRV_PKT_HANDSHAKE_REJECT

    This commit introduces a new packet type `TSRV_PKT_HANDSHAKE_REJECT`
    for server response. This packet type is supposed to be sent to the
    client when the server detects invalid handshake from the client.

    `TSRV_PKT_HANDSHAKE_REJECT` represents `struct pkt_handshake_reject`
    being sent by the server. The client then can see the reason of
    rejection by reading the `uint8_t reason`. Furthermore, the server
    may give human readable message which contains more information
    about the rejection reason, it is stored in `char msg[255]` (NUL
    terminated C string).

    The packet structure looks like this:
    \```
      #define TSRV_HREJECT_INVALID (1u << 0u)
      #define TSRV_HREJECT_VERSION_NOT_SUPPORTED (1u << 1u)
      struct pkt_handshake_reject {
        uint8_t  reason;
        char     msg[255];
      };
      OFFSET_ASSERT(struct pkt_handshake_reject, reason, 0);
      OFFSET_ASSERT(struct pkt_handshake_reject, msg, 1);
      SIZE_ASSERT(struct pkt_handshake_reject, 256);
    \```

    Currently, we have 2 valid values for the `uint8_t reason`:

     1) `TSRV_HREJECT_INVALID`
        The client sends invalid handshake packet (wrong length or wrong
        type or wrong format).
    
     2) `TSRV_HREJECT_VERSION_NOT_SUPPORTED`
        The client software version is not compatible with the server.

    We may add more types in the future :)

    Signed-off-by: Ammar Faizi <ammarfaizi2@gmail.com>
```


# Frequently Used Tags
- `Signed-off-by:` certifies that you wrote it or otherwise have the
right to pass it on as a open-source patch.

- `Acked-by:` tag indicates if a person was not directly involved in the
preparation or handling of a patch but wishes to signify and record
their approval of it then they can arrange to have an `Acked-by:` line.
`Acked-by:` does not necessarily indicate acknowledgement of the entire
patch.

- `Tested-by:` tag indicates that the commit has been successfully
tested (in some environment) by the person named. This tag informs
maintainers that some testing has been performed, provides a means to
locate testers for future patches, and ensures credit for the testers.

- `Reviewed-by`: tag is a statement of opinion that the commit is an
appropriate modification of the software without any remaining serious
technical issues. Any interested reviewer (who has done the work) can
offer a `Reviewed-by:` tag for a patch.

- `Reported-by:` tag gives credit to people who find bugs and report
them and it hopefully inspires them to help us again in the future.
Please note that if the bug was reported in private, then ask for
permission first before using the `Reported-by:` tag.

- `Co-authored-by:` or `Co-developed-by:` tag states that the commit was
co-created by multiple developers; it is a used to give attribution to
co-authors (in addition to the author attributed by the `From:` tag)
when several people work on a single patch.

- `Suggested-by:` tag indicates that the commit idea is suggested by the
person named and ensures credit to the person for the idea.

- `Fixes:` tag indicates that the commit fixes an issue in a previous
commit, issue, or discussion.

- `Link:` tag indicates relevant reference of the commit.

- `Cc:` indicates that the commit author want to notify the CC'ed party.

Other similar tags may be used as well.

# License
This software is licensed under the GNU GPL-v2 license.
