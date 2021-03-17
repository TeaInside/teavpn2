# Contributing
Please note we have a code of conduct, please follow it in all your
interactions with the project.

## Pull Request

- We follow Linux Kernel Coding Style, see here:
https://www.kernel.org/doc/html/v5.10/process/coding-style.html

- Commits in pull request MUST contain real person with a real email
address.

- Commits in pull request MUST be signed with GPG.
See https://docs.gitlab.com/ee/user/project/repository/gpg_signed_commits/
for details.

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

- Commit messages SHOULD be word-wrapped 80 chars per line and has a
newline between paragraphs. Except for message that has its own format
like compiler error messages, valgrind output, long URL, etc.

- Pull request SHOULD contain explanation about the changes.

- Pull request SHOULD be reviewed by at least one person before it be
merged.

- Pull request that fixes a bug SHOULD be reviewed and be acked by
at least one internal maintainer.

- Pull request that fixes a bug SHOULD contain extra sign-off rule
"Reported-by" and "Acked-by" to give credit to people who have been
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
