# Contributing

Thank you for helping. Bug reports, questions and pull requests are all welcome. A verifier
is only worth something if other people can check it, so a report that it accepts something
it should refuse is the most useful contribution of all.

## Sign your commits

Every commit in a pull request must carry a sign-off. A required check refuses a pull request
with an unsigned commit.

```bash
git commit -s -m "Describe the change"
```

`-s` adds this line to the commit message, with the name and email from your git configuration:

```
Signed-off-by: Your Name <you@example.com>
```

By adding it, you certify the [Developer Certificate of Origin 1.1](DCO) for that commit. In
short, you wrote the change or have the right to submit it, you submit it under this
repository's license (see [LICENSE](LICENSE)), and you understand that the contribution and its
sign-off are public and kept permanently. Read the [full text](DCO) before your first sign-off.

If you forgot to sign off, fix the commits and force-push the branch:

```bash
git commit --amend -s --no-edit           # the last commit
git rebase --signoff origin/main          # every commit on the branch
```

## Before you open a pull request

- Run the tests of the package you changed: `npm test` in `packages/<name>`.
- Add a test that fails without your change. For a verifier, that usually means one tampered
  input it must reject.
- Keep each source file's two license header lines as they are.

## How a change lands

Each release of this repository is a snapshot published from the maintainer's development
repository. A pull request is reviewed and discussed here. Once it is accepted, it is applied at
the source and reaches this repository with the next release, instead of being merged as-is.

## Security issues

Do not open a public issue for a vulnerability. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository instead.
