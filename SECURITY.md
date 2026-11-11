# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report them privately through GitHub instead: open the repository's **Security** tab and choose
**Report a vulnerability**. (Maintainers: turn this on under *Settings → Code security → Private
vulnerability reporting*.)

Please include:

- the Caltrop version and .NET version,
- what an attacker could do, and what they would need (for example a key, or the ability to change stored data),
- the smallest code that shows the problem, if you have it.

We aim to acknowledge reports within 3 working days, and to agree on a fix and disclosure date with you.
We will credit you in the release notes unless you would rather stay anonymous.

## Supported versions

Security fixes go into the latest release. Caltrop keeps reading data from every earlier version, so
upgrading is always safe.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No, please upgrade |

## Scope

In scope: anything that lets someone read, forge or change data protected by Caltrop without the key or
password, recover keys, or bypass a check such as token expiry, signature or code verification.

Out of scope: attacks that need the secret key or access to the running process, weak passwords chosen by
users, and the behaviour of the underlying .NET or operating system cryptography (please report those to
Microsoft or the OS vendor). See [docs/security-model.md](docs/security-model.md) for what Caltrop does and
does not protect against.
