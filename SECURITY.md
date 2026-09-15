# Security policy

## Reporting

Open a [private security advisory](https://github.com/voitta-ai/shmobster/security/advisories/new)
on this repository. If that is not available to you, email the maintainer at
the address on the commits in `git log`. Please do not open a public issue for
a vulnerability.

Expect an acknowledgement within a week. This is a small project with one
maintainer; there is no bounty and no SLA beyond that.

## What is in scope

shmobster runs shell commands on a host, on behalf of whoever can message it in
Slack. The interesting surface is the gate chain, and a report that gets a
command past it is the most useful thing you can send:

- **YOLT verdict** -- a mutating command that classifies as read-only.
- **Egress allow-list** -- a fetch to a host outside the channel's
  `allow_domains` that runs without an approval card.
- **Grant layer** -- a write outside the channel tree that runs uncarded.
- **Sandbox** -- a read or write that escapes the seatbelt profile, including
  through a symlink or a path the shell resolves at runtime.
- **Approvals** -- running a parked command without a trusted user's approval,
  or an id from one boot being accepted after a restart.
- **Redaction** -- a credential this process holds reaching a channel, a log, or
  a vendor.
- **Policy** -- one channel reading another channel's credentials, or widening
  its own envelope without a trusted user.

## What is not

The trust model, stated in the README, assumes **private channels and trusted
invitees**. Reports that reduce to "a person who was invited to the channel can
use the agent" are working as designed. So are:

- `cwd` not being a sandbox by itself (it is not; the seatbelt is).
- `github_repos` and `aws_profile` being best-effort text guards, which the
  README says.
- Anything requiring write access to the host's config or policy file: that is
  the deployment's owner, who already controls the process.

## Dependencies

The exec classifier and the redactor come from
[voitta-yolt](https://github.com/voitta-ai/voitta-yolt); a flaw in either is
best reported there, and it will be picked up here. Vendor SDKs (slack-bolt,
litellm) go to their own projects.
